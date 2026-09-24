package falcon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/event_streams"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/falcon/models/streaming_models"
)

// StreamingHandle is higher order type that allows for easy use of CrowdStrike Falcon Streaming API.
type StreamingHandle struct {
	ctx           context.Context
	ctxCancelFunc context.CancelFunc
	client        *client.CrowdStrikeAPISpecification
	appId         string
	offset        uint64
	stream        *models.MainAvailableStreamV2
	Events        chan *streaming_models.EventItem
	Errors        chan StreamingError
	HTTPClient    *http.Client
}

// refreshPeriodPerSecond is how much of the session lifetime the stream is
// allowed to burn before refreshing: nine tenths of it, kept in time.Duration
// so that short lifetimes do not truncate to zero.
const refreshPeriodPerSecond = 9 * time.Second / 10

// maxRefreshActiveSessionInterval is the largest interval, in seconds, that can
// still be turned into a refresh period without overflowing a time.Duration.
const maxRefreshActiveSessionInterval = int64(math.MaxInt64 / refreshPeriodPerSecond)

// checkStreamDescriptor makes sure the descriptor carries the fields the stream
// actually dereferences, and works out the session refresh period from it. The
// descriptor comes back from ListAvailableStreamsOAuth2 with every field a
// pointer, so a sparse response would otherwise panic on first use.
func checkStreamDescriptor(stream *models.MainAvailableStreamV2) (time.Duration, error) {
	if stream == nil {
		return 0, errors.New("no stream descriptor provided")
	}
	if stream.DataFeedURL == nil {
		return 0, errors.New("stream descriptor has no dataFeedURL")
	}
	if stream.SessionToken == nil {
		return 0, errors.New("stream descriptor has no sessionToken")
	}
	if stream.SessionToken.Token == nil {
		return 0, errors.New("stream descriptor has no sessionToken.token")
	}
	if stream.RefreshActiveSessionInterval == nil {
		return 0, errors.New("stream descriptor has no refreshActiveSessionInterval")
	}

	interval := *stream.RefreshActiveSessionInterval
	if interval <= 0 || interval > maxRefreshActiveSessionInterval {
		return 0, fmt.Errorf("stream descriptor carries an unusable refreshActiveSessionInterval: %d", interval)
	}
	return time.Duration(interval) * refreshPeriodPerSecond, nil
}

// newStream initializes new StreamingHandle and connects to the Streaming API using the provided http.Client.
func newStream(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	appId string,
	stream *models.MainAvailableStreamV2,
	offset uint64,
	httpClient *http.Client,
) (*StreamingHandle, error) {
	refreshPeriod, err := checkStreamDescriptor(stream)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)

	sh := &StreamingHandle{
		ctx:           ctx,
		ctxCancelFunc: cancel,
		client:        client,
		appId:         appId,
		stream:        stream,
		offset:        offset,
		Events:        make(chan *streaming_models.EventItem),
		Errors:        make(chan StreamingError),
		HTTPClient:    httpClient,
	}
	sh.maintainSession(refreshPeriod)
	if err := sh.open(); err != nil {
		sh.Close()
		return nil, err
	}
	return sh, nil
}

// NewStreamWithClient initializes new StreamingHandle and connects to the Streaming API using the provided http.Client.
func NewStreamWithClient(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	appId string,
	stream *models.MainAvailableStreamV2,
	offset uint64,
	httpClient *http.Client,
) (*StreamingHandle, error) {
	return newStream(ctx, client, appId, stream, offset, httpClient)
}

// NewStream initializes new StreamingHandle and connects to the Streaming API.
// The streams need to be discovered first by event_streams.ListAvailableStreamsOAuth2() method.
// The appId must be an ID that is unique within your CrowdStrike account. Each running instance of your application must provide unique ID.
// The offset value can then be used to skip seen events, should the stream disconnect. Users are advised to use zero (0) value at start. Each event then contains its own offset.
func NewStream(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	appId string,
	stream *models.MainAvailableStreamV2,
	offset uint64,
) (*StreamingHandle, error) {
	return newStream(ctx, client, appId, stream, offset, &http.Client{})
}

func (sh *StreamingHandle) maintainSession(refreshPeriod time.Duration) {
	ticker := time.NewTicker(refreshPeriod)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-sh.ctx.Done():
				return
			case <-ticker.C:
				_, err := sh.client.EventStreams.RefreshActiveStreamSession(
					&event_streams.RefreshActiveStreamSessionParams{
						AppID:      sh.appId,
						ActionName: "refresh_active_stream_session",
						Partition:  0,
						Context:    sh.ctx,
					},
				)

				if err != nil {
					sh.Errors <- StreamingError{
						Fatal: true,
						Err:   err,
					}
					return
				}
			}
		}
	}()
}

func (sh *StreamingHandle) open() error {
	req, err := http.NewRequestWithContext(sh.ctx, "GET", sh.url(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Add("Authorization", "Token "+*sh.stream.SessionToken.Token)
	req.Header.Add("Connection", "Keep-Alive")
	req.Header.Add("Date", time.Now().Format(time.RFC1123Z))

	if sh.HTTPClient == nil {
		sh.HTTPClient = &http.Client{}
	}
	resp, err := sh.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	sh.Events = make(chan *streaming_models.EventItem)
	go func() {
		defer func() {
			err := resp.Body.Close()

			if err != nil {
				sh.Errors <- StreamingError{
					Fatal: false,
					Err:   err,
				}
			}

			sh.Errors <- StreamingError{
				Fatal: true,
				Err:   errors.New("streaming connection closed"),
			}

			close(sh.Errors)
			close(sh.Events)
		}()

		dec := json.NewDecoder(resp.Body)
		for {
			select {
			case <-sh.ctx.Done():
				return
			default:
				if dec.More() {
					var detection streaming_models.EventItem
					var rawMessage json.RawMessage
					err := dec.Decode(&rawMessage)
					if err != nil {
						sh.Errors <- StreamingError{Fatal: false, Err: err}
						continue
					}

					err = json.Unmarshal(rawMessage, &detection)
					if err != nil {
						sh.Errors <- StreamingError{Fatal: false, Err: err}
						continue
					}

					detection.RawMessage = rawMessage
					sh.Events <- &detection
				}
			}
		}
	}()

	return nil
}

// Close the StreamingHandle after use.
func (sh *StreamingHandle) Close() {
	sh.ctxCancelFunc()
	if sh.HTTPClient != nil {
		sh.HTTPClient.CloseIdleConnections()
	}
}

func (sh *StreamingHandle) url() string {
	if sh.offset != 0 {
		return fmt.Sprintf("%s&offset=%d", *sh.stream.DataFeedURL, sh.offset)
	}
	return *sh.stream.DataFeedURL
}

// StreamingError structure that holds original error and indicates whether the Error is likely fatal or not.
type StreamingError struct {
	Fatal bool
	Err   error
}

func (e StreamingError) Error() string {
	return e.Err.Error()
}
