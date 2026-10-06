package falcon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
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

	// stopped is closed by Close to tell senders that nothing will read again.
	stopped  chan struct{}
	stopOnce sync.Once
}

// ErrStreamClosed is the error of the fatal StreamingError sent when the
// streaming connection ends. If a read or decode failure ended it, the error
// sent wraps both ErrStreamClosed and that failure.
var ErrStreamClosed = errors.New("streaming connection closed")

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

	// Errors has room for one error, so that the final one can wait for a
	// consumer still reading after Close without blocking on one that is not.
	sh := &StreamingHandle{
		ctx:           ctx,
		ctxCancelFunc: cancel,
		stopped:       make(chan struct{}),
		client:        client,
		appId:         appId,
		stream:        stream,
		offset:        offset,
		Events:        make(chan *streaming_models.EventItem),
		Errors:        make(chan StreamingError, 1),
		HTTPClient:    httpClient,
	}
	body, err := sh.open()
	if err != nil {
		sh.Close()
		return nil, err
	}

	var senders sync.WaitGroup
	var final StreamingError
	senders.Add(2)
	go func() {
		defer senders.Done()
		sh.maintainSession(refreshPeriod)
	}()
	go func() {
		defer senders.Done()
		final = sh.read(body)
	}()
	// Both goroutines send on Errors, so neither may close it. Once both have
	// stopped nothing else can send, so the final error goes last.
	go func() {
		senders.Wait()
		sh.sendFinal(final)
		close(sh.Errors)
		close(sh.Events)
	}()
	return sh, nil
}

// NewStreamWithClient initializes new StreamingHandle and connects to the Streaming API using the provided http.Client.
// It rejects the same unusable stream descriptors as NewStream.
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
// It returns an error without connecting if the stream lacks dataFeedURL, sessionToken.token or refreshActiveSessionInterval, or if refreshActiveSessionInterval is not a usable positive number of seconds.
// It also returns an error if the data feed answers with a non-2xx status.
// When the connection ends, including when ctx is cancelled or Close is called, a fatal StreamingError whose error is or wraps ErrStreamClosed is sent on Errors and then both channels are closed.
// A failed session refresh is also sent as a fatal StreamingError, but the connection keeps running until it ends; use errors.Is(err, ErrStreamClosed) to tell the end of the stream apart.
// Read Errors as well as Events: until Close is called, an error left unread holds the stream up, and neither channel is closed before the final error has been sent.
// Errors holds one error until it is received, so an error may be received after events that were sent after it.
func NewStream(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	appId string,
	stream *models.MainAvailableStreamV2,
	offset uint64,
) (*StreamingHandle, error) {
	return newStream(ctx, client, appId, stream, offset, &http.Client{})
}

// maintainSession refreshes the stream session every refreshPeriod until the
// handle is closed or a refresh fails.
func (sh *StreamingHandle) maintainSession(refreshPeriod time.Duration) {
	ticker := time.NewTicker(refreshPeriod)
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
				// A refresh cut short by Close is not a failure worth reporting.
				if sh.ctx.Err() == nil {
					sh.sendError(StreamingError{Fatal: true, Err: err})
				}
				return
			}
		}
	}
}

// open connects to the data feed and returns the body the events are read from.
func (sh *StreamingHandle) open() (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(sh.ctx, "GET", sh.url(), nil)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The body usually says why, for example an expired session token. The
		// data feed pretty-prints it, so put it on one line.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		if reason := strings.Join(strings.Fields(string(detail)), " "); reason != "" {
			return nil, fmt.Errorf("open streaming connection: unexpected status %d: %s", resp.StatusCode, reason)
		}
		return nil, fmt.Errorf("open streaming connection: unexpected status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// read decodes events from body until the data feed ends or the handle is
// closed, then stops the session refresh and returns the error that reports
// the end of the stream.
func (sh *StreamingHandle) read(body io.ReadCloser) (final StreamingError) {
	var cause error
	defer func() {
		// Nothing more can arrive on this handle, so stop refreshing its session.
		sh.ctxCancelFunc()
		if err := body.Close(); err != nil {
			sh.sendError(StreamingError{Fatal: false, Err: err})
		}
		closed := ErrStreamClosed
		if cause != nil {
			closed = fmt.Errorf("%w: %w", ErrStreamClosed, cause)
		}
		final = StreamingError{Fatal: true, Err: closed}
	}()

	dec := json.NewDecoder(body)
	for sh.ctx.Err() == nil {
		var rawMessage json.RawMessage
		if err := dec.Decode(&rawMessage); err != nil {
			// The decoder returns the same error on every later call, so any
			// failure ends the stream. EOF and Close are its normal ends.
			if !errors.Is(err, io.EOF) && sh.ctx.Err() == nil {
				cause = err
			}
			return
		}

		var detection streaming_models.EventItem
		if err := json.Unmarshal(rawMessage, &detection); err != nil {
			sh.sendError(StreamingError{Fatal: false, Err: err})
			continue
		}
		detection.RawMessage = rawMessage
		select {
		case sh.Events <- &detection:
		case <-sh.ctx.Done():
			return
		}
	}
	return
}

// sendError delivers err unless Close is called first, so that no goroutine is
// left blocked on a consumer that has stopped reading. A cancelled ctx alone
// does not drop err, because the consumer may still be reading.
func (sh *StreamingHandle) sendError(err StreamingError) {
	select {
	case sh.Errors <- err:
	case <-sh.stopped:
	}
}

// sendFinal sends err, the error that ends the stream, once no other sender is
// left. After Close the consumer may have stopped reading, so instead of
// waiting it drops an older error still unread to make room and leaves err in
// Errors: a consumer still reading receives it before Errors is closed, and one
// that has stopped reading leaves nothing blocked.
func (sh *StreamingHandle) sendFinal(err StreamingError) {
	select {
	case sh.Errors <- err:
		return
	case <-sh.stopped:
	}
	select {
	case <-sh.Errors:
	default:
	}
	// No other sender is left and Errors now has room, so this cannot block.
	sh.Errors <- err
}

// Close the StreamingHandle after use. Events and Errors are closed once the
// connection and the session refresh have stopped. Errors not yet received
// when Close is called may be dropped, but the final ErrStreamClosed is always
// sent before Errors is closed, so a consumer that keeps reading receives it.
func (sh *StreamingHandle) Close() {
	sh.ctxCancelFunc()
	sh.stopOnce.Do(func() { close(sh.stopped) })
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

// Error returns the text of Err, or "<nil>" for a StreamingError without one,
// such as the zero value received once Errors is closed.
func (e StreamingError) Error() string {
	if e.Err == nil {
		return "<nil>"
	}
	return e.Err.Error()
}
