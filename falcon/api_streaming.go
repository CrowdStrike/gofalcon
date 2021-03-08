package falcon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/event_streams"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/falcon/models/streaming_models"
)

// StreamingHandle is higher order type that allows for easy use of CrowdStrike Falcon Streaming API
type StreamingHandle struct {
	ctx    context.Context
	client *client.CrowdStrikeAPISpecification
	appId  string
	stream *models.MainAvailableStreamV2
	Events chan *streaming_models.EventItem
	Errors chan StreamingError
}

// NewStream initializes new StreamingHandle. Users are advised to read from the StreamingHandle channels
func NewStream(ctx context.Context, client *client.CrowdStrikeAPISpecification, appId string, stream *models.MainAvailableStreamV2) (*StreamingHandle, error) {
	sh := &StreamingHandle{
		ctx:    ctx,
		client: client,
		appId:  appId,
		stream: stream,
		Events: make(chan *streaming_models.EventItem),
		Errors: make(chan StreamingError),
	}
	sh.maintainSession()
	err := sh.open()
	if err != nil {
		sh.Close()
		return nil, err
	}
	return sh, nil
}

func (sh *StreamingHandle) maintainSession() {
	ticker := time.NewTicker(time.Duration(*sh.stream.RefreshActiveSessionInterval*9/10) * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-sh.ctx.Done():
				return
			case <-ticker.C:
				_, err := sh.client.EventStreams.RefreshActiveStreamSession(&event_streams.RefreshActiveStreamSessionParams{
					AppID:      sh.appId,
					ActionName: "refresh_active_stream_session",
					Partition:  0,
					Context:    sh.ctx,
				})

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
	req, err := http.NewRequestWithContext(sh.ctx, "GET", *sh.stream.DataFeedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Add("Authorization", "Token "+*sh.stream.SessionToken.Token)
	req.Header.Add("Connection", "Keep-Alive")
	req.Header.Add("Date", time.Now().Format(time.RFC1123Z))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	sh.Events = make(chan *streaming_models.EventItem)
	go func() {
		defer resp.Body.Close()

		dec := json.NewDecoder(resp.Body)
		for dec.More() {
			var detection streaming_models.EventItem
			//dec.DisallowUnknownFields()
			err := dec.Decode(&detection)
			if err != nil {
				sh.Errors <- StreamingError{Fatal: false, Err: err}
			}
			sh.Events <- &detection
		}
		sh.Errors <- StreamingError{
			Fatal: true,
			Err:   errors.New("Streaming connection closed"),
		}
		close(sh.Events)
	}()

	return nil
}

// Close the StreamingHandle after use
func (sh *StreamingHandle) Close() {
	close(sh.Errors)
	sh.Errors = nil
}

// StreamingError structure that holds original error and indicates whether the Error is likely fatal or not
type StreamingError struct {
	Fatal bool
	Err   error
}

func (e StreamingError) Error() string {
	return e.Err.Error()
}
