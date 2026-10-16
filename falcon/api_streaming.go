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
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/event_streams"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/falcon/models/streaming_models"
)

// StreamingHandle is a connection to one stream of the Falcon Streaming API. It
// delivers the events of the stream on Events and its errors on Errors.
type StreamingHandle struct {
	// ctx ends once nothing will read the channels again: on Close, or when
	// the ctx passed to NewStream ends.
	ctx           context.Context
	ctxCancelFunc context.CancelCauseFunc

	// readCtx ends with ctx, and also as soon as the stream itself ends, with
	// the reason as its cause.
	readCtx  context.Context
	stopRead context.CancelCauseFunc

	client *client.CrowdStrikeAPISpecification
	appId  string
	offset uint64
	stream *models.MainAvailableStreamV2

	// Events delivers the events of the stream. It is closed when the stream
	// ends, possibly before the final error has been received from Errors.
	Events chan *streaming_models.EventItem

	// Errors delivers the errors of the stream. The last one has Fatal set and
	// reports the end of the stream. Keep reading it: while an error sits
	// unread, the stream waits at the next error and keeps refreshing its
	// session meanwhile, so a stalled stream holds its session until Close. A
	// stream that has ended waits the same way to hand over its final error,
	// but no longer refreshes.
	Errors chan StreamingError

	// HTTPClient is the client the data feed was opened with. Setting it has
	// no effect.
	HTTPClient *http.Client
}

// ErrStreamClosed reports the end of every stream. The Err of the final
// StreamingError is ErrStreamClosed itself when the stream ended with nothing
// to report: the data feed ended, Close was called, or ctx was cancelled
// without a cause. Otherwise it wraps ErrStreamClosed and the reason: a broken
// data feed, a failed session refresh, a deadline of ctx, or the cause given
// when cancelling it. So errors.Is(err, ErrStreamClosed) holds for the Err of
// every final error, and err == ErrStreamClosed only for one with nothing to
// report.
var ErrStreamClosed = errors.New("streaming connection closed")

// DataFeedError is the error NewStream and NewStreamWithClient return, wrapped,
// when the data feed answers with a non-2xx status. A 401 means the session
// token has expired or has already been used to connect: list the streams
// again to get a new one.
type DataFeedError struct {
	// StatusCode is the HTTP status the data feed answered with.
	StatusCode int
	// Detail is the start of the response body, put on one line. It is empty
	// when the data feed sent no body.
	Detail string
}

// Error returns the status code and Detail.
func (e *DataFeedError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("unexpected status %d", e.StatusCode)
	}
	return fmt.Sprintf("unexpected status %d: %s", e.StatusCode, e.Detail)
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
	if client == nil {
		// The session refresh would otherwise panic minutes later, in a
		// goroutine the caller cannot recover from.
		return nil, errors.New("no API client provided")
	}
	refreshPeriod, err := checkStreamDescriptor(stream)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	streamCtx, cancel := context.WithCancelCause(ctx)
	readCtx, stopRead := context.WithCancelCause(streamCtx)

	// Errors has room for one error, so that after Close the final error can
	// wait there for a consumer that keeps reading, without blocking if none
	// does.
	sh := &StreamingHandle{
		ctx:           streamCtx,
		ctxCancelFunc: cancel,
		readCtx:       readCtx,
		stopRead:      stopRead,
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

	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		sh.maintainSession(refreshPeriod)
	}()
	// The reader is the only sender on Errors, so once it has stopped the final
	// error goes last. The refresh stops with the reader, and waiting for it
	// leaves nothing of the stream running once its channels are closed.
	go func() {
		final := sh.read(body)
		<-refreshDone
		sh.sendFinal(final)
		close(sh.Errors)
		close(sh.Events)
		// Let go of the ctx passed to NewStream.
		cancel(nil)
	}()
	return sh, nil
}

// NewStreamWithClient is NewStream with the http.Client used for the data feed.
// A nil httpClient means a new http.Client. Leave its Timeout unset, since it
// would end the stream once it passes.
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

// NewStream connects to a stream listed by
// event_streams.ListAvailableStreamsOAuth2. The appId must be unique within
// your CrowdStrike account: each running instance of your application must use
// its own. Pass a zero offset at start. Each event carries its offset. A
// session token connects only once, so to resume after the stream ends, list
// the streams again and pass the offset of the last event received plus one.
//
// It returns an error without connecting if client is nil, or if the stream
// lacks dataFeedURL, sessionToken.token or a usable
// refreshActiveSessionInterval. If the data feed answers with a non-2xx
// status, the error it returns wraps a *DataFeedError.
//
// The stream ends when the data feed ends or breaks, when its session cannot
// be refreshed, or when Close is called or ctx ends. A refresh that fails on a
// network error, 429 or 5xx is retried until the session would expire, the
// full refreshActiveSessionInterval after the last refresh.
//
// Read both Events and Errors. The end is reported by the only StreamingError
// with Fatal set. It is queued in Errors and both channels are closed right
// after, possibly before it has been received, so check each receive from
// Events: once Events is closed, the final error is the next one in Errors. Keep reading Errors until Close is called or ctx
// ends, since the stream waits at the next error while one is unread, and at
// its end. Because Errors holds an error until it is received, an error can be
// received after events that came after it.
func NewStream(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	appId string,
	stream *models.MainAvailableStreamV2,
	offset uint64,
) (*StreamingHandle, error) {
	return newStream(ctx, client, appId, stream, offset, nil)
}

// maintainSession refreshes the stream session refreshPeriod after the stream
// started and after each refresh, until the stream ends. The session lasts a
// ninth longer than refreshPeriod, and a refresh that fails is retried within
// that time if it may pass. A failure that cannot be retried, or that persists
// until the session would expire, ends the stream, since the connection cannot
// outlive its session, and becomes the cause the final error wraps.
func (sh *StreamingHandle) maintainSession(refreshPeriod time.Duration) {
	timer := time.NewTimer(refreshPeriod)
	defer timer.Stop()
	for {
		select {
		case <-sh.readCtx.Done():
			return
		case <-timer.C:
		}
		if err := sh.refreshSession(refreshPeriod / 9); err != nil {
			// Only the first cause counts, so a refresh cut short by the
			// end of the stream does not replace why it ended.
			sh.stopRead(fmt.Errorf("refresh active stream session: %w", err))
			return
		}
		timer.Reset(refreshPeriod)
	}
}

// refreshSession refreshes the stream session, retrying a failure that may pass
// within grace, the time left before the session expires. The five retries
// wait a 32nd of grace, then twice as long each time, so the last one starts
// just before the session would expire. It returns the last failure.
func (sh *StreamingHandle) refreshSession(grace time.Duration) error {
	wait := grace / 32
	for retriesLeft := 5; ; retriesLeft-- {
		_, err := sh.client.EventStreams.RefreshActiveStreamSession(
			&event_streams.RefreshActiveStreamSessionParams{
				AppID:      sh.appId,
				ActionName: "refresh_active_stream_session",
				Partition:  0,
				Context:    sh.readCtx,
			},
		)
		if err == nil || retriesLeft == 0 || !retryableRefresh(err) {
			return err
		}
		select {
		case <-sh.readCtx.Done():
			return err
		case <-time.After(wait):
		}
		wait *= 2
	}
}

// retryableRefresh tells whether a failed refresh may pass if tried again: it
// failed on the network, or the API answered 429 or a 5xx, the failures
// RetryConfig retries too. Any other status the API answered with stays.
func retryableRefresh(err error) bool {
	// Both the errors of the generated client and the runtime.APIError it
	// returns for a status it does not know have these methods.
	var status interface {
		IsCode(code int) bool
		IsServerError() bool
	}
	if !errors.As(err, &status) {
		return true
	}
	return status.IsServerError() || status.IsCode(http.StatusTooManyRequests)
}

// open connects to the data feed and returns the body the events are read from.
func (sh *StreamingHandle) open() (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(sh.readCtx, "GET", sh.url(), nil)
	if err != nil {
		return nil, fmt.Errorf("open streaming connection: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Add("Authorization", "Token "+*sh.stream.SessionToken.Token)
	req.Header.Add("Connection", "Keep-Alive")
	req.Header.Add("Date", time.Now().Format(time.RFC1123Z))

	resp, err := sh.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("open streaming connection: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The body usually says why, for example an expired session token. The
		// data feed pretty-prints it, so put it on one line, without the
		// character the limit may have cut in half.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("open streaming connection: %w", &DataFeedError{
			StatusCode: resp.StatusCode,
			Detail:     strings.Join(strings.Fields(strings.ToValidUTF8(string(detail), "")), " "),
		})
	}
	return resp.Body, nil
}

// read decodes events from body until the data feed ends or the stream is
// stopped, then stops the session refresh, closes body and returns the error
// that reports the end of the stream.
func (sh *StreamingHandle) read(body io.ReadCloser) (final StreamingError) {
	// Close body as soon as the stream stops. That ends a pending read even
	// through a transport that does not cancel the body with its request.
	bodyClosed := make(chan error, 1)
	context.AfterFunc(sh.readCtx, func() { bodyClosed <- body.Close() })
	var cause error
	defer func() {
		// Nothing more can arrive on this handle, so stop refreshing its
		// session, which also closes body.
		sh.stopRead(nil)
		if err := <-bodyClosed; err != nil {
			sh.sendError(StreamingError{Fatal: false, Err: err})
		}
		// A failed session refresh, or a deadline or cancel cause of the parent
		// ctx, stopped the stream before the read could fail on its own. A
		// plain cancel, by Close or the parent, leaves just context.Canceled,
		// which says nothing, so only that exact error is left out.
		if c := context.Cause(sh.readCtx); cause == nil && c != context.Canceled {
			cause = c
		}
		closed := ErrStreamClosed
		if cause != nil {
			closed = fmt.Errorf("%w: %w", ErrStreamClosed, cause)
		}
		final = StreamingError{Fatal: true, Err: closed}
	}()

	dec := json.NewDecoder(body)
	for sh.readCtx.Err() == nil {
		var rawMessage json.RawMessage
		if err := dec.Decode(&rawMessage); err != nil {
			// The decoder returns the same error on every later call, so any
			// failure ends the stream. EOF and a stopped stream are its normal
			// ends.
			if !errors.Is(err, io.EOF) && sh.readCtx.Err() == nil {
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
		case <-sh.readCtx.Done():
			return
		}
	}
	return
}

// sendError delivers err unless the stream is stopped first, by Close or by the
// end of the ctx passed to NewStream, so that no goroutine is left blocked on a
// consumer that has stopped reading. The end of the stream alone does not drop
// err, because the consumer may still be reading.
func (sh *StreamingHandle) sendError(err StreamingError) {
	select {
	case sh.Errors <- err:
	case <-sh.ctx.Done():
	}
}

// sendFinal sends err, the error that ends the stream, once nothing else can
// send. After Close or the end of ctx the consumer may have stopped reading, so
// rather than wait it replaces any unread error, leaving err in Errors for a
// consumer that is still reading.
func (sh *StreamingHandle) sendFinal(err StreamingError) {
	select {
	case sh.Errors <- err:
		return
	case <-sh.ctx.Done():
	}
	select {
	case <-sh.Errors:
	default:
	}
	// No other sender is left and Errors now has room, so this cannot block.
	sh.Errors <- err
}

// Close ends the stream. It does not wait: Events and Errors are closed once
// the read and any session refresh in progress have returned. Errors not yet
// received may be dropped, but the final error is still left in Errors before
// it is closed, so a consumer that keeps reading receives it. Cancelling the
// ctx passed to NewStream has the same effect, except that a cause given to
// the cancel, or a deadline, is wrapped in the final error. Close is not needed
// once the final error has been received or Events is closed, but calling it
// then is harmless, as is calling it more than once or from any goroutine.
func (sh *StreamingHandle) Close() {
	sh.ctxCancelFunc(nil)
}

func (sh *StreamingHandle) url() string {
	if sh.offset != 0 {
		return fmt.Sprintf("%s&offset=%d", *sh.stream.DataFeedURL, sh.offset)
	}
	return *sh.stream.DataFeedURL
}

// StreamingError is an error sent on Errors. Only the last one of a stream is
// fatal.
type StreamingError struct {
	// Fatal is set only on the last error of a stream, the one that reports
	// its end. Its Err is or wraps ErrStreamClosed.
	Fatal bool
	// Err is what went wrong.
	Err error
}

// Error returns the text of Err, or "<nil>" for a StreamingError without one,
// such as the zero value received once Errors is closed.
func (e StreamingError) Error() string {
	if e.Err == nil {
		return "<nil>"
	}
	return e.Err.Error()
}

// Unwrap returns Err, so that errors.Is and errors.As see through a
// StreamingError.
func (e StreamingError) Unwrap() error {
	return e.Err
}
