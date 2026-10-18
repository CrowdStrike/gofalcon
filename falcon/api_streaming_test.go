package falcon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/event_streams"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/falcon/models/streaming_models"
)

// completeStream is the shape ListAvailableStreamsOAuth2 returns for a usable
// stream, limited to the fields the streaming handle actually reads.
func completeStream() *models.MainAvailableStreamV2 {
	return &models.MainAvailableStreamV2{
		DataFeedURL:                  swag.String("https://data.example.com/datafeed/v2"),
		RefreshActiveSessionInterval: swag.Int64(1800),
		SessionToken: &models.MainSessionToken{
			Token: swag.String("token"),
		},
	}
}

func withStream(mutate func(*models.MainAvailableStreamV2)) *models.MainAvailableStreamV2 {
	s := completeStream()
	mutate(s)
	return s
}

// withInterval is completeStream with a session lifetime of seconds.
func withInterval(seconds int64) *models.MainAvailableStreamV2 {
	return withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(seconds) })
}

// eventMessage is one event as the data feed sends it.
const eventMessage = `{"metadata":{"eventType":"UserActivityAuditEvent"},"event":{}}` + "\n"

func TestCheckStreamDescriptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		stream     *models.MainAvailableStreamV2
		wantErr    string
		wantPeriod time.Duration
	}{
		{
			name:    "nil descriptor",
			stream:  nil,
			wantErr: "no stream descriptor provided",
		},
		{
			name:    "no data feed url",
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.DataFeedURL = nil }),
			wantErr: "no dataFeedURL",
		},
		{
			name:    "no session token",
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.SessionToken = nil }),
			wantErr: "no sessionToken",
		},
		{
			name:    "no token inside the session token",
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.SessionToken.Token = nil }),
			wantErr: "no sessionToken.token",
		},
		{
			name:    "no refresh interval",
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = nil }),
			wantErr: "no refreshActiveSessionInterval",
		},
		{
			name:    "zero refresh interval",
			stream:  withInterval(0),
			wantErr: "unusable refreshActiveSessionInterval: 0",
		},
		{
			name:    "negative refresh interval",
			stream:  withInterval(-5),
			wantErr: "unusable refreshActiveSessionInterval: -5",
		},
		{
			name:    "refresh interval that would overflow the period",
			stream:  withInterval(math.MaxInt64),
			wantErr: "unusable refreshActiveSessionInterval",
		},
		{
			name:       "one second still yields a usable period",
			stream:     withInterval(1),
			wantPeriod: 900 * time.Millisecond,
		},
		{
			name:       "typical interval is unchanged",
			stream:     completeStream(),
			wantPeriod: 27 * time.Minute,
		},
		// 10248191152s is the largest interval whose nine-tenths period, in
		// nanoseconds, still fits in an int64.
		{
			name:       "largest interval that still fits",
			stream:     withInterval(10248191152),
			wantPeriod: 9223372036800000000,
		},
		{
			name:    "one second past the largest interval",
			stream:  withInterval(10248191153),
			wantErr: "unusable refreshActiveSessionInterval: 10248191153",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			period, err := checkStreamDescriptor(tc.stream)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected an error containing %q, got %q", tc.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if period != tc.wantPeriod {
				t.Fatalf("expected a refresh period of %v, got %v", tc.wantPeriod, period)
			}
		})
	}
}

// roundTripFunc answers HTTP requests with a plain function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// closeAndDrain closes the handle and reads both channels until the reader
// goroutine closes them, so it can finish before the test returns.
func closeAndDrain(t *testing.T, sh *StreamingHandle) {
	t.Helper()

	sh.Close()
	drain(t, sh)
}

// drain reads both channels until the handle closes them, failing the test if
// that takes more than 5s, and returns what arrived.
func drain(t *testing.T, sh *StreamingHandle) (events int, errs []StreamingError) {
	t.Helper()

	eventsCh, errsCh := sh.Events, sh.Errors
	timeout := time.After(5 * time.Second)
	for eventsCh != nil || errsCh != nil {
		select {
		case _, ok := <-eventsCh:
			if !ok {
				eventsCh = nil
				continue
			}
			events++
		case se, ok := <-errsCh:
			if !ok {
				errsCh = nil
				continue
			}
			errs = append(errs, se)
		case <-timeout:
			t.Fatalf("stream channels were not closed within 5s; got %d events and errors %v", events, errs)
		}
	}
	return events, errs
}

// waitEventsClosed reads Events, but not Errors, until the handle closes it,
// failing the test if that takes more than 5s.
func waitEventsClosed(t *testing.T, sh *StreamingHandle) {
	t.Helper()

	timeout := time.After(5 * time.Second)
	for open := true; open; {
		select {
		case _, open = <-sh.Events:
		case <-timeout:
			t.Fatal("expected Events to be closed within 5s while Errors went unread")
		}
	}
}

// within returns what ch receives, failing the test unless it receives or is
// closed within 5s.
func within[T any](t *testing.T, ch <-chan T, what string) (v T) {
	t.Helper()

	select {
	case v = <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("expected %s within 5s", what)
	}
	return v
}

// wantEnd is how a test expects a stream to end: nonFatal non-fatal errors,
// then the final error. The final error wraps cause, and errors.As finds
// causeAs in it. Without either it must be a clean ErrStreamClosed.
type wantEnd struct {
	nonFatal int
	cause    error
	causeAs  any
}

// check fails the test unless errs are those of a stream that ended as w
// expects.
func (w wantEnd) check(t *testing.T, errs []StreamingError) {
	t.Helper()

	if len(errs) != w.nonFatal+1 {
		t.Fatalf("expected %d non-fatal errors, then the final error, got %v", w.nonFatal, errs)
	}
	for _, se := range errs[:w.nonFatal] {
		if se.Fatal {
			t.Fatalf("expected %d non-fatal errors, then the final error, got %v", w.nonFatal, errs)
		}
	}
	w.checkFinal(t, errs[w.nonFatal])
}

// checkFinal fails the test unless final is the final error w expects.
func (w wantEnd) checkFinal(t *testing.T, final StreamingError) {
	t.Helper()

	if !final.Fatal || !errors.Is(final.Err, ErrStreamClosed) {
		t.Fatalf("expected a fatal ErrStreamClosed, got Fatal=%v Err=%v", final.Fatal, final.Err)
	}
	switch {
	case w.cause == nil && w.causeAs == nil && final.Err != ErrStreamClosed:
		t.Fatalf("expected a clean ErrStreamClosed, got %v", final.Err)
	case w.cause != nil && !errors.Is(final.Err, w.cause):
		t.Fatalf("expected the final error to wrap %v, got %v", w.cause, final.Err)
	case w.causeAs != nil && !errors.As(final.Err, w.causeAs):
		t.Fatalf("expected errors.As(%T) to match the final error, got %v", w.causeAs, final.Err)
	}
}

// stopFunc ends a stream as a consumer does once it will not read again: with
// Close, or by cancelling the ctx the stream was opened with.
type stopFunc func(sh *StreamingHandle, cancel context.CancelCauseFunc)

func stopByClose(sh *StreamingHandle, _ context.CancelCauseFunc) { sh.Close() }

func stopByCancel(_ *StreamingHandle, cancel context.CancelCauseFunc) { cancel(nil) }

// readerFunc reads with a plain function.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) {
	return f(p)
}

// idleFeed is a data feed with no events. Like a real response body, its
// pending read fails once the request is cancelled. It gives up after 10s, so
// a handle that never cancels the request fails its test instead of hanging.
func idleFeed(req *http.Request) io.Reader {
	return readerFunc(func([]byte) (int, error) {
		select {
		case <-req.Context().Done():
			return 0, req.Context().Err()
		case <-time.After(10 * time.Second):
			return 0, errors.New("idle data feed was never cancelled")
		}
	})
}

// feedOf returns a data feed holding exactly messages.
func feedOf(messages string) func(*http.Request) io.Reader {
	return func(*http.Request) io.Reader {
		return strings.NewReader(messages)
	}
}

// endlessFeed is a data feed that sends events until the request is cancelled.
func endlessFeed(req *http.Request) io.Reader {
	var wire strings.Reader
	return readerFunc(func(p []byte) (int, error) {
		if err := req.Context().Err(); err != nil {
			return 0, err
		}
		if wire.Len() == 0 {
			wire.Reset(eventMessage)
		}
		return wire.Read(p)
	})
}

// feedBody is a data feed response body that records when it is closed.
type feedBody struct {
	io.Reader
	once     sync.Once
	closed   chan struct{}
	closeErr error
}

func (b *feedBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return b.closeErr
}

func (b *feedBody) isClosed() bool {
	select {
	case <-b.closed:
		return true
	default:
		return false
	}
}

// fakeFeed answers data feed requests with status and a body built by body,
// recording each request and the body it returned. When err is set, the
// request fails with it instead, and when closeErr is set, closing the body
// returns it. open() sends the request on the goroutine that calls
// NewStreamWithClient, so the slices need no lock.
type fakeFeed struct {
	status   int
	body     func(*http.Request) io.Reader
	err      error
	closeErr error
	requests []*http.Request
	bodies   []*feedBody
}

func (f *fakeFeed) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		f.requests = append(f.requests, req)
		if f.err != nil {
			return nil, f.err
		}
		body := &feedBody{Reader: f.body(req), closed: make(chan struct{}), closeErr: f.closeErr}
		f.bodies = append(f.bodies, body)
		return &http.Response{StatusCode: f.status, Body: body, Header: make(http.Header)}, nil
	})}
}

// refreshAPI is an API client whose session refresh requests are answered by
// refresh. Any other API request fails.
func refreshAPI(refresh roundTripFunc) *client.CrowdStrikeAPISpecification {
	return retryingRefreshAPI(refresh, nil)
}

// retryingRefreshAPI is refreshAPI with the retry that ApiConfig.RetryConfig
// sets up, unless config is nil.
func retryingRefreshAPI(refresh roundTripFunc, config *RetryConfig) *client.CrowdStrikeAPISpecification {
	var transport http.RoundTripper = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(req.URL.Path, "/sensors/entities/datafeed-actions/v1/") {
			return nil, fmt.Errorf("unexpected API request to %s", req.URL.Path)
		}
		return refresh(req)
	})
	if config != nil {
		transport = &retryTransport{T: transport, config: config}
	}
	httpClient := &http.Client{Transport: transport}
	return client.New(httptransport.NewWithClient("api.example.com", "/", []string{"https"}, httpClient), strfmt.Default)
}

// idleAPI is the API client for streams whose session no test expects to be
// refreshed. A refresh through it fails, which ends the stream with that
// failure.
var idleAPI = refreshAPI(func(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("unexpected session refresh to %s", req.URL.Path)
})

// jsonResp is an API response with status and a JSON body.
func jsonResp(status int, body string) *http.Response {
	resp := fakeResp(status)
	resp.Header.Set("Content-Type", "application/json")
	resp.Body = io.NopCloser(strings.NewReader(body))
	return resp
}

// connect opens a stream on f whose session no test expects to be refreshed,
// and closes it when the test ends.
func (f *fakeFeed) connect(ctx context.Context, t *testing.T) *StreamingHandle {
	t.Helper()

	return f.connectWith(ctx, t, idleAPI, completeStream())
}

// connectRefreshing opens a stream on f with a one-second session, so that its
// first refresh through api comes after 900ms, and closes it when the test
// ends.
func (f *fakeFeed) connectRefreshing(ctx context.Context, t *testing.T, api *client.CrowdStrikeAPISpecification) *StreamingHandle {
	t.Helper()

	return f.connectWith(ctx, t, api, withInterval(1))
}

func (f *fakeFeed) connectWith(ctx context.Context, t *testing.T, api *client.CrowdStrikeAPISpecification, stream *models.MainAvailableStreamV2) *StreamingHandle {
	t.Helper()

	sh, err := NewStreamWithClient(ctx, api, "app", stream, 0, f.client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(sh.Close)
	return sh
}

func TestNewStreamWithClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		stream *models.MainAvailableStreamV2
		offset uint64
		// noAPI connects without an API client.
		noAPI   bool
		wantErr string
		wantURL string
	}{
		{
			// The generated Validate would reject this descriptor for fields
			// the stream never reads.
			name:    "descriptor with only the fields the stream reads connects",
			stream:  completeStream(),
			wantURL: "https://data.example.com/datafeed/v2",
		},
		{
			// The data feed URL ListAvailableStreamsOAuth2 returns already
			// carries the appId query parameter.
			name: "offset is added to the data feed URL",
			stream: withStream(func(s *models.MainAvailableStreamV2) {
				s.DataFeedURL = swag.String("https://data.example.com/datafeed/v2?appId=app")
			}),
			offset:  42,
			wantURL: "https://data.example.com/datafeed/v2?appId=app&offset=42",
		},
		{
			name:    "data feed URL that does not parse is rejected before any request",
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.DataFeedURL = swag.String("http://bad host/feed") }),
			wantErr: "open streaming connection: parse",
		},
		{
			name:    "unusable descriptor is rejected before the data feed is opened",
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = nil }),
			wantErr: "no refreshActiveSessionInterval",
		},
		{
			// Without one, the first session refresh would panic.
			name:    "missing API client is rejected before the data feed is opened",
			stream:  completeStream(),
			noAPI:   true,
			wantErr: "no API client provided",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			feed := &fakeFeed{status: http.StatusOK, body: feedOf("")}
			api := idleAPI
			if tc.noAPI {
				api = nil
			}

			sh, err := NewStreamWithClient(context.Background(), api, "app", tc.stream, tc.offset, feed.client())

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected an error containing %q, got %q", tc.wantErr, err.Error())
				}
				if len(feed.requests) != 0 {
					t.Fatalf("expected no data feed request, got %d", len(feed.requests))
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			closeAndDrain(t, sh)

			if len(feed.requests) != 1 {
				t.Fatalf("expected one data feed request, got %d", len(feed.requests))
			}
			if got := feed.requests[0].URL.String(); got != tc.wantURL {
				t.Fatalf("expected the data feed request to go to %q, got %q", tc.wantURL, got)
			}
			if got, want := feed.requests[0].Header.Get("Authorization"), "Token token"; got != want {
				t.Fatalf("expected Authorization %q, got %q", want, got)
			}
		})
	}
}

// NewStream, and NewStreamWithClient given no http.Client, connect with a new
// http.Client, so that changing HTTPClient cannot change http.DefaultClient.
func TestNewStreamDefaultClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		connect func(stream *models.MainAvailableStreamV2) (*StreamingHandle, error)
	}{
		{
			name: "NewStream",
			connect: func(stream *models.MainAvailableStreamV2) (*StreamingHandle, error) {
				return NewStream(context.Background(), idleAPI, "app", stream, 0)
			},
		},
		{
			name: "NewStreamWithClient without a client",
			connect: func(stream *models.MainAvailableStreamV2) (*StreamingHandle, error) {
				return NewStreamWithClient(context.Background(), idleAPI, "app", stream, 0, nil)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The data feed answers with no events, so the stream ends at once.
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			t.Cleanup(server.Close)
			stream := withStream(func(s *models.MainAvailableStreamV2) { s.DataFeedURL = swag.String(server.URL + "/feed?appId=app") })

			sh, err := tc.connect(stream)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			t.Cleanup(sh.Close)
			if sh.HTTPClient == nil || sh.HTTPClient == http.DefaultClient {
				t.Fatalf("expected a new http.Client, got %p", sh.HTTPClient)
			}

			_, errs := drain(t, sh)
			if n := requests.Load(); n != 1 {
				t.Fatalf("expected one data feed request, got %d", n)
			}
			wantEnd{}.check(t, errs)
		})
	}
}

// A one-second session lifetime gives a 900ms refresh period, so the first
// refresh must reach the API no sooner than that, and the second, due at 1.8s,
// no later than 2.5s, which a period half as long again would miss.
func TestNewStreamRefreshesOnComputedPeriod(t *testing.T) {
	t.Parallel()

	refreshed := make(chan *http.Request, 2)
	api := refreshAPI(func(req *http.Request) (*http.Response, error) {
		select {
		case refreshed <- req:
		default:
		}
		return jsonResp(http.StatusOK, "{}"), nil
	})

	// Keep the data feed open with no events, as an idle stream would be.
	feed := &fakeFeed{status: http.StatusOK, body: idleFeed}

	start := time.Now()
	sh := feed.connectRefreshing(context.Background(), t, api)
	t.Cleanup(func() { closeAndDrain(t, sh) })

	var requests []*http.Request
	timeout := time.After(2500 * time.Millisecond)
	for len(requests) < 2 {
		select {
		case req := <-refreshed:
			requests = append(requests, req)
		case <-timeout:
			t.Fatalf("expected two session refreshes within 2.5s for a 1s session lifetime, got %d", len(requests))
		}
		if elapsed := time.Since(start); len(requests) == 1 && elapsed < 900*time.Millisecond {
			t.Fatalf("expected the first refresh after the 900ms period, got it after %v", elapsed)
		}
	}
	for i, req := range requests {
		if req.Method != http.MethodPost || req.URL.Path != "/sensors/entities/datafeed-actions/v1/0" {
			t.Fatalf("refresh %d: expected POST /sensors/entities/datafeed-actions/v1/0, got %s %s", i, req.Method, req.URL.Path)
		}
		query := req.URL.Query()
		if got, want := query.Get("action_name"), "refresh_active_stream_session"; got != want {
			t.Fatalf("refresh %d: expected action_name %q, got %q", i, want, got)
		}
		if got, want := query.Get("appId"), "app"; got != want {
			t.Fatalf("refresh %d: expected appId %q, got %q", i, want, got)
		}
	}
}

// Each event is handed over as it came off the wire: decoded, and with the wire
// bytes kept in RawMessage, which streaming_models.As decodes its typed payload
// from. Each event keeps its own bytes once the next one has been read.
func TestStreamDeliversEvents(t *testing.T) {
	t.Parallel()

	wire := `{"metadata":{"customerIDString":"cid","offset":42,"eventType":"AuthActivityAuditEvent","eventCreationTime":1700000000000},` +
		`"event":{"OperationName":"userAuthenticate","UserId":"user@example.com","Attributes":{"k":"v"}}}`
	// Shorter than the first, so that it would fit in the bytes of the first.
	next := `{"metadata":{"offset":43,"eventType":"UserActivityAuditEvent"},"event":{}}`
	feed := &fakeFeed{status: http.StatusOK, body: feedOf(wire + "\n" + next + "\n")}
	sh := feed.connect(context.Background(), t)

	item := within(t, sh.Events, "the first event")
	second := within(t, sh.Events, "the second event")
	if item == nil || second == nil {
		t.Fatal("Events was closed before both events were delivered")
	}
	wantMetadata := streaming_models.Metadata{CID: "cid", Offset: 42, EventType: "AuthActivityAuditEvent", EventCreationTime: 1700000000000}
	if item.Metadata != wantMetadata {
		t.Fatalf("Metadata = %+v, want %+v", item.Metadata, wantMetadata)
	}
	if item.Event.OperationName == nil || *item.Event.OperationName != "userAuthenticate" || item.Event.Attributes["k"] != "v" {
		t.Fatalf("Event = %+v, want OperationName userAuthenticate and Attributes k=v", item.Event)
	}
	if string(item.RawMessage) != wire {
		t.Fatalf("first RawMessage = %s, want the wire bytes %s", item.RawMessage, wire)
	}
	if string(second.RawMessage) != next || second.Metadata.Offset != 43 {
		t.Fatalf("second event = offset %d, RawMessage %s, want offset 43 and the wire bytes %s", second.Metadata.Offset, second.RawMessage, next)
	}
	typed, err := streaming_models.As[streaming_models.AuthActivityAuditEvent](item)
	if err != nil {
		t.Fatalf("As: %v", err)
	}
	if typed.UserID == nil || *typed.UserID != "user@example.com" {
		t.Fatalf("UserID = %v, want user@example.com", typed.UserID)
	}
	events, errs := drain(t, sh)
	if events != 0 {
		t.Fatalf("expected no event after the 2 sent, got %d", events)
	}
	wantEnd{}.check(t, errs)
}

// An event with a field that does not fit streaming_models.Event is delivered
// like any other, with that field kept in Event.Additional, and nothing is
// reported on Errors.
func TestStreamDeliversEventThatDoesNotFitTheModel(t *testing.T) {
	t.Parallel()

	wire := `{"metadata":{"offset":7,"eventType":"UserActivityAuditEvent"},"event":{"OperationName":"x","UTCTimestamp":"soon"}}`
	feed := &fakeFeed{status: http.StatusOK, body: feedOf(wire + "\n")}
	sh := feed.connect(context.Background(), t)

	var item *streaming_models.EventItem
	select {
	case item = <-sh.Events:
	case se := <-sh.Errors:
		t.Fatalf("expected the event, got error %v", se)
	case <-time.After(5 * time.Second):
		t.Fatal("expected the event within 5s")
	}
	if item == nil {
		t.Fatal("Events was closed before the event was delivered")
	}
	if item.Metadata.Offset != 7 || item.Event.OperationName == nil || *item.Event.OperationName != "x" {
		t.Fatalf("event = offset %d, OperationName %v, want offset 7 and OperationName x", item.Metadata.Offset, item.Event.OperationName)
	}
	if got := string(item.Event.Additional["UTCTimestamp"]); got != `"soon"` {
		t.Fatalf("Additional[UTCTimestamp] = %s, want \"soon\"", got)
	}
	if string(item.RawMessage) != wire {
		t.Fatalf("RawMessage = %s, want the wire bytes %s", item.RawMessage, wire)
	}
	events, errs := drain(t, sh)
	if events != 0 {
		t.Fatalf("expected no event after the one sent, got %d", events)
	}
	wantEnd{}.check(t, errs)
}

// Close only ends the stream. It leaves alone the idle connections of the
// http.Client, which the rest of the program may share.
func TestCloseLeavesIdleConnections(t *testing.T) {
	t.Parallel()

	feed := &fakeFeed{status: http.StatusOK, body: idleFeed}
	transport := &idleCountingTransport{RoundTripper: feed.client().Transport}
	sh, err := NewStreamWithClient(context.Background(), idleAPI, "app", completeStream(), 0, &http.Client{Transport: transport})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	closeAndDrain(t, sh)

	if n := transport.idleClosed.Load(); n != 0 {
		t.Fatalf("expected Close to leave idle connections alone, but they were closed %d times", n)
	}
}

// idleCountingTransport counts how often it is told to close its idle
// connections.
type idleCountingTransport struct {
	http.RoundTripper
	idleClosed atomic.Int32
}

func (t *idleCountingTransport) CloseIdleConnections() {
	t.idleClosed.Add(1)
}

// Once the stream has ended on its own, it lets go of the ctx it was opened
// with, so that a long-lived ctx does not keep a reference to every stream.
func TestStreamEndReleasesParentContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	feed := &fakeFeed{status: http.StatusOK, body: feedOf("")}
	sh := feed.connect(ctx, t)
	drain(t, sh)

	within(t, sh.ctx.Done(), "the stream to let go of its parent ctx after it ended")
}

func TestNewStreamDataFeedStatus(t *testing.T) {
	t.Parallel()

	// An empty feed, so that wrongly refusing the status fails fast instead of
	// hanging on reading the error body.
	for _, status := range []int{http.StatusOK, 299} {
		t.Run(fmt.Sprintf("%d connects", status), func(t *testing.T) {
			t.Parallel()

			feed := &fakeFeed{status: status, body: feedOf("")}
			closeAndDrain(t, feed.connect(context.Background(), t))
		})
	}

	errDial := errors.New("dial refused")
	tests := []struct {
		name   string
		status int
		body   string
		// err fails the data feed request before any response arrives.
		err     error
		wantErr string
		// wantStatus expects the error to wrap a *DataFeedError with it.
		wantStatus int
		wantIs     error
	}{
		{
			name:       "expired session token",
			status:     http.StatusUnauthorized,
			body:       `{"errors":[{"code":401,"message":"access denied"}]}` + "\n",
			wantErr:    `open streaming connection: unexpected status 401: {"errors":[{"code":401,"message":"access denied"}]}`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			// The data feed pretty-prints its errors like this.
			name:       "multi-line error body is put on one line",
			status:     http.StatusUnauthorized,
			body:       "{\n  \"errors\": [\n    {\n      \"code\": 401,\n      \"message\": \"Not authorized\"\n    }\n  ]\n}\n",
			wantErr:    `open streaming connection: unexpected status 401: { "errors": [ { "code": 401, "message": "Not authorized" } ] }`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "long error body is cut short",
			status:     http.StatusServiceUnavailable,
			body:       strings.Repeat("x", 600),
			wantErr:    "open streaming connection: unexpected status 503: " + strings.Repeat("x", 512),
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			// The limit falls between the two bytes of é.
			name:       "character cut in half by the limit is left out",
			status:     http.StatusServiceUnavailable,
			body:       strings.Repeat("x", 511) + "é",
			wantErr:    "open streaming connection: unexpected status 503: " + strings.Repeat("x", 511),
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "status just below 2xx",
			status:     199,
			wantErr:    "open streaming connection: unexpected status 199",
			wantStatus: 199,
		},
		{
			name:       "status just above 2xx",
			status:     http.StatusMultipleChoices,
			wantErr:    "open streaming connection: unexpected status 300",
			wantStatus: http.StatusMultipleChoices,
		},
		{
			name:   "request fails before any response",
			err:    errDial,
			wantIs: errDial,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			feed := &fakeFeed{status: tc.status, body: feedOf(tc.body), err: tc.err}
			sh, err := NewStreamWithClient(context.Background(), idleAPI, "app", completeStream(), 0, feed.client())
			if err == nil {
				closeAndDrain(t, sh)
				t.Fatal("expected an error, got a connected stream")
			}
			if !strings.HasPrefix(err.Error(), "open streaming connection: ") {
				t.Fatalf("expected the error to say the connection could not be opened, got %q", err.Error())
			}
			if tc.wantErr != "" && err.Error() != tc.wantErr {
				t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("expected an error wrapping %v, got %v", tc.wantIs, err)
			}
			var feedErr *DataFeedError
			if tc.wantStatus != 0 && (!errors.As(err, &feedErr) || feedErr.StatusCode != tc.wantStatus) {
				t.Fatalf("expected an error wrapping a *DataFeedError with status %d, got %v", tc.wantStatus, err)
			}
			if len(feed.requests) != 1 {
				t.Fatalf("expected one data feed request, got %d", len(feed.requests))
			}
			if feed.requests[0].Context().Err() == nil {
				t.Fatal("expected the context of the failed connection to be cancelled")
			}
			if tc.err != nil {
				return
			}
			if len(feed.bodies) != 1 {
				t.Fatalf("expected one data feed body, got %d", len(feed.bodies))
			}
			if !feed.bodies[0].isClosed() {
				t.Fatal("expected the refused data feed body to be closed")
			}
		})
	}
}

// When the data feed ends, the handle reports it and closes its channels
// without waiting for Close.
func TestStreamEndsWithDataFeed(t *testing.T) {
	t.Parallel()

	errBodyClose := errors.New("close failed")
	tests := []struct {
		name       string
		feed       string
		closeErr   error
		wantEvents int
		want       wantEnd
	}{
		{
			name:       "events, then the feed ends",
			feed:       eventMessage + eventMessage,
			wantEvents: 2,
		},
		{
			name:       "event that is not an object is reported and skipped",
			feed:       `{"event":[]}` + "\n" + eventMessage,
			wantEvents: 1,
			want:       wantEnd{nonFatal: 1},
		},
		{
			name:       "message cut off by a dropped connection",
			feed:       eventMessage + `{"metadata":{`,
			wantEvents: 1,
			want:       wantEnd{cause: io.ErrUnexpectedEOF},
		},
		{
			name:       "data feed that is not JSON",
			feed:       eventMessage + "<html>",
			wantEvents: 1,
			want:       wantEnd{causeAs: new(*json.SyntaxError)},
		},
		{
			name:       "failure to close the feed is reported but not fatal",
			feed:       eventMessage,
			closeErr:   errBodyClose,
			wantEvents: 1,
			want:       wantEnd{nonFatal: 1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			feed := &fakeFeed{status: http.StatusOK, body: feedOf(tc.feed), closeErr: tc.closeErr}
			sh := feed.connect(context.Background(), t)

			events, errs := drain(t, sh)

			if events != tc.wantEvents {
				t.Fatalf("expected %d events, got %d", tc.wantEvents, events)
			}
			tc.want.check(t, errs)
			if tc.closeErr != nil && !errors.Is(errs[0].Err, tc.closeErr) {
				t.Fatalf("expected the non-fatal error to be %v, got %v", tc.closeErr, errs[0].Err)
			}
			if !feed.bodies[0].isClosed() {
				t.Fatal("expected the data feed body to be closed")
			}
		})
	}
}

// A consumer that stops reading and calls Close must not leave the reader
// blocked on a send forever, never closing the data feed body.
func TestCloseReleasesDataFeedWhenConsumerStopsReading(t *testing.T) {
	t.Parallel()

	// Once the event has been read off the wire the reader is committed to
	// delivering it, so Close lands while that delivery is pending.
	read := make(chan struct{})
	var once sync.Once
	feed := &fakeFeed{status: http.StatusOK, body: func(*http.Request) io.Reader {
		wire := strings.NewReader(eventMessage)
		return readerFunc(func(p []byte) (int, error) {
			n, err := wire.Read(p)
			once.Do(func() { close(read) })
			return n, err
		})
	}}
	sh := feed.connect(context.Background(), t)

	within(t, read, "the reader to read the data feed")
	sh.Close()

	within(t, feed.bodies[0].closed, "the data feed body to be closed after Close")
	drain(t, sh)
}

// A transport given to NewStreamWithClient may hand back a body whose read
// does not end when the request is cancelled. Close must still end the
// stream, so it closes the body itself, which ends the pending read.
func TestCloseReleasesBodyThatIgnoresContext(t *testing.T) {
	t.Parallel()

	feed := &fakeFeed{status: http.StatusOK}
	reading := make(chan struct{})
	var once sync.Once
	feed.body = func(*http.Request) io.Reader {
		return readerFunc(func([]byte) (int, error) {
			once.Do(func() { close(reading) })
			// open() has recorded the body before the reader starts.
			select {
			case <-feed.bodies[0].closed:
				return 0, errors.New("read on closed body")
			case <-time.After(10 * time.Second):
				return 0, errors.New("body was never closed")
			}
		})
	}
	sh := feed.connect(context.Background(), t)
	within(t, reading, "the reader to wait on the data feed")
	sh.Close()

	_, errs := drain(t, sh)
	wantEnd{}.check(t, errs)
}

// After Close nothing will read again, and cancelling the context the stream
// was opened with means the same, so the handle must close its channels even
// though errors are left unread. The final error takes their place, so a
// consumer that reads Errors only once Events has closed still learns how the
// stream ended.
func TestStopWithUnreadErrors(t *testing.T) {
	t.Parallel()

	errShutdown := errors.New("shutting down")
	stops := []struct {
		name      string
		stop      stopFunc
		wantCause error
	}{
		{name: "Close", stop: stopByClose},
		{name: "parent cancel", stop: stopByCancel},
		{
			name:      "parent cancel with a cause",
			stop:      func(_ *StreamingHandle, cancel context.CancelCauseFunc) { cancel(errShutdown) },
			wantCause: errShutdown,
		},
	}
	tests := []struct {
		name string
		// unread is how many messages that are not events come off the
		// wire, one read each, leaving their errors unread.
		unread int
	}{
		{name: "no unread error", unread: 0},
		{name: "unread error waiting in Errors", unread: 1},
		// The second error does not fit, so when the stream stops the reader
		// is either decoding it or already blocked sending it.
		{name: "second unread error behind the first", unread: 2},
	}
	for _, stop := range stops {
		for _, tc := range tests {
			t.Run(stop.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				// Stop once the reader has passed every message whose error
				// fits in Errors, and is on the one that does not.
				waitRead := min(tc.unread+1, 2)
				reached := make(chan struct{})
				feed := &fakeFeed{status: http.StatusOK, body: func(req *http.Request) io.Reader {
					idle := idleFeed(req)
					reads := 0
					return readerFunc(func(p []byte) (int, error) {
						reads++
						if reads == waitRead {
							close(reached)
						}
						if reads <= tc.unread {
							return copy(p, "[1]\n"), nil
						}
						return idle.Read(p)
					})
				}}
				ctx, cancel := context.WithCancelCause(context.Background())
				t.Cleanup(func() { cancel(nil) })
				sh := feed.connect(ctx, t)

				within(t, reached, "the reader to reach the data feed")
				stop.stop(sh, cancel)

				waitEventsClosed(t, sh)
				_, errs := drain(t, sh)
				wantEnd{cause: stop.wantCause}.check(t, errs)
			})
		}
	}
}

// A stream that has ended on its own waits for an unread error to be received
// before its final error. Once Close or the end of ctx says no one will read
// again, it must stop waiting, drop that error, and close its channels.
func TestStopAfterStreamEndedWithUnreadError(t *testing.T) {
	t.Parallel()

	stops := []struct {
		name string
		stop stopFunc
	}{
		{name: "Close", stop: stopByClose},
		{name: "parent cancel", stop: stopByCancel},
	}
	for _, stop := range stops {
		t.Run(stop.name, func(t *testing.T) {
			t.Parallel()

			feed := &fakeFeed{status: http.StatusOK, body: feedOf("[1]\n")}
			ctx, cancel := context.WithCancelCause(context.Background())
			t.Cleanup(func() { cancel(nil) })
			sh := feed.connect(ctx, t)

			// The feed has ended once its body is closed, and the final error
			// then waits behind the unread one.
			within(t, feed.bodies[0].closed, "the data feed body to be closed at the end of the feed")
			stop.stop(sh, cancel)

			waitEventsClosed(t, sh)
			_, errs := drain(t, sh)
			wantEnd{}.check(t, errs)
		})
	}
}

// Until Close the consumer is still expected to read, so a stream that ends on
// its own must not drop an error left unread: it waits for that error to be
// received and sends the final error after it, whether the feed ended cleanly
// or broke.
func TestStreamEndKeepsUnreadError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// tail follows the event on the wire.
		tail      string
		wantCause error
	}{
		{name: "data feed ends"},
		{name: "data feed is cut off", tail: `{"metadata":`, wantCause: io.ErrUnexpectedEOF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			feed := &fakeFeed{status: http.StatusOK, body: feedOf("[1,2]\n" + eventMessage + tc.tail)}
			sh := feed.connect(context.Background(), t)

			// The event follows a message that is not an event, so by the time
			// the event arrives, that message's error is waiting unread.
			within(t, sh.Events, "the event after an unread error")
			// Read nothing more until the feed has ended, so that the stream
			// ends with that error still unread.
			within(t, feed.bodies[0].closed, "the data feed body to be closed at the end of the feed")

			_, errs := drain(t, sh)
			wantEnd{nonFatal: 1, cause: tc.wantCause}.check(t, errs)
		})
	}
}

// A StreamingError received after Errors has closed is the zero value, so
// printing one must not panic.
func TestStreamingErrorText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  StreamingError
		want string
	}{
		{name: "error", err: StreamingError{Err: ErrStreamClosed}, want: ErrStreamClosed.Error()},
		{name: "zero value", err: StreamingError{}, want: "<nil>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

// errors.Is and errors.As see through a StreamingError to its Err.
func TestStreamingErrorUnwrap(t *testing.T) {
	t.Parallel()

	errRefused := errors.New("refresh refused")
	tests := []struct {
		name   string
		err    StreamingError
		target error
		want   bool
	}{
		{name: "final error", err: StreamingError{Fatal: true, Err: ErrStreamClosed}, target: ErrStreamClosed, want: true},
		{
			name:   "cause the final error wraps",
			err:    StreamingError{Fatal: true, Err: fmt.Errorf("%w: %w", ErrStreamClosed, errRefused)},
			target: errRefused,
			want:   true,
		},
		{name: "zero value", err: StreamingError{}, target: ErrStreamClosed, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := errors.Is(tc.err, tc.target); got != tc.want {
				t.Fatalf("errors.Is(%v, %v) = %v, want %v", tc.err, tc.target, got, tc.want)
			}
		})
	}

	t.Run("errors.As reaches a typed cause", func(t *testing.T) {
		t.Parallel()

		se := StreamingError{Err: fmt.Errorf("open streaming connection: %w", &DataFeedError{StatusCode: http.StatusUnauthorized})}
		var feedErr *DataFeedError
		if !errors.As(se, &feedErr) || feedErr.StatusCode != http.StatusUnauthorized {
			t.Fatalf("errors.As(%v, *DataFeedError) did not find the 401", se)
		}
	})
}

// Cancelling the context the stream was opened with ends it like any other
// end of the connection, so a consumer still reading gets the final error,
// which also wraps the cancel cause or deadline if there is one.
func TestParentCancelEndsStream(t *testing.T) {
	t.Parallel()

	// cancelWith opens a ctx that end cancels with cause.
	cancelWith := func(cause error) func() (ctx context.Context, end func()) {
		return func() (context.Context, func()) {
			ctx, cancel := context.WithCancelCause(context.Background())
			return ctx, func() { cancel(cause) }
		}
	}
	errShutdown := errors.New("shutting down")
	errCanceledShutdown := fmt.Errorf("shutting down: %w", context.Canceled)
	tests := []struct {
		name string
		// open returns the ctx to open the stream with, and end, which ends
		// that ctx once the reader is waiting on the data feed.
		open      func() (ctx context.Context, end func())
		wantCause error
	}{
		{name: "plain cancel", open: cancelWith(nil)},
		{name: "cancel with a cause", open: cancelWith(errShutdown), wantCause: errShutdown},
		{
			// Only the plain context.Canceled says nothing about why.
			name:      "cancel with a cause that wraps context.Canceled",
			open:      cancelWith(errCanceledShutdown),
			wantCause: errCanceledShutdown,
		},
		{
			name: "deadline",
			open: func() (context.Context, func()) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
				return ctx, func() {
					<-ctx.Done()
					cancel()
				}
			},
			wantCause: context.DeadlineExceeded,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Repeat it so that a delivery left to chance cannot pass.
			for i := range 50 {
				ctx, end := tc.open()
				t.Cleanup(end)
				// End ctx only once the reader is waiting on the feed, so that
				// it fails a pending read instead of landing before the first
				// one. A deadline may still pass before the first read on a
				// busy machine, which then ends the stream without one.
				reading := make(chan struct{})
				feed := &fakeFeed{status: http.StatusOK, body: func(req *http.Request) io.Reader {
					idle := idleFeed(req)
					var once sync.Once
					return readerFunc(func(p []byte) (int, error) {
						once.Do(func() { close(reading) })
						return idle.Read(p)
					})
				}}
				sh := feed.connect(ctx, t)

				select {
				case <-reading:
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
					t.Fatalf("round %d: the reader did not read the data feed within 5s", i)
				}
				end()
				_, errs := drain(t, sh)

				wantEnd{cause: tc.wantCause}.check(t, errs)
				if !feed.bodies[0].isClosed() {
					t.Fatalf("round %d: expected the data feed body to be closed", i)
				}
			}
		})
	}
}

// Once the data feed ends nothing more can arrive, so the session refresh must
// stop even while an error waits unread in Errors and the failure to close the
// data feed is waiting to be sent after it.
func TestDataFeedEndStopsSessionRefresh(t *testing.T) {
	t.Parallel()

	refreshing := make(chan struct{}, 1)
	released := make(chan struct{}, 1)
	api := refreshAPI(func(req *http.Request) (*http.Response, error) {
		select {
		case refreshing <- struct{}{}:
		default:
		}
		<-req.Context().Done()
		select {
		case released <- struct{}{}:
		default:
		}
		return nil, req.Context().Err()
	})
	wire, feedWriter := io.Pipe()
	t.Cleanup(func() { _ = feedWriter.Close() })
	// If the feed were refused, NewStreamWithClient would block reading the
	// pipe as an error body. End the pipe after a while so that it fails
	// instead of hanging.
	watchdog := time.AfterFunc(10*time.Second, func() {
		_ = feedWriter.CloseWithError(errors.New("the data feed was not read to its end within 10s"))
	})
	t.Cleanup(func() { watchdog.Stop() })
	errCloseFailed := errors.New("close failed")
	feed := &fakeFeed{
		status:   http.StatusOK,
		body:     func(*http.Request) io.Reader { return wire },
		closeErr: errCloseFailed,
	}
	sh := feed.connectRefreshing(context.Background(), t, api)

	within(t, refreshing, "a session refresh")
	// The write returns once the reader has taken the message, whose error
	// then waits unread.
	if _, err := feedWriter.Write([]byte("[1]\n")); err != nil {
		t.Fatalf("write to the data feed: %v", err)
	}
	_ = feedWriter.Close()

	within(t, released, "the session refresh to stop once the data feed ended")
	// The refresh cut short by the end of the feed is not why it ended.
	_, errs := drain(t, sh)
	wantEnd{nonFatal: 2}.check(t, errs)
	if !errors.Is(errs[1].Err, errCloseFailed) {
		t.Fatalf("expected the second non-fatal error to be the close failure, got %v", errs[1].Err)
	}
}

// Nothing of the stream may still run once its channels are closed, so a
// refresh still on its way back holds them open until it returns.
func TestChannelsCloseAfterSessionRefresh(t *testing.T) {
	t.Parallel()

	refreshing := make(chan struct{})
	release := make(chan struct{})
	var once, releaseOnce sync.Once
	releaseRefresh := func() { releaseOnce.Do(func() { close(release) }) }
	// Let the refresh go even if the test fails before it would.
	t.Cleanup(releaseRefresh)
	var returned atomic.Bool
	api := refreshAPI(func(*http.Request) (*http.Response, error) {
		once.Do(func() { close(refreshing) })
		// Like a transport that does not give up on a cancelled request.
		<-release
		returned.Store(true)
		return nil, errors.New("refresh answered late")
	})
	feed := &fakeFeed{status: http.StatusOK, body: idleFeed}
	sh := feed.connectRefreshing(context.Background(), t, api)

	within(t, refreshing, "a session refresh")
	sh.Close()
	time.AfterFunc(100*time.Millisecond, releaseRefresh)

	_, errs := drain(t, sh)
	if !returned.Load() {
		t.Fatal("expected the channels to stay open until the session refresh returned")
	}
	// The refresh failed only after Close had ended the stream, so it is not
	// why the stream ended.
	wantEnd{}.check(t, errs)
}

// A refresh cut short by the end of the stream is not a failure, so the stream
// still ends with a clean ErrStreamClosed.
func TestSessionRefreshCutShort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		stop stopFunc
	}{
		{name: "refresh cut short by Close is not reported", stop: stopByClose},
		{name: "refresh cut short by a parent cancel is not reported", stop: stopByCancel},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			refreshing := make(chan struct{}, 1)
			api := refreshAPI(func(req *http.Request) (*http.Response, error) {
				select {
				case refreshing <- struct{}{}:
				default:
				}
				<-req.Context().Done()
				return nil, req.Context().Err()
			})
			feed := &fakeFeed{status: http.StatusOK, body: idleFeed}
			ctx, cancel := context.WithCancelCause(context.Background())
			t.Cleanup(func() { cancel(nil) })
			sh := feed.connectRefreshing(ctx, t, api)

			within(t, refreshing, "a session refresh")
			tc.stop(sh, cancel)

			_, errs := drain(t, sh)
			wantEnd{}.check(t, errs)
		})
	}
}

// The connection cannot outlive its session, so a refresh that keeps failing
// ends the stream once the session would expire, the full one-second interval
// after it started, and the final error says why. The retries wait 3.125ms,
// then twice as long each time, so the sixth and last attempt starts 96.875ms
// into the last 100ms of the session. The channels close only once the refresh
// has stopped, so by then the attempt count is final.
func TestFailedRefreshEndsStreamWhenSessionExpires(t *testing.T) {
	t.Parallel()

	errReset := errors.New("connection reset")
	var attempts atomic.Int32
	api := refreshAPI(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		return nil, errReset
	})
	feed := &fakeFeed{status: http.StatusOK, body: idleFeed}
	start := time.Now()
	sh := feed.connectRefreshing(context.Background(), t, api)

	_, errs := drain(t, sh)
	elapsed := time.Since(start)
	wantEnd{cause: errReset}.check(t, errs)
	if n := attempts.Load(); n != 6 {
		t.Fatalf("expected 6 refresh attempts, got %d", n)
	}
	if lastAttempt := 900*time.Millisecond + 96875*time.Microsecond; elapsed < lastAttempt {
		t.Fatalf("expected the stream to end no sooner than the last attempt at %v, got %v", lastAttempt, elapsed)
	}
	if !feed.bodies[0].isClosed() {
		t.Fatal("expected the data feed body to be closed")
	}
}

// A refresh that fails on the network, with a 429 or with a 5xx may succeed
// if tried again, so it is retried while the session lasts, with or without
// ApiConfig.RetryConfig, and the stream keeps running.
func TestFailedRefreshRetried(t *testing.T) {
	t.Parallel()

	retry := &RetryConfig{MaxTries: 2, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond}
	tests := []struct {
		name  string
		fail  func() (*http.Response, error)
		retry *RetryConfig
	}{
		{
			name: "network error",
			fail: func() (*http.Response, error) { return nil, errors.New("connection reset") },
		},
		{
			name: "429",
			fail: func() (*http.Response, error) { return jsonResp(http.StatusTooManyRequests, "{}"), nil },
		},
		{
			name: "500",
			fail: func() (*http.Response, error) { return jsonResp(http.StatusInternalServerError, "{}"), nil },
		},
		{
			name: "503, a status the generated client does not know",
			fail: func() (*http.Response, error) { return jsonResp(http.StatusServiceUnavailable, "{}"), nil },
		},
		{
			// Each attempt is retried by RetryConfig too, and fails once its
			// two tries have run out.
			name:  "503 under RetryConfig",
			fail:  func() (*http.Response, error) { return jsonResp(http.StatusServiceUnavailable, "{}"), nil },
			retry: retry,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			const failures = 3
			var requests atomic.Int32
			succeeded := make(chan struct{})
			var once sync.Once
			api := retryingRefreshAPI(func(*http.Request) (*http.Response, error) {
				if requests.Add(1) <= failures {
					return tc.fail()
				}
				once.Do(func() { close(succeeded) })
				return jsonResp(http.StatusOK, "{}"), nil
			}, tc.retry)
			feed := &fakeFeed{status: http.StatusOK, body: idleFeed}
			sh := feed.connectRefreshing(context.Background(), t, api)

			within(t, succeeded, "the failed refresh to be retried until it succeeded")
			// The stream is still running, so only Close ends it, cleanly.
			sh.Close()
			_, errs := drain(t, sh)
			wantEnd{}.check(t, errs)
		})
	}
}

// After a retried refresh succeeds, the session lasts the full interval from
// then on, so the next refresh comes a whole refresh period after it, not on
// the schedule of the refresh that failed. With a two-second interval, four
// failures delay the success by 93.75ms, which the old schedule would take off
// the next period.
func TestRefreshAfterRetryWaitsFullPeriod(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	succeeded := make(chan time.Time, 1)
	next := make(chan time.Time, 1)
	api := refreshAPI(func(*http.Request) (*http.Response, error) {
		switch n := attempts.Add(1); {
		case n <= 4:
			return nil, errors.New("connection reset")
		case n == 5:
			succeeded <- time.Now()
		default:
			select {
			case next <- time.Now():
			default:
			}
		}
		return jsonResp(http.StatusOK, "{}"), nil
	})
	feed := &fakeFeed{status: http.StatusOK, body: idleFeed}
	sh := feed.connectWith(context.Background(), t, api, withInterval(2))
	t.Cleanup(func() { closeAndDrain(t, sh) })

	success := within(t, succeeded, "the retried refresh to succeed")
	if gap := within(t, next, "the next refresh").Sub(success); gap < 1800*time.Millisecond {
		t.Fatalf("expected the next refresh a full 1.8s period after the retried one, got it after %v", gap)
	}
}

// A failed refresh ends the stream, but the consumer is still expected to read,
// so errors it has not received yet are kept: the reader waits to hand them
// over before the final error. The messages behind them are not read once the
// stream has ended.
func TestFailedRefreshKeepsUnreadErrors(t *testing.T) {
	t.Parallel()

	errRefused := errors.New("refresh refused")
	// The refresh fails only once the reader has taken the second message off
	// the wire, so that its error is bound to wait behind the first.
	second := make(chan struct{})
	api := refreshAPI(func(req *http.Request) (*http.Response, error) {
		select {
		case <-second:
			return nil, errRefused
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	})
	// One message per read: the first error waits in Errors, the reader waits
	// to send the second, and two more messages wait behind them.
	feed := &fakeFeed{status: http.StatusOK, body: func(req *http.Request) io.Reader {
		messages := []string{"[1]\n", "[2]\n", "[3]\n", "[4]\n"}
		idle := idleFeed(req)
		reads := 0
		return readerFunc(func(p []byte) (int, error) {
			if reads == len(messages) {
				return idle.Read(p)
			}
			if reads == 1 {
				close(second)
			}
			n := copy(p, messages[reads])
			reads++
			return n, nil
		})
	}}
	sh := feed.connectRefreshing(context.Background(), t, api)

	within(t, sh.readCtx.Done(), "the failed refresh to end the stream")

	_, errs := drain(t, sh)
	wantEnd{nonFatal: 2, cause: errRefused}.check(t, errs)
}

// A stream that a failed refresh has ended still waits for an unread error to
// be received before its final error, as any other end of the stream does.
func TestFailedRefreshWaitsForUnreadErrorAtEnd(t *testing.T) {
	t.Parallel()

	errRefused := errors.New("refresh refused")
	api := refreshAPI(func(*http.Request) (*http.Response, error) {
		return nil, errRefused
	})
	// The error of the first message waits unread while the reader waits on the
	// rest of the feed, which the failed refresh then cuts off.
	feed := &fakeFeed{status: http.StatusOK, body: func(req *http.Request) io.Reader {
		return io.MultiReader(strings.NewReader("[1]\n"), idleFeed(req))
	}}
	sh := feed.connectRefreshing(context.Background(), t, api)

	within(t, feed.bodies[0].closed, "the failed refresh to end the stream")

	_, errs := drain(t, sh)
	wantEnd{nonFatal: 1, cause: errRefused}.check(t, errs)
}

// A failed refresh ends the stream even while the reader is waiting to hand
// over an event no one takes, so a consumer that reads only Errors still learns
// that the stream ended.
func TestFailedRefreshEndsStreamWithEventPending(t *testing.T) {
	t.Parallel()

	errRefused := errors.New("refresh refused")
	api := refreshAPI(func(*http.Request) (*http.Response, error) {
		return nil, errRefused
	})
	feed := &fakeFeed{status: http.StatusOK, body: feedOf(eventMessage)}
	sh := feed.connectRefreshing(context.Background(), t, api)

	final := within(t, sh.Errors, "the final error while an event was pending")
	wantEnd{cause: errRefused}.checkFinal(t, final)
	drain(t, sh)
}

// A refresh the API rejects with any other error status cannot succeed if tried
// again, so it ends the stream at once, and the final error lets errors.As
// reach the error of the generated client. The API answers a 404 for an
// unknown appId, a status the generated client does not know.
func TestRefreshRejectedByAPI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int
		causeAs any
	}{
		{name: "400", status: http.StatusBadRequest, causeAs: new(*event_streams.RefreshActiveStreamSessionBadRequest)},
		{name: "403", status: http.StatusForbidden, causeAs: new(*event_streams.RefreshActiveStreamSessionForbidden)},
		{name: "404", status: http.StatusNotFound, causeAs: new(*runtime.APIError)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var attempts atomic.Int32
			api := refreshAPI(func(*http.Request) (*http.Response, error) {
				attempts.Add(1)
				return jsonResp(tc.status, fmt.Sprintf(`{"errors":[{"code":%d,"message":"rejected"}]}`, tc.status)), nil
			})
			feed := &fakeFeed{status: http.StatusOK, body: idleFeed}
			sh := feed.connectRefreshing(context.Background(), t, api)

			_, errs := drain(t, sh)
			wantEnd{causeAs: tc.causeAs}.check(t, errs)
			if n := attempts.Load(); n != 1 {
				t.Fatalf("expected one refresh attempt, got %d", n)
			}
		})
	}
}

// Close may be called from several goroutines at once, also while ctx is
// cancelled, and the stream still ends exactly once.
func TestConcurrentClose(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	feed := &fakeFeed{status: http.StatusOK, body: endlessFeed}
	sh := feed.connect(ctx, t)

	var closers sync.WaitGroup
	for i := range 10 {
		closers.Add(1)
		go func() {
			defer closers.Done()
			if i == 5 {
				cancel()
			}
			sh.Close()
		}()
	}
	_, errs := drain(t, sh)
	closers.Wait()

	wantEnd{}.check(t, errs)
}

// A ctx that has already ended stops NewStream from connecting, and the error
// says so. That holds for a transport that checks the request ctx before it
// dials, as http.Transport does.
func TestNewStreamWithEndedContext(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)
	stream := withStream(func(s *models.MainAvailableStreamV2) { s.DataFeedURL = swag.String(server.URL + "/feed?appId=app") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sh, err := NewStreamWithClient(ctx, idleAPI, "app", stream, 0, server.Client())
	if err == nil {
		closeAndDrain(t, sh)
		t.Fatal("expected an error, got a connected stream")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected an error wrapping context.Canceled, got %v", err)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("expected no data feed request, got %d", n)
	}
}

// A consumer that reads both channels in one select loop until a fatal error,
// as examples/falcon_event_stream does, must check each receive from Events:
// Events can close before the final error has been received. The final error
// must then be the next one in Errors, with nothing after it, however the
// stream ends.
func TestConsumerLoopReceivesFinalError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body func(*http.Request) io.Reader
		// stop, when set, ends the stream once an event has arrived.
		stop      stopFunc
		wantCause error
		// waitEnd makes the loop wait after each event until the reader has
		// reached the end of the data feed.
		waitEnd bool
	}{
		{name: "data feed ends", body: feedOf(eventMessage + eventMessage)},
		{
			// When the loop takes the event before the error, it comes back
			// only once the feed has ended with the error still waiting, so
			// Events must stay open until that error has been received.
			name:    "data feed ends with an error unread",
			body:    feedOf("[1]\n" + eventMessage),
			waitEnd: true,
		},
		{name: "data feed fails", body: feedOf(eventMessage + `{"metadata":`), wantCause: io.ErrUnexpectedEOF},
		{name: "Close", body: endlessFeed, stop: stopByClose},
		{name: "parent cancel", body: endlessFeed, stop: stopByCancel},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Repeat it so that the case a select happens to pick cannot pass.
			for i := range 200 {
				ctx, cancel := context.WithCancelCause(context.Background())
				t.Cleanup(func() { cancel(nil) })
				feed := &fakeFeed{status: http.StatusOK, body: tc.body}
				sh := feed.connect(ctx, t)
				final := consumeUntilFatal(t, sh, func() {
					if tc.waitEnd {
						within(t, feed.bodies[0].closed, fmt.Sprintf("the reader to reach the end of the data feed in round %d", i))
					}
					if tc.stop != nil {
						tc.stop(sh, cancel)
					}
				})
				events, rest := drain(t, sh)

				wantEnd{cause: tc.wantCause}.checkFinal(t, final)
				if events != 0 || len(rest) != 0 {
					t.Fatalf("round %d: expected nothing after the final error, got %d events and errors %v", i, events, rest)
				}
			}
		})
	}
}

// consumeUntilFatal reads sh in one select loop until the fatal error, checking
// each receive from Events, and returns that error. onEvent runs after every
// event. The final error is sent before either channel closes, so once Events
// is closed it must already be waiting in Errors.
func consumeUntilFatal(t *testing.T, sh *StreamingHandle, onEvent func()) StreamingError {
	t.Helper()

	timeout := time.After(5 * time.Second)
	for {
		select {
		case se := <-sh.Errors:
			if se.Fatal {
				return se
			}
			if se.Err == nil {
				t.Fatal("Errors was closed before the fatal error was received")
			}
		case _, ok := <-sh.Events:
			if !ok {
				select {
				case se := <-sh.Errors:
					return se
				default:
					t.Fatal("Events was closed before the final error was sent")
				}
			}
			onEvent()
		case <-timeout:
			t.Fatal("the stream did not end within 5s")
		}
	}
}
