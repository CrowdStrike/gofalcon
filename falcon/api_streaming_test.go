package falcon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

// completeStream is the shape ListAvailableStreamsOAuth2 returns for a usable
// stream, limited to the fields the streaming handle actually reads.
func completeStream() *models.MainAvailableStreamV2 {
	return &models.MainAvailableStreamV2{
		DataFeedURL:                  swag.String("https://firehose.example.com/sensors/entities/datafeed/v2"),
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
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(0) }),
			wantErr: "unusable refreshActiveSessionInterval: 0",
		},
		{
			name:    "negative refresh interval",
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(-5) }),
			wantErr: "unusable refreshActiveSessionInterval: -5",
		},
		{
			name:    "refresh interval that would overflow the period",
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(math.MaxInt64) }),
			wantErr: "unusable refreshActiveSessionInterval",
		},
		{
			name:       "one second still yields a usable period",
			stream:     withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(1) }),
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
			stream:     withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(10248191152) }),
			wantPeriod: 9223372036800000000,
		},
		{
			name:    "one second past the largest interval",
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(10248191153) }),
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
			if period <= 0 {
				t.Fatalf("refresh period %v would panic time.NewTicker", period)
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
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(req.URL.Path, "/sensors/entities/datafeed-actions/v1/") {
			return nil, fmt.Errorf("unexpected API request to %s", req.URL.Path)
		}
		return refresh(req)
	})}
	return client.New(httptransport.NewWithClient("api.example.com", "/", []string{"https"}, httpClient), strfmt.Default)
}

func TestNewStreamWithClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		stream  *models.MainAvailableStreamV2
		wantErr string
	}{
		{
			// The generated Validate would reject this descriptor for fields
			// the stream never reads.
			name:   "descriptor with only the fields the stream reads connects",
			stream: completeStream(),
		},
		{
			name:    "unusable descriptor is rejected before the data feed is opened",
			stream:  withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = nil }),
			wantErr: "no refreshActiveSessionInterval",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// open() sends the data feed request on the calling goroutine, so
			// the slice needs no lock.
			var requests []*http.Request
			httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests = append(requests, req)
				return fakeResp(http.StatusOK), nil
			})}

			sh, err := NewStreamWithClient(context.Background(), nil, "app", tc.stream, 0, httpClient)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected an error containing %q, got %q", tc.wantErr, err.Error())
				}
				if len(requests) != 0 {
					t.Fatalf("expected no data feed request, got %d", len(requests))
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			closeAndDrain(t, sh)

			if len(requests) != 1 {
				t.Fatalf("expected one data feed request, got %d", len(requests))
			}
			if got, want := requests[0].URL.String(), "https://firehose.example.com/sensors/entities/datafeed/v2"; got != want {
				t.Fatalf("expected the data feed request to go to %q, got %q", want, got)
			}
			if got, want := requests[0].Header.Get("Authorization"), "Token token"; got != want {
				t.Fatalf("expected Authorization %q, got %q", want, got)
			}
		})
	}
}

// A one-second session lifetime gives a 900ms refresh period, so a refresh
// must reach the API well within the wait below. A handle that ignored the
// computed period would not refresh at all in that time.
func TestNewStreamRefreshesOnComputedPeriod(t *testing.T) {
	t.Parallel()

	refreshed := make(chan struct{}, 1)
	api := refreshAPI(func(*http.Request) (*http.Response, error) {
		select {
		case refreshed <- struct{}{}:
		default:
		}
		resp := fakeResp(http.StatusOK)
		resp.Header.Set("Content-Type", "application/json")
		resp.Body = io.NopCloser(strings.NewReader("{}"))
		return resp, nil
	})

	// Keep the data feed open with no events, as an idle stream would be.
	feed, feedWriter := io.Pipe()
	feedHTTPClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: feed, Header: make(http.Header)}, nil
	})}

	stream := withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(1) })
	sh, err := NewStreamWithClient(context.Background(), api, "app", stream, 0, feedHTTPClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-refreshed:
	case <-time.After(3 * time.Second):
		t.Error("expected a session refresh within 3s for a 1s session lifetime")
	}

	_ = feedWriter.Close()
	closeAndDrain(t, sh)
}

func TestNewStreamReportsDataFeedRefusal(t *testing.T) {
	t.Parallel()

	errDial := errors.New("dial refused")
	tests := []struct {
		name   string
		status int
		body   string
		// err fails the data feed request before any response arrives.
		err     error
		wantErr string
		wantIs  error
	}{
		{
			name:    "expired session token",
			status:  http.StatusUnauthorized,
			body:    `{"errors":[{"code":401,"message":"access denied"}]}` + "\n",
			wantErr: `open streaming connection: unexpected status 401: {"errors":[{"code":401,"message":"access denied"}]}`,
		},
		{
			// The data feed pretty-prints its errors like this.
			name:    "multi-line error body is put on one line",
			status:  http.StatusUnauthorized,
			body:    "{\n  \"errors\": [\n    {\n      \"code\": 401,\n      \"message\": \"Not authorized\"\n    }\n  ]\n}\n",
			wantErr: `open streaming connection: unexpected status 401: { "errors": [ { "code": 401, "message": "Not authorized" } ] }`,
		},
		{
			name:    "long error body is cut short",
			status:  http.StatusServiceUnavailable,
			body:    strings.Repeat("x", 600),
			wantErr: "open streaming connection: unexpected status 503: " + strings.Repeat("x", 512),
		},
		{
			name:    "status just below 2xx",
			status:  199,
			wantErr: "open streaming connection: unexpected status 199",
		},
		{
			name:    "status just above 2xx",
			status:  http.StatusMultipleChoices,
			wantErr: "open streaming connection: unexpected status 300",
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
			sh, err := NewStreamWithClient(context.Background(), nil, "app", completeStream(), 0, feed.client())
			if err == nil {
				closeAndDrain(t, sh)
				t.Fatal("expected an error, got a connected stream")
			}
			if tc.wantErr != "" && err.Error() != tc.wantErr {
				t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("expected an error wrapping %v, got %v", tc.wantIs, err)
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

func TestNewStreamAcceptsEvery2xxStatus(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusOK, 299} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			t.Parallel()

			// An empty feed, so that wrongly refusing the status fails fast
			// instead of hanging on reading the error body.
			feed := &fakeFeed{status: status, body: feedOf("")}
			sh, err := NewStreamWithClient(context.Background(), nil, "app", completeStream(), 0, feed.client())
			if err != nil {
				t.Fatalf("expected status %d to connect, got %v", status, err)
			}
			closeAndDrain(t, sh)
		})
	}
}

// When the data feed ends, the handle reports it and closes its channels
// without waiting for Close.
func TestStreamEndsWithDataFeed(t *testing.T) {
	t.Parallel()

	event := `{"metadata":{"eventType":"UserActivityAuditEvent"},"event":{"OperationName":"x"}}`
	errBodyClose := errors.New("close failed")
	tests := []struct {
		name         string
		feed         string
		closeErr     error
		wantEvents   int
		wantNonFatal int
		wantCause    error
	}{
		{
			name:       "events, then the feed ends",
			feed:       event + "\n" + event + "\n",
			wantEvents: 2,
		},
		{
			name:         "event that does not fit the model is reported and skipped",
			feed:         `{"event":[]}` + "\n" + event,
			wantEvents:   1,
			wantNonFatal: 1,
		},
		{
			name:       "message cut off by a dropped connection",
			feed:       event + "\n" + `{"metadata":{`,
			wantEvents: 1,
			wantCause:  io.ErrUnexpectedEOF,
		},
		{
			name:         "failure to close the feed is reported but not fatal",
			feed:         event + "\n",
			closeErr:     errBodyClose,
			wantEvents:   1,
			wantNonFatal: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			feed := &fakeFeed{status: http.StatusOK, body: feedOf(tc.feed), closeErr: tc.closeErr}
			sh, err := NewStreamWithClient(context.Background(), nil, "app", completeStream(), 0, feed.client())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			t.Cleanup(sh.Close)

			events, errs := drain(t, sh)

			if events != tc.wantEvents {
				t.Fatalf("expected %d events, got %d", tc.wantEvents, events)
			}
			var nonFatal, fatal []error
			for _, se := range errs {
				if se.Fatal {
					fatal = append(fatal, se.Err)
				} else {
					nonFatal = append(nonFatal, se.Err)
				}
			}
			if len(nonFatal) != tc.wantNonFatal {
				t.Fatalf("expected %d non-fatal errors, got %d: %v", tc.wantNonFatal, len(nonFatal), errs)
			}
			if tc.closeErr != nil && !errors.Is(nonFatal[0], tc.closeErr) {
				t.Fatalf("expected the non-fatal error to be %v, got %v", tc.closeErr, nonFatal[0])
			}
			if len(fatal) != 1 || !errors.Is(fatal[0], ErrStreamClosed) {
				t.Fatalf("expected exactly one fatal ErrStreamClosed, got %v", fatal)
			}
			if last := errs[len(errs)-1]; !last.Fatal || !errors.Is(last.Err, ErrStreamClosed) {
				t.Fatalf("expected the fatal ErrStreamClosed to arrive last, got %v", errs)
			}
			if tc.wantCause == nil && fatal[0] != ErrStreamClosed {
				t.Fatalf("expected a clean end of stream, got %v", fatal[0])
			}
			if tc.wantCause != nil && !errors.Is(fatal[0], tc.wantCause) {
				t.Fatalf("expected the end of stream to wrap %v, got %v", tc.wantCause, fatal[0])
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
		wire := strings.NewReader(`{"metadata":{"eventType":"UserActivityAuditEvent"},"event":{}}`)
		return readerFunc(func(p []byte) (int, error) {
			n, err := wire.Read(p)
			once.Do(func() { close(read) })
			return n, err
		})
	}}
	sh, err := NewStreamWithClient(context.Background(), nil, "app", completeStream(), 0, feed.client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(sh.Close)

	select {
	case <-read:
	case <-time.After(5 * time.Second):
		t.Fatal("the reader did not read the data feed within 5s")
	}
	sh.Close()

	select {
	case <-feed.bodies[0].closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the data feed body was not closed within 5s of Close")
	}
	drain(t, sh)
}

// After Close nothing will read again, so the handle must finish and close its
// channels even though the consumer never reads the errors still pending.
func TestCloseEndsStreamWithoutReadingErrors(t *testing.T) {
	t.Parallel()

	feed := &fakeFeed{status: http.StatusOK, body: idleFeed}
	sh, err := NewStreamWithClient(context.Background(), nil, "app", completeStream(), 0, feed.client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sh.Close()

	timeout := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-sh.Events:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("Events was not closed within 5s of Close while Errors went unread")
		}
	}
}

// Cancelling the context the stream was opened with ends it like any other
// end of the connection, so a consumer still reading gets the final error.
func TestParentCancelEndsStream(t *testing.T) {
	t.Parallel()

	// Repeat it so that a delivery left to chance cannot pass.
	for i := range 50 {
		ctx, cancel := context.WithCancel(context.Background())
		// Cancel only once the reader is waiting on the feed, so that the
		// cancel fails a pending read instead of landing before the first one.
		reading := make(chan struct{})
		feed := &fakeFeed{status: http.StatusOK, body: func(req *http.Request) io.Reader {
			idle := idleFeed(req)
			var once sync.Once
			return readerFunc(func(p []byte) (int, error) {
				once.Do(func() { close(reading) })
				return idle.Read(p)
			})
		}}
		sh, err := NewStreamWithClient(ctx, nil, "app", completeStream(), 0, feed.client())
		if err != nil {
			cancel()
			t.Fatalf("unexpected error: %v", err)
		}

		select {
		case <-reading:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatalf("round %d: the reader did not read the data feed within 5s", i)
		}
		cancel()
		_, errs := drain(t, sh)
		sh.Close()

		if len(errs) != 1 || !errs[0].Fatal || errs[0].Err != ErrStreamClosed {
			t.Fatalf("round %d: expected exactly one fatal ErrStreamClosed, got %v", i, errs)
		}
		if !feed.bodies[0].isClosed() {
			t.Fatalf("round %d: expected the data feed body to be closed", i)
		}
	}
}

// Once the data feed ends nothing more can arrive, so the session refresh must
// stop even while no one is reading Errors.
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
	feed := &fakeFeed{status: http.StatusOK, body: func(*http.Request) io.Reader { return wire }}
	stream := withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(1) })
	sh, err := NewStreamWithClient(context.Background(), api, "app", stream, 0, feed.client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(sh.Close)

	select {
	case <-refreshing:
	case <-time.After(3 * time.Second):
		t.Fatal("expected a session refresh within 3s for a 1s session lifetime")
	}
	_ = feedWriter.Close()

	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the session refresh was still running 5s after the data feed ended")
	}
	closeAndDrain(t, sh)
}

func TestSessionRefreshErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		refresh roundTripFunc
		// cancelParent ends the stream by cancelling the context it was
		// opened with instead of calling Close. Close may drop a pending
		// error, so only a parent cancel shows a spurious report every time.
		cancelParent bool
	}{
		{
			name: "refresh cut short by Close is not reported",
			refresh: func(req *http.Request) (*http.Response, error) {
				<-req.Context().Done()
				return nil, req.Context().Err()
			},
		},
		{
			name: "refresh cut short by a parent cancel is not reported",
			refresh: func(req *http.Request) (*http.Response, error) {
				<-req.Context().Done()
				return nil, req.Context().Err()
			},
			cancelParent: true,
		},
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
				return tc.refresh(req)
			})
			feed := &fakeFeed{status: http.StatusOK, body: idleFeed}
			stream := withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(1) })
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			sh, err := NewStreamWithClient(ctx, api, "app", stream, 0, feed.client())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			t.Cleanup(sh.Close)

			select {
			case <-refreshing:
			case <-time.After(3 * time.Second):
				t.Fatal("expected a session refresh within 3s for a 1s session lifetime")
			}

			if tc.cancelParent {
				cancel()
				_, errs := drain(t, sh)
				if len(errs) != 1 || !errs[0].Fatal || errs[0].Err != ErrStreamClosed {
					t.Fatalf("expected exactly one fatal ErrStreamClosed after the parent cancel, got %v", errs)
				}
				return
			}

			sh.Close()
			_, errs := drain(t, sh)
			for _, se := range errs {
				if !errors.Is(se.Err, ErrStreamClosed) {
					t.Fatalf("expected only ErrStreamClosed after Close, got %v", se.Err)
				}
			}
		})
	}
}

// A failed refresh is reported as fatal, but the connection it could not
// refresh keeps delivering events until it ends, and the session is not
// refreshed again.
func TestFailedRefreshKeepsStreamRunning(t *testing.T) {
	t.Parallel()

	refreshes := make(chan struct{}, 2)
	api := refreshAPI(func(*http.Request) (*http.Response, error) {
		refreshes <- struct{}{}
		return nil, errors.New("refresh refused")
	})
	wire, feedWriter := io.Pipe()
	t.Cleanup(func() { _ = feedWriter.Close() })
	feed := &fakeFeed{status: http.StatusOK, body: func(req *http.Request) io.Reader {
		// Like a real response body, the feed fails once its request is
		// cancelled, so a refresh failure that ended the stream would show.
		context.AfterFunc(req.Context(), func() { _ = wire.CloseWithError(req.Context().Err()) })
		return wire
	}}
	stream := withStream(func(s *models.MainAvailableStreamV2) { s.RefreshActiveSessionInterval = swag.Int64(1) })
	sh, err := NewStreamWithClient(context.Background(), api, "app", stream, 0, feed.client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(sh.Close)

	select {
	case se := <-sh.Errors:
		if !se.Fatal || errors.Is(se.Err, ErrStreamClosed) || !strings.Contains(se.Err.Error(), "refresh refused") {
			t.Fatalf("expected the fatal refresh failure, got %+v", se)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected the refresh failure within 5s for a 1s session lifetime")
	}

	go func() {
		_, _ = io.WriteString(feedWriter, `{"metadata":{"eventType":"UserActivityAuditEvent","offset":7},"event":{}}`+"\n")
	}()
	select {
	case ev := <-sh.Events:
		if ev.Metadata.Offset != 7 {
			t.Fatalf("expected the event at offset 7, got %+v", ev.Metadata)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected the connection to keep delivering events after the refresh failure")
	}

	// Two more refresh periods pass without another attempt.
	<-refreshes
	select {
	case <-refreshes:
		t.Fatal("expected no refresh after the first one failed")
	case <-time.After(2 * time.Second):
	}

	_ = feedWriter.Close()
	events, errs := drain(t, sh)
	if events != 0 || len(errs) != 1 || !errs[0].Fatal || errs[0].Err != ErrStreamClosed {
		t.Fatalf("expected the feed's end to bring only a clean ErrStreamClosed, got %d events and errors %v", events, errs)
	}
}
