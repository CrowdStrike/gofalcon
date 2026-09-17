package falcon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	httpruntime "github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// fakeTransport returns responses from a pre-configured sequence, repeating the
// last entry once exhausted. It also records the body read on each call.
type fakeTransport struct {
	responses []*http.Response
	errors    []error
	calls     int
	bodies    []string
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil && req.Body != http.NoBody {
		b, _ := io.ReadAll(req.Body)
		f.bodies = append(f.bodies, string(b))
	} else {
		f.bodies = append(f.bodies, "")
	}
	i := f.calls
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	f.calls++
	return f.responses[i], f.errors[i]
}

func fakeResp(code int) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
	}
}

func fastRetry(maxTries uint) *RetryConfig {
	return &RetryConfig{
		MaxTries:        maxTries,
		InitialInterval: time.Millisecond,
		MaxInterval:     5 * time.Millisecond,
	}
}

func TestRetryTransport(t *testing.T) {
	tests := map[string]struct {
		responses  []*http.Response
		errors     []error
		wantStatus int
		wantErr    bool
		wantCalls  int
	}{
		"no retry on 2xx": {
			responses:  []*http.Response{fakeResp(200)},
			errors:     []error{nil},
			wantStatus: 200,
			wantCalls:  1,
		},
		"no retry on 4xx": {
			responses:  []*http.Response{fakeResp(400)},
			errors:     []error{nil},
			wantStatus: 400,
			wantCalls:  1,
		},
		"retries on 429": {
			responses:  []*http.Response{fakeResp(429), fakeResp(200)},
			errors:     []error{nil, nil},
			wantStatus: 200,
			wantCalls:  2,
		},
		"retries on 5xx": {
			responses:  []*http.Response{fakeResp(503), fakeResp(503), fakeResp(200)},
			errors:     []error{nil, nil, nil},
			wantStatus: 200,
			wantCalls:  3,
		},
		"stops after MaxTries": {
			responses: []*http.Response{fakeResp(503)},
			errors:    []error{nil},
			wantErr:   true,
			wantCalls: 3,
		},
		"retries on network error": {
			responses:  []*http.Response{nil, fakeResp(200)},
			errors:     []error{errors.New("connection refused"), nil},
			wantStatus: 200,
			wantCalls:  2,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := &fakeTransport{responses: tc.responses, errors: tc.errors}
			rt := &retryTransport{T: fake, config: fastRetry(3)}

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
			resp, err := rt.RoundTrip(req)

			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErr && resp.StatusCode != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, resp.StatusCode)
			}
			if fake.calls != tc.wantCalls {
				t.Fatalf("expected %d calls, got %d", tc.wantCalls, fake.calls)
			}
		})
	}
}

func TestRetryTransport_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fake := &fakeTransport{
		responses: []*http.Response{nil, nil, nil},
		errors:    []error{errors.New("err"), errors.New("err"), errors.New("err")},
	}
	rt := &retryTransport{
		T:      &cancelAfterNTransport{wrapped: fake, n: 2, cancel: cancel},
		config: fastRetry(10),
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	_, err := rt.RoundTrip(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

// TestRetryTransport_UnlimitedRetriesUntilContextCancellation verifies that
// MaxTries:0 keeps retrying until context cancellation and is not subject to
// any internal elapsed-time limit imposed by the backoff library.
func TestRetryTransport_UnlimitedRetriesUntilContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fake := &fakeTransport{
		responses: []*http.Response{nil, nil, nil, nil, nil},
		errors:    []error{errors.New("err"), errors.New("err"), errors.New("err"), errors.New("err"), errors.New("err")},
	}
	rt := &retryTransport{
		T:      &cancelAfterNTransport{wrapped: fake, n: 4, cancel: cancel},
		config: &RetryConfig{MaxTries: 0, InitialInterval: time.Millisecond, MaxInterval: 5 * time.Millisecond},
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	_, err := rt.RoundTrip(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if fake.calls < 4 {
		t.Fatalf("expected at least 4 calls before cancellation, got %d", fake.calls)
	}
}

// cancelAfterNTransport cancels the context after n calls.
type cancelAfterNTransport struct {
	wrapped http.RoundTripper
	n       int
	calls   int
	cancel  context.CancelFunc
}

func (c *cancelAfterNTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls++
	if c.calls >= c.n {
		c.cancel()
	}
	return c.wrapped.RoundTrip(req)
}

func TestRetryTransport_BodyReplayedOnRetry(t *testing.T) {
	body := "hello falcon"
	fake := &fakeTransport{
		responses: []*http.Response{fakeResp(503), fakeResp(200)},
		errors:    []error{nil, nil},
	}
	rt := &retryTransport{T: fake, config: fastRetry(3)}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", bytes.NewBufferString(body))
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", fake.calls)
	}
	for i, b := range fake.bodies {
		if b != body {
			t.Errorf("call %d: expected body %q, got %q", i, body, b)
		}
	}
}

func fakeRespWithRetryAfter(code int, retryAfter string) *http.Response {
	r := fakeResp(code)
	r.Header.Set("X-RateLimit-RetryAfter", retryAfter)
	return r
}

func TestRetryTransport_UsesRetryAfterHeader(t *testing.T) {
	retryAt := fmt.Sprintf("%d", time.Now().Add(1*time.Second).Unix())
	fake := &fakeTransport{
		responses: []*http.Response{fakeRespWithRetryAfter(429, retryAt), fakeResp(200)},
		errors:    []error{nil, nil},
	}
	rt := &retryTransport{T: fake, config: fastRetry(3)}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if fake.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", fake.calls)
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := map[string]struct {
		header   string
		wantMin  time.Duration
		wantMax  time.Duration
		wantZero bool
	}{
		"future epoch": {
			header:  fmt.Sprintf("%d", time.Now().Add(30*time.Second).Unix()),
			wantMin: 25 * time.Second,
			wantMax: 35 * time.Second,
		},
		"near-future epoch clamps to 1s": {
			header:  fmt.Sprintf("%d", time.Now().Unix()+1),
			wantMin: 1 * time.Millisecond,
			wantMax: 2 * time.Second,
		},
		"past epoch": {
			header:   fmt.Sprintf("%d", time.Now().Add(-10*time.Second).Unix()),
			wantZero: true,
		},
		"empty string": {
			header:   "",
			wantZero: true,
		},
		"non-numeric": {
			header:   "not-a-number",
			wantZero: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := parseRetryAfter(tc.header)
			if tc.wantZero {
				if got != 0 {
					t.Fatalf("expected 0, got %v", got)
				}
				return
			}
			if got < tc.wantMin || got > tc.wantMax {
				t.Fatalf("expected duration in [%v, %v], got %v", tc.wantMin, tc.wantMax, got)
			}
		})
	}
}

func TestRetryTransport_RetryAfterMissingHeaderFallsBack(t *testing.T) {
	fake := &fakeTransport{
		responses: []*http.Response{fakeResp(429), fakeResp(200)},
		errors:    []error{nil, nil},
	}
	rt := &retryTransport{T: fake, config: fastRetry(3)}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if fake.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", fake.calls)
	}
}

func TestRetryTransport_RetryAfterInvalidHeaderFallsBack(t *testing.T) {
	fake := &fakeTransport{
		responses: []*http.Response{fakeRespWithRetryAfter(429, "not-a-number"), fakeResp(200)},
		errors:    []error{nil, nil},
	}
	rt := &retryTransport{T: fake, config: fastRetry(3)}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if fake.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", fake.calls)
	}
}

func TestRetryTransport_5xxDoesNotUseRetryAfter(t *testing.T) {
	retryAt := fmt.Sprintf("%d", time.Now().Add(30*time.Second).Unix())
	resp503 := fakeResp(503)
	resp503.Header.Set("X-RateLimit-RetryAfter", retryAt)

	fake := &fakeTransport{
		responses: []*http.Response{resp503, fakeResp(200)},
		errors:    []error{nil, nil},
	}
	rt := &retryTransport{T: fake, config: fastRetry(3)}

	start := time.Now()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("5xx should use exponential backoff, not retry-after; elapsed %v", elapsed)
	}
}

func TestRetryTransport_SharedCooldownGatesSubsequentRequests(t *testing.T) {
	fake := &fakeTransport{
		responses: []*http.Response{fakeResp(200), fakeResp(200)},
		errors:    []error{nil, nil},
	}
	rt := &retryTransport{T: fake, config: fastRetry(3)}

	rt.setCooldown(500 * time.Millisecond)

	rt.mu.Lock()
	cooldownSet := !rt.cooldownUntil.IsZero()
	rt.mu.Unlock()

	if !cooldownSet {
		t.Fatal("expected cooldownUntil to be set after setCooldown")
	}

	start := time.Now()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/gated", nil)
	resp, err := rt.RoundTrip(req)
	waited := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if waited < 400*time.Millisecond {
		t.Fatalf("expected request to be gated by cooldown, but only waited %v", waited)
	}
}

func TestRetryTransport_SharedCooldownConcurrentRequests(t *testing.T) {
	transport := &funcTransport{fn: func(req *http.Request) (*http.Response, error) {
		return fakeResp(200), nil
	}}
	rt := &retryTransport{T: transport, config: fastRetry(5)}

	rt.setCooldown(500 * time.Millisecond)

	var wg sync.WaitGroup
	var gatedCount atomic.Int32

	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/gated", nil)
			resp, err := rt.RoundTrip(req)
			elapsed := time.Since(start)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if resp.StatusCode != 200 {
				t.Errorf("expected 200, got %d", resp.StatusCode)
				return
			}
			if elapsed >= 400*time.Millisecond {
				gatedCount.Add(1)
			}
		}()
	}

	wg.Wait()

	if gatedCount.Load() == 0 {
		t.Fatal("expected at least one concurrent request to be gated by cooldown")
	}
}

func TestRetryTransport_CooldownRespectsContextCancellation(t *testing.T) {
	rt := &retryTransport{
		T:      &fakeTransport{responses: []*http.Response{fakeResp(200)}, errors: []error{nil}},
		config: fastRetry(3),
	}

	rt.mu.Lock()
	rt.cooldownUntil = time.Now().Add(10 * time.Second)
	rt.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	_, err := rt.RoundTrip(req)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
}

// funcTransport is a test helper that calls a function for each RoundTrip.
type funcTransport struct {
	fn func(*http.Request) (*http.Response, error)
}

func (f *funcTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f.fn(req)
}

func fakeRespWithRemaining(code int, remaining string) *http.Response {
	r := fakeResp(code)
	r.Header.Set("X-Ratelimit-Remaining", remaining)
	return r
}

func TestRoundTripper_ProactiveThrottle_NoDelay(t *testing.T) {
	t.Parallel()
	fake := &fakeTransport{
		responses: []*http.Response{fakeRespWithRemaining(200, "50"), fakeRespWithRemaining(200, "49")},
		errors:    []error{nil, nil},
	}
	rt := &roundTripper{T: fake, UserAgent: "test"}
	rt.remaining.Store(-1)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	start := time.Now()
	_, _ = rt.RoundTrip(req)
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("unexpected delay on first request with unknown remaining")
	}

	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	start = time.Now()
	_, _ = rt.RoundTrip(req2)
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("unexpected delay when remaining=50")
	}
}

func TestRoundTripper_ProactiveThrottle_ModerateDelay(t *testing.T) {
	t.Parallel()
	fake := &fakeTransport{
		responses: []*http.Response{fakeRespWithRemaining(200, "7")},
		errors:    []error{nil},
	}
	rt := &roundTripper{T: fake, UserAgent: "test"}
	rt.remaining.Store(8)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	start := time.Now()
	_, _ = rt.RoundTrip(req)
	elapsed := time.Since(start)
	if elapsed < 150*time.Millisecond || elapsed > 400*time.Millisecond {
		t.Fatalf("expected ~200ms delay, got %v", elapsed)
	}
}

func TestRoundTripper_ProactiveThrottle_StrongDelay(t *testing.T) {
	t.Parallel()
	fake := &fakeTransport{
		responses: []*http.Response{fakeRespWithRemaining(200, "2")},
		errors:    []error{nil},
	}
	rt := &roundTripper{T: fake, UserAgent: "test"}
	rt.remaining.Store(3)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	start := time.Now()
	_, _ = rt.RoundTrip(req)
	elapsed := time.Since(start)
	if elapsed < 400*time.Millisecond || elapsed > 750*time.Millisecond {
		t.Fatalf("expected ~500ms delay, got %v", elapsed)
	}
}

func TestRoundTripper_ProactiveThrottle_ContextCancelled(t *testing.T) {
	t.Parallel()
	fake := &fakeTransport{
		responses: []*http.Response{fakeResp(200)},
		errors:    []error{nil},
	}
	rt := &roundTripper{T: fake, UserAgent: "test"}
	rt.remaining.Store(1)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	start := time.Now()
	_, err := rt.RoundTrip(req)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("expected prompt cancellation, but waited %v", elapsed)
	}
}

func TestRoundTripper_ProactiveThrottle_UnparseableHeader(t *testing.T) {
	t.Parallel()
	fake := &fakeTransport{
		responses: []*http.Response{fakeRespWithRemaining(200, "abc")},
		errors:    []error{nil},
	}
	rt := &roundTripper{T: fake, UserAgent: "test"}
	rt.remaining.Store(-1)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	start := time.Now()
	_, _ = rt.RoundTrip(req)
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("unexpected delay with unparseable header")
	}
	if rt.remaining.Load() != -1 {
		t.Fatalf("expected remaining to stay -1, got %d", rt.remaining.Load())
	}
}

func TestWaitForCooldown_PreflightDeadlineExceeded(t *testing.T) {
	t.Parallel()
	rt := &retryTransport{
		T:      &fakeTransport{responses: []*http.Response{fakeResp(200)}, errors: []error{nil}},
		config: fastRetry(3),
	}
	rt.mu.Lock()
	rt.cooldownUntil = time.Now().Add(10 * time.Second)
	rt.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := rt.waitForCooldown(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
	if elapsed > 10*time.Millisecond {
		t.Fatalf("expected immediate return from preflight check, but waited %v", elapsed)
	}
	if !strings.Contains(err.Error(), "exceeds context deadline") {
		t.Fatalf("expected descriptive error message, got: %v", err)
	}
}

func TestDownloadAwareJSONConsumer(t *testing.T) {
	jsonArray := `[{"a":1},{"b":2}]`
	jsonObject := `{"n":123}`

	// writerTarget cases assert raw bytes are streamed verbatim into an io.Writer,
	// which is how the report-download endpoints pass their payload. A plain
	// JSONConsumer would instead try to json-decode into the writer and fail.
	t.Run("io.Writer target streams JSON array verbatim", func(t *testing.T) {
		var buf bytes.Buffer
		if err := downloadAwareConsumer(httpruntime.JSONConsumer()).Consume(strings.NewReader(jsonArray), &buf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if buf.String() != jsonArray {
			t.Fatalf("expected %q, got %q", jsonArray, buf.String())
		}
	})

	t.Run("io.Writer target streams JSON object verbatim", func(t *testing.T) {
		var buf bytes.Buffer
		if err := downloadAwareConsumer(httpruntime.JSONConsumer()).Consume(strings.NewReader(jsonObject), &buf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if buf.String() != jsonObject {
			t.Fatalf("expected %q, got %q", jsonObject, buf.String())
		}
	})

	t.Run("non-writer target decodes as JSON with UseNumber", func(t *testing.T) {
		var out struct {
			N json.Number `json:"n"`
		}
		if err := downloadAwareConsumer(httpruntime.JSONConsumer()).Consume(strings.NewReader(jsonObject), &out); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.N != json.Number("123") {
			t.Fatalf("expected json.Number 123, got %q", out.N)
		}
	})
}

func TestDownloadAwareCSVConsumer(t *testing.T) {
	// rawCSV uses CRLF row terminators and a quoted field containing a comma.
	// A csv.Reader -> csv.Writer round-trip (what the default CSVConsumer does for
	// an io.Writer target) rewrites CRLF to LF and may re-quote fields, so this
	// payload proves the download path streams the exact bytes instead.
	rawCSV := "a,b\r\nc,\"d,e\"\r\n"

	t.Run("io.Writer target streams CSV verbatim", func(t *testing.T) {
		var buf bytes.Buffer
		if err := downloadAwareConsumer(httpruntime.CSVConsumer()).Consume(strings.NewReader(rawCSV), &buf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if buf.String() != rawCSV {
			t.Fatalf("expected %q, got %q", rawCSV, buf.String())
		}
	})

	t.Run("io.ReaderFrom target streams CSV verbatim", func(t *testing.T) {
		var target readerFromBuffer
		if err := downloadAwareConsumer(httpruntime.CSVConsumer()).Consume(strings.NewReader(rawCSV), &target); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.buf.String() != rawCSV {
			t.Fatalf("expected %q, got %q", rawCSV, target.buf.String())
		}
	})

	t.Run("non-writer target decodes CSV into records", func(t *testing.T) {
		var records [][]string
		if err := downloadAwareConsumer(httpruntime.CSVConsumer()).Consume(strings.NewReader(rawCSV), &records); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := [][]string{{"a", "b"}, {"c", "d,e"}}
		if !reflect.DeepEqual(records, want) {
			t.Fatalf("expected %v, got %v", want, records)
		}
	})
}

// readerFromBuffer is an io.ReaderFrom that is not itself an io.Writer, so it
// exercises the consumer's io.ReaderFrom branch rather than the io.Writer one.
type readerFromBuffer struct {
	buf bytes.Buffer
}

func (r *readerFromBuffer) ReadFrom(src io.Reader) (int64, error) {
	return r.buf.ReadFrom(src)
}

func TestDownloadAwareYAMLConsumer(t *testing.T) {
	// Generated models carry only json struct tags. A tag-unaware YAML decoder
	// maps fields by lowercased Go field name, so snake_case wire names such as
	// created_timestamp and trace_id silently drop and decode as nil. Decoding
	// into a real generated model here proves the consumer routes YAML through
	// JSON so those json tags drive the mapping.
	const configYAML = `meta:
  trace_id: trace-123
resources:
  - id: cfg-1
    name: my-config
    created_timestamp: "2024-01-02T03:04:05Z"
`
	consumer := downloadAwareConsumer(yamlJSONConsumer())

	t.Run("snake_case YAML populates json-tagged model fields", func(t *testing.T) {
		var payload models.DomainEntitiesConfigurationsResponseV1
		if err := consumer.Consume(strings.NewReader(configYAML), &payload); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if payload.Meta == nil || payload.Meta.TraceID == nil {
			t.Fatalf("meta.trace_id not decoded: %+v", payload.Meta)
		}
		if got := *payload.Meta.TraceID; got != "trace-123" {
			t.Fatalf("expected trace_id trace-123, got %q", got)
		}

		if len(payload.Resources) != 1 {
			t.Fatalf("expected 1 resource, got %d", len(payload.Resources))
		}
		res := payload.Resources[0]
		if res.ID == nil || *res.ID != "cfg-1" {
			t.Fatalf("expected id cfg-1, got %v", res.ID)
		}
		if res.Name == nil || *res.Name != "my-config" {
			t.Fatalf("expected name my-config, got %v", res.Name)
		}

		wantTS, err := time.Parse(time.RFC3339, "2024-01-02T03:04:05Z")
		if err != nil {
			t.Fatalf("parse expected timestamp: %v", err)
		}
		if res.CreatedTimestamp == nil || !time.Time(*res.CreatedTimestamp).Equal(wantTS) {
			t.Fatalf("expected created_timestamp %s, got %v", wantTS, res.CreatedTimestamp)
		}
	})

	t.Run("io.Writer target streams YAML verbatim", func(t *testing.T) {
		// Download endpoints that advertise YAML pass an io.Writer target; the
		// download-aware wrapper must stream the exact bytes rather than decode.
		var buf bytes.Buffer
		if err := consumer.Consume(strings.NewReader(configYAML), &buf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if buf.String() != configYAML {
			t.Fatalf("expected verbatim YAML, got %q", buf.String())
		}
	})
}

func TestBinaryDownloadMediaTypes(t *testing.T) {
	got := binaryDownloadMediaTypes()

	t.Run("covers the download and streaming binary types", func(t *testing.T) {
		// These are the produced content types that the go-openapi runtime does
		// not register a consumer for by default. Without registration the runtime
		// returns a "no consumer" error for the download or stream.
		want := []string{
			"application/gzip",
			"application/msword",
			"application/pdf",
			"application/vnd.ms-excel",
			"application/vnd.openxmlformats-officedocument.presentationml.presentation",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			"application/x-7z-compressed",
			"application/zip",
			"image/bmp",
			"image/gif",
			"image/jpeg",
			"image/jpg",
			"image/png",
			"text/event-stream",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("expected %v, got %v", want, got)
		}
	})

	t.Run("excludes types that need structured decoding", func(t *testing.T) {
		// These content types decode into typed models (or, for a download target,
		// stream through the download-aware consumer), and text/plain is served by
		// the runtime's default text consumer. Byte-streaming them here would clobber
		// that handling.
		excluded := map[string]struct{}{
			"application/json":        {},
			"application/schema+json": {},
			"application/x-ndjson":    {},
			"application/yaml":        {},
			"application/x-yaml":      {},
			"text/csv":                {},
			"text/plain":              {},
		}
		for _, mediaType := range got {
			if _, bad := excluded[mediaType]; bad {
				t.Fatalf("media type %q must not be in binaryDownloadMediaTypes", mediaType)
			}
		}
	})

	t.Run("byte-stream consumer preserves binary payloads verbatim", func(t *testing.T) {
		// The registered consumer must stream raw bytes into the string payload
		// without decoding. Bytes here include a NUL and high bytes that a text or
		// CSV round-trip would alter.
		raw := string([]byte{0x00, 0xFF, 0x0D, 0x0A, 'P', 'K', 0x03, 0x04})
		var payload string
		if err := httpruntime.ByteStreamConsumer().Consume(strings.NewReader(raw), &payload); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if payload != raw {
			t.Fatalf("expected %q, got %q", raw, payload)
		}
	})
}

func TestRegisterDownloadConsumers(t *testing.T) {
	// producedMediaTypes are the content types the swagger spec advertises in a
	// response `produces` block that the go-openapi runtime does not resolve to a
	// consumer on its own. If a new endpoint introduces another such type, this
	// test fails until registerDownloadConsumers covers it, guarding against the
	// "no consumer" download regressions that PRs #725 and #731 addressed.
	producedMediaTypes := []string{
		"application/gzip",
		"application/json",
		"application/msword",
		"application/pdf",
		"application/schema+json",
		"application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/x-7z-compressed",
		"application/x-ndjson",
		"application/x-yaml",
		"application/yaml",
		"application/zip",
		"image/bmp",
		"image/gif",
		"image/jpeg",
		"image/jpg",
		"image/png",
		"text/csv",
		"text/event-stream",
		// charset params must be stripped before lookup, as the runtime does.
		"application/json; charset=utf-8",
	}

	transport := httptransport.New("example.com", "/", []string{"https"})
	registerDownloadConsumers(transport)

	for _, mediaType := range producedMediaTypes {
		t.Run(mediaType, func(t *testing.T) {
			key, _, err := mime.ParseMediaType(mediaType)
			if err != nil {
				t.Fatalf("parse media type %q: %v", mediaType, err)
			}
			if _, ok := transport.Consumers[key]; !ok {
				t.Fatalf("no consumer registered for produced media type %q", mediaType)
			}
		})
	}
}
