package falcon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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
