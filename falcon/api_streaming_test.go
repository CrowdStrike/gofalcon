package falcon

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
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
	errs, events := sh.Errors, sh.Events
	timeout := time.After(5 * time.Second)
	for errs != nil || events != nil {
		select {
		case _, ok := <-errs:
			if !ok {
				errs = nil
			}
		case _, ok := <-events:
			if !ok {
				events = nil
			}
		case <-timeout:
			t.Fatal("stream channels were not closed within 5s of Close")
		}
	}
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
	apiHTTPClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(req.URL.Path, "/sensors/entities/datafeed-actions/v1/") {
			return nil, fmt.Errorf("unexpected API request to %s", req.URL.Path)
		}
		select {
		case refreshed <- struct{}{}:
		default:
		}
		resp := fakeResp(http.StatusOK)
		resp.Header.Set("Content-Type", "application/json")
		resp.Body = io.NopCloser(strings.NewReader("{}"))
		return resp, nil
	})}
	api := client.New(httptransport.NewWithClient("api.example.com", "/", []string{"https"}, apiHTTPClient), strfmt.Default)

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
