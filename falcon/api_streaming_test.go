package falcon

import (
	"context"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/swag"

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
		{
			name: "largest interval that still fits",
			stream: withStream(func(s *models.MainAvailableStreamV2) {
				s.RefreshActiveSessionInterval = swag.Int64(maxRefreshActiveSessionInterval)
			}),
			wantPeriod: time.Duration(maxRefreshActiveSessionInterval) * refreshPeriodPerSecond,
		},
		{
			name: "one second past the largest interval",
			stream: withStream(func(s *models.MainAvailableStreamV2) {
				s.RefreshActiveSessionInterval = swag.Int64(maxRefreshActiveSessionInterval + 1)
			}),
			wantErr: "unusable refreshActiveSessionInterval",
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

// A descriptor carrying only the fields the stream reads is accepted, even
// though the generated Validate would reject it for the fields it does not.
func TestNewStreamAcceptsMinimalDescriptor(t *testing.T) {
	t.Parallel()

	fake := &fakeTransport{responses: []*http.Response{fakeResp(http.StatusOK)}, errors: []error{nil}}
	httpClient := &http.Client{Transport: fake}

	sh, err := NewStreamWithClient(context.Background(), nil, "app", completeStream(), 0, httpClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sh.Close()
	// open() reports the closed connection on the way out; drain it so the
	// reader goroutine can finish.
	<-sh.Errors
}
