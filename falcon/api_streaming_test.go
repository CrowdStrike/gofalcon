package falcon

import (
	"context"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

func strPtr(s string) *string { return &s }
func i64Ptr(i int64) *int64   { return &i }

func completeStream() *models.MainAvailableStreamV2 {
	return &models.MainAvailableStreamV2{
		DataFeedURL:                  strPtr("https://firehose.example.com/sensors/entities/datafeed/v2"),
		RefreshActiveSessionInterval: i64Ptr(1800),
		RefreshActiveSessionURL:      strPtr("https://api.example.com/sensors/entities/datafeed-actions/v1"),
		SessionToken: &models.MainSessionToken{
			Token: strPtr("token"),
		},
	}
}

func TestNewStreamRejectsIncompleteDescriptor(t *testing.T) {
	noInterval := completeStream()
	noInterval.RefreshActiveSessionInterval = nil

	zeroInterval := completeStream()
	zeroInterval.RefreshActiveSessionInterval = i64Ptr(0)

	noToken := completeStream()
	noToken.SessionToken = nil

	noURL := completeStream()
	noURL.DataFeedURL = nil

	for name, stream := range map[string]*models.MainAvailableStreamV2{
		"no stream":        nil,
		"no interval":      noInterval,
		"zero interval":    zeroInterval,
		"no session token": noToken,
		"no data feed url": noURL,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewStream(context.Background(), nil, "app", stream, 0)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}
