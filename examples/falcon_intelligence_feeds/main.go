package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/intelligence_feeds"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

var errDownloadURLCaptured = errors.New("feed download URL captured")

// downloadURLCapture stops net/http from automatically following the API's
// redirect so each worker can download the signed URL to a file.
type downloadURLCapture struct {
	next      http.RoundTripper
	locations sync.Map
}

func (c *downloadURLCapture) decorate(next http.RoundTripper) http.RoundTripper {
	c.next = next
	return c
}

func (c *downloadURLCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if req.URL.Path != "/indicator-feed/entities/feed-download/v1" || resp.StatusCode != http.StatusPermanentRedirect {
		return resp, nil
	}

	location := resp.Header.Get("Location")
	feedItemID := req.URL.Query().Get("feed_item_id")
	if location == "" || feedItemID == "" {
		return resp, nil
	}

	c.locations.Store(feedItemID, location)
	if resp.Body != nil {
		resp.Body.Close()
	}
	return nil, errDownloadURLCaptured
}

func (c *downloadURLCapture) take(feedItemID string) (string, bool) {
	location, ok := c.locations.LoadAndDelete(feedItemID)
	if !ok {
		return "", false
	}
	return location.(string), true
}

func main() {
	clientID := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Falcon OAuth2 client ID (defaults to FALCON_CLIENT_ID)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Falcon OAuth2 client secret (defaults to FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for an OAuth2 client that can access multiple CIDs")
	cloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation, such as us-1, us-2, eu-1, or us-gov-1")
	feedName := flag.String("feed-name", "", "Name of an intelligence feed available to the customer")
	feedInterval := flag.String("feed-interval", "any", "Feed interval: any, dump, daily, hourly, or minutely")
	lookback := flag.Duration("lookback", 24*time.Hour, "How far back to query feed archives")
	concurrency := flag.Int("concurrency", 4, "Maximum number of concurrent downloads")
	outputDir := flag.String("output-dir", "feeds", "Directory for downloaded feed archives")
	flag.Parse()

	if *clientID == "" || *clientSecret == "" {
		fatal(errors.New("set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET or pass --client-id and --client-secret"))
	}
	if *feedName == "" {
		fatal(errors.New("pass --feed-name with a feed available to this customer"))
	}
	if *lookback <= 0 {
		fatal(errors.New("--lookback must be greater than zero"))
	}
	if *concurrency <= 0 {
		fatal(errors.New("--concurrency must be greater than zero"))
	}

	ctx := context.Background()
	capture := &downloadURLCapture{}
	falconClient, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:           *clientID,
		ClientSecret:       *clientSecret,
		MemberCID:          *memberCID,
		Cloud:              falcon.Cloud(*cloud),
		Context:            ctx,
		TransportDecorator: capture.decorate,
	})
	if err != nil {
		fatal(err)
	}

	items, err := queryFeedArchives(
		ctx,
		falconClient,
		*feedName,
		*feedInterval,
		time.Now().UTC().Add(-*lookback),
	)
	if err != nil {
		fatal(err)
	}
	if len(items) == 0 {
		fmt.Println("No feed archives matched the query.")
		return
	}

	if err := os.MkdirAll(*outputDir, 0o750); err != nil {
		fatal(fmt.Errorf("create output directory: %w", err))
	}

	fmt.Printf("Downloading %d feed archives with up to %d concurrent requests.\n", len(items), *concurrency)
	downloader := &http.Client{Timeout: 10 * time.Minute}
	if err := downloadFeedArchives(ctx, falconClient, capture, downloader, items, *outputDir, *concurrency); err != nil {
		fatal(err)
	}
}

// queryFeedArchives uses the since parameter as a cursor. Feed item IDs are
// deduplicated because the server can include the cursor item in two responses.
func queryFeedArchives(
	ctx context.Context,
	falconClient *client.CrowdStrikeAPISpecification,
	feedName string,
	feedInterval string,
	since time.Time,
) ([]*models.RestapiIndicatorFeedQueryItem, error) {
	seen := make(map[string]struct{})
	items := make([]*models.RestapiIndicatorFeedQueryItem, 0)
	cursor := since

	for {
		sinceValue := cursor.Format(time.RFC3339Nano)
		response, err := falconClient.IntelligenceFeeds.QueryFeedArchives(
			&intelligence_feeds.QueryFeedArchivesParams{
				Context:      ctx,
				FeedName:     feedName,
				FeedInterval: &feedInterval,
				Since:        &sinceValue,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("query feed archives since %s: %w", sinceValue, err)
		}
		if response.Payload == nil || len(response.Payload.Resources) == 0 {
			break
		}

		nextCursor := cursor
		newItems := 0
		for _, item := range response.Payload.Resources {
			if item == nil || item.FeedItemID == "" {
				continue
			}
			created, err := time.Parse(time.RFC3339Nano, item.CreatedTimestamp)
			if err != nil {
				return nil, fmt.Errorf("parse created timestamp for feed item %s: %w", item.FeedItemID, err)
			}
			if created.After(nextCursor) {
				nextCursor = created
			}
			if _, exists := seen[item.FeedItemID]; exists {
				continue
			}
			seen[item.FeedItemID] = struct{}{}
			items = append(items, item)
			newItems++
		}

		if newItems == 0 || !nextCursor.After(cursor) {
			break
		}
		cursor = nextCursor.Add(time.Nanosecond)
	}

	return items, nil
}

func downloadFeedArchives(
	ctx context.Context,
	falconClient *client.CrowdStrikeAPISpecification,
	capture *downloadURLCapture,
	downloader *http.Client,
	items []*models.RestapiIndicatorFeedQueryItem,
	outputDir string,
	concurrency int,
) error {
	semaphore := make(chan struct{}, concurrency)
	errorsCh := make(chan error, len(items))
	var workers sync.WaitGroup

	for _, item := range items {
		item := item
		workers.Add(1)
		go func() {
			defer workers.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := downloadFeedArchive(ctx, falconClient, capture, downloader, item.FeedItemID, outputDir); err != nil {
				errorsCh <- err
			}
		}()
	}

	workers.Wait()
	close(errorsCh)

	var downloadErrors []error
	for err := range errorsCh {
		downloadErrors = append(downloadErrors, err)
	}
	return errors.Join(downloadErrors...)
}

func downloadFeedArchive(
	ctx context.Context,
	falconClient *client.CrowdStrikeAPISpecification,
	capture *downloadURLCapture,
	downloader *http.Client,
	feedItemID string,
	outputDir string,
) error {
	err := falconClient.IntelligenceFeeds.DownloadFeedArchive(
		&intelligence_feeds.DownloadFeedArchiveParams{
			Context:    ctx,
			FeedItemID: feedItemID,
		},
	)

	location, captured := capture.take(feedItemID)
	if !captured {
		var redirect *intelligence_feeds.DownloadFeedArchivePermanentRedirect
		if errors.As(err, &redirect) && redirect.Location != "" {
			location = redirect.Location
			captured = true
		}
	}
	if !captured {
		return fmt.Errorf("request download URL for feed item %s: %w", feedItemID, err)
	}
	if err != nil && !errors.Is(err, errDownloadURLCaptured) {
		var redirect *intelligence_feeds.DownloadFeedArchivePermanentRedirect
		if !errors.As(err, &redirect) {
			return fmt.Errorf("request download URL for feed item %s: %w", feedItemID, err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return fmt.Errorf("create download request for feed item %s: %w", feedItemID, err)
	}
	resp, err := downloader.Do(req)
	if err != nil {
		return fmt.Errorf("download feed item %s: %w", feedItemID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download feed item %s: unexpected HTTP status %s", feedItemID, resp.Status)
	}

	temporary, err := os.CreateTemp(outputDir, ".feed-*.zip")
	if err != nil {
		return fmt.Errorf("create temporary file for feed item %s: %w", feedItemID, err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("set permissions for feed item %s: %w", feedItemID, err)
	}
	if _, err := io.Copy(temporary, resp.Body); err != nil {
		temporary.Close()
		return fmt.Errorf("write feed item %s: %w", feedItemID, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close feed item %s: %w", feedItemID, err)
	}

	destination := filepath.Join(outputDir, url.PathEscape(feedItemID)+".zip")
	if err := os.Rename(temporaryName, destination); err != nil {
		return fmt.Errorf("store feed item %s: %w", feedItemID, err)
	}
	fmt.Printf("Downloaded %s to %s\n", feedItemID, destination)
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
