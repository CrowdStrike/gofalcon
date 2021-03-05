package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/event_streams"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/falcon/models/streaming_models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon clod abbreviation (us-1, us-2, eu-1, us-gov-1)")

	flag.Parse()

	if *clientId == "" {
		*clientId = promptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = promptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Cloud:        falcon.Cloud(*clientCloud),
		Context:      context.Background(),
	})
	if err != nil {
		panic(err)
	}

	json := "json"
	appId := "falcon_event_stream"
	// Step 1: Discover Available Streams
	response, err := client.EventStreams.ListAvailableStreamsOAuth2(&event_streams.ListAvailableStreamsOAuth2Params{
		AppID:   appId,
		Format:  &json,
		Context: context.Background(),
	})
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	for _, e := range response.Payload.Errors {
		fmt.Println(e)
	}

	availableStreams := response.Payload.Resources
	for _, stream := range availableStreams {
		ctx := context.Background()

		// Step 2: set-up side goroutine to maintain the token validity
		maintainStreamSession(ctx, client, appId, *stream.RefreshActiveSessionInterval)

		// Step 3: Open the stream
		for event := range streamEvents(ctx, stream) {
			pretty, err := falcon_util.PrettyJson(event)
			if err != nil {
				panic(err)
			}
			fmt.Println(pretty)
		}
	}
}

func promptUser(prompt string) string {
	fmt.Printf("%s: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	s, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(s)
}

func maintainStreamSession(ctx context.Context, client *client.CrowdStrikeAPISpecification, appId string, refreshActiveSessionInterval int64) {
	ticker := time.NewTicker(time.Duration(refreshActiveSessionInterval*9/10) * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, err := client.EventStreams.RefreshActiveStreamSession(&event_streams.RefreshActiveStreamSessionParams{
					AppID:      appId,
					ActionName: "refresh_active_stream_session",
					Partition:  0,
					Context:    ctx,
				})

				if err != nil {
					panic(falcon.ErrorExplain(err))
				}
			}
		}
	}()
}

func streamEvents(ctx context.Context, stream *models.MainAvailableStreamV2) <-chan *streaming_models.EventItem {
	out := make(chan *streaming_models.EventItem)

	req, err := http.NewRequestWithContext(ctx, "GET", *stream.DataFeedURL, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Add("Authorization", "Token "+*stream.SessionToken.Token)
	req.Header.Add("Connection", "Keep-Alive")
	req.Header.Add("Date", time.Now().Format(time.RFC1123Z))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	go func() {
		defer resp.Body.Close()

		dec := json.NewDecoder(resp.Body)
		for dec.More() {
			var detection streaming_models.EventItem
			//dec.DisallowUnknownFields()
			err := dec.Decode(&detection)
			if err != nil {
				panic(err)
			}
			out <- &detection
		}
		close(out)
	}()

	return out
}
