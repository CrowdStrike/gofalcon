package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/event_streams"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String(
		"client-id",
		os.Getenv("FALCON_CLIENT_ID"),
		"Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)",
	)
	clientSecret := flag.String(
		"client-secret",
		os.Getenv("FALCON_CLIENT_SECRET"),
		"Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)",
	)
	memberCID := flag.String(
		"member-cid",
		os.Getenv("FALCON_MEMBER_CID"),
		"Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)",
	)
	clientCloud := flag.String(
		"cloud",
		os.Getenv("FALCON_CLOUD"),
		"Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)",
	)
	appName := flag.String(
		"app-name",
		"falcon_event_stream",
		"Application name (needs to be unique in your Falcon environment)",
	)

	flag.Parse()

	if *clientId == "" {
		*clientId = falcon_util.PromptUser(
			`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`,
		)
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser(
			`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`,
		)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		MemberCID:    *memberCID,
		Cloud:        falcon.Cloud(*clientCloud),
		Context:      context.Background(),
	})
	if err != nil {
		panic(err)
	}

	json := "json"
	// Step 1: Discover Available Streams
	response, err := client.EventStreams.ListAvailableStreamsOAuth2(
		&event_streams.ListAvailableStreamsOAuth2Params{
			AppID:   *appName,
			Format:  &json,
			Context: context.Background(),
		},
	)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		panic(err)
	}

	availableStreams := response.Payload.Resources
	if len(availableStreams) == 0 {
		fmt.Printf(
			"No available stream was found. This may be caused by second instance of this application already running in your environment with ID=%s, or by missing streaming api capability\n",
			*appName,
		)
	}
	for _, availableStream := range availableStreams {
		stream, err := falcon.NewStream(context.Background(), client, *appName, availableStream, 0)
		if err != nil {
			panic(err)
		}
		defer stream.Close()

		var fatal error
		for fatal == nil {
			select {
			case err := <-stream.Errors:
				if err.Fatal {
					fatal = err.Err
				} else {
					fmt.Fprintln(os.Stderr, err)
				}
			case event := <-stream.Events:
				pretty, err := falcon_util.PrettyJson(event)
				if err != nil {
					panic(err)
				}
				fmt.Println(pretty)
				fmt.Println(event.Metadata.EventType)
			}
		}
		panic(fatal)
	}
}
