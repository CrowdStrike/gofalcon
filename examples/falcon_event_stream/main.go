package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

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

	// Ctrl-C cancels ctx, which ends the stream like Close does. From Go 1.26
	// on, NotifyContext gives that cancel a cause, which the final error then
	// wraps.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

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
			Context: ctx,
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
		return
	}
	// Step 2: Read the first stream until it ends. A listed stream must be
	// connected before its sessionToken.expiration, minutes after listing, so
	// a program reading several streams connects to all of them at once.
	stream, err := falcon.NewStream(ctx, client, *appName, availableStreams[0], 0)
	if err != nil {
		panic(err)
	}
	err = printEvents(stream)
	stream.Close()
	fmt.Fprintln(os.Stderr, err)
	if code := exitCode(err, ctx.Err() != nil); code != 0 {
		stop()
		os.Exit(code)
	}
}

// exitCode is the status to exit with once the stream has ended with err: 0
// when the data feed simply ended or Ctrl-C asked to stop, and 1 otherwise.
func exitCode(err error, interrupted bool) int {
	// The final error is ErrStreamClosed itself when the stream ended with
	// nothing to report.
	if err == falcon.ErrStreamClosed || interrupted {
		return 0
	}
	return 1
}

// printEvents prints the events of stream, and the errors that do not end it,
// until it ends, and returns the error that ended it.
func printEvents(stream *falcon.StreamingHandle) error {
	for {
		select {
		case err := <-stream.Errors:
			if err.Fatal {
				return err.Err
			}
			fmt.Fprintln(os.Stderr, err)
		case event, ok := <-stream.Events:
			if !ok {
				// Events closes as the stream ends, and the error that
				// ended it is then waiting in Errors.
				return (<-stream.Errors).Err
			}
			pretty, err := falcon_util.PrettyJson(event)
			if err != nil {
				return err
			}
			fmt.Println(pretty)
			fmt.Println(event.Metadata.EventType)
		}
	}
}
