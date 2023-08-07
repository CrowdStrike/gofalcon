package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	falconClientId := os.Getenv("FALCON_CLIENT_ID")
	falconClientSecret := os.Getenv("FALCON_CLIENT_SECRET")
	clientCloud := os.Getenv("FALCON_CLOUD")
	if falconClientId == "" {
		falconClientId = falcon_util.PromptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if falconClientSecret == "" {
		falconClientSecret = falcon_util.PromptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     falconClientId,
		ClientSecret: falconClientSecret,
		Cloud:        falcon.Cloud(clientCloud),
		Context:      context.Background(),
	})
	if err != nil {
		panic(err)
	}

	res, err := client.FalconContainer.GetCredentials(&falcon_container.GetCredentialsParams{
		Context: context.Background(),
	})
	if err != nil {
		panic(err)
	}
	payload := res.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		traceId := ""
		if payload.Meta != nil && payload.Meta.TraceID != nil {
			traceId = *payload.Meta.TraceID
		}
		fmt.Fprintf(os.Stderr, "WARNING: %v (trace_id=%s)", err, traceId)
	}
	resources := payload.Resources
	if len(resources) != 1 {
		fmt.Fprintf(os.Stderr, "Expected to receive exactly one token, but got %d\n", len(resources))
		panic("Unexpected response")
	}
	fmt.Printf("%s\n", *resources[0].Token)
}
