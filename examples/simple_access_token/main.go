package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	falconAccessToken := os.Getenv("FALCON_ACCESS_TOKEN")
	falconCloud := os.Getenv("FALCON_CLOUD")
	if falconAccessToken == "" {
		falconAccessToken = falcon_util.PromptUser(`Missing FALCON_ACCESS_TOKEN environment variable. Please provide your OAuth2 API Access Token for authentication with CrowdStrike Falcon platform`)
	}

	if falconCloud == "" {
		falconCloud = falcon_util.PromptUser(`Missing FALCON_CLOUD environment variable. Please provide your CrowdStrike Falcon cloud region (us-1, us-2, eu-1, us-gov-1, etc).`)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		AccessToken: falconAccessToken,
		Context:     context.Background(),
		Cloud:       falcon.Cloud(falconCloud),
	})
	if err != nil {
		panic(err)
	}

	limit := int64(10)
	res, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{
		Context: context.Background(),
		Limit:   &limit,
	})
	if err != nil {
		panic(err)
	}
	payload := res.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		panic(err)
	}
	fmt.Printf("Found %d host(s):\n", len(payload.Resources))
	for _, id := range payload.Resources {
		fmt.Println(" -", id)
	}
}
