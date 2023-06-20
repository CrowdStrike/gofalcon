package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/incidents"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	falconAccessToken := os.Getenv("FALCON_ACCESS_TOKEN")
	if falconAccessToken == "" {
		falconAccessToken = falcon_util.PromptUser(`Missing FALCON_ACCESS_TOKEN environment variable. Please provide your OAuth2 API Access Token for authentication with CrowdStrike Falcon platform`)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		AccessToken: falconAccessToken,
		Context:     context.Background(),
	})
	if err != nil {
		panic(err)
	}

	desc := "timestamp.desc"
	res, err := client.Incidents.CrowdScore(&incidents.CrowdScoreParams{
		Context: context.Background(),
		Sort:    &desc,
	})
	if err != nil {
		panic(err)
	}
	payload := res.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		panic(err)
	}
	fmt.Printf("As of %s your CrowdScore is %d.\n",
		payload.Resources[0].Timestamp.String(), *payload.Resources[0].Score)
}
