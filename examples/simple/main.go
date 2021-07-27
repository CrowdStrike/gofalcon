package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/incidents"
)

func main() {
	falconClientId := os.Getenv("FALCON_CLIENT_ID")
	falconClientSecret := os.Getenv("FALCON_CLIENT_SECRET")
	clientCloud := os.Getenv("FALCON_CLOUD")
	if falconClientId == "" {
		falconClientId = promptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if falconClientSecret == "" {
		falconClientSecret = promptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
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

func promptUser(prompt string) string {
	fmt.Printf("%s: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	s, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(s)
}

type void struct{}
