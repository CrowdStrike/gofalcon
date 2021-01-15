package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/incidents"
)

func main() {
	falconClientId := os.Getenv("FALCON_CLIENT_ID")
	falconClientSecret := os.Getenv("FALCON_CLIENT_SECRET")
	if falconClientId == "" {
		fmt.Printf("Please provide your Falcon Client ID: ")
		_, err := fmt.Scanln(&falconClientId)
		if err != nil {
			panic(err)
		}
	}
	if falconClientSecret == "" {
		fmt.Printf("Please provide your Falcon Client Secret: ")
		_, err := fmt.Scanln(&falconClientSecret)
		if err != nil {
			panic(err)
		}
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId: falconClientId,
		ClientSecret: falconClientSecret,
		Context: context.Background(),
	})
	if err != nil {
		panic(err)
	}

	desc := "timestamp.desc"
	res, err := client.Incidents.CrowdScore(&incidents.CrowdScoreParams{
		Context: context.Background(),
		Sort: &desc,
	})
	if err != nil {
		panic(err)
	}
	payload := res.GetPayload()
	fmt.Printf("As of %s your CrowdScore is %d.\n",
		payload.Resources[0].Timestamp.String(), *payload.Resources[0].Score)
}
