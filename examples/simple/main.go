package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	httptransport "github.com/go-openapi/runtime/client"
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

	apiclient, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId: falconClientId,
		ClientSecret: falconClientSecret,
		Context: context.Background(),
	})
	if err != nil {
		panic(err)
	}

	apiKeyHeaderAuth := httptransport.APIKeyAuth("X-API-TOKEN", "header", "THIS-SHALL-BE-REMOVED")
	res, err := apiclient.SensorDownload.GetCombinedSensorInstallersByQuery(&sensor_download.GetCombinedSensorInstallersByQueryParams{Context: context.Background()}, apiKeyHeaderAuth)
	if err != nil {
		panic(err)
	}
	payload := res.GetPayload()
	for _, res := range payload.Resources {
		fmt.Println(*res.Description)
	}
	fmt.Printf("Found %d sensors available for download.\n", len(payload.Resources))
}
