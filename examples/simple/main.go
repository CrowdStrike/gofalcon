package main

import (
	"os"
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"golang.org/x/oauth2/clientcredentials"
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

	config := clientcredentials.Config{
		ClientID: falconClientId,
		ClientSecret: falconClientSecret,
		TokenURL: "https://" + client.DefaultHost + "/oauth2/token",
	}
	authenticatedClient := config.Client(context.Background())

	customTransport := httptransport.NewWithClient(
		client.DefaultHost, client.DefaultBasePath, []string{}, authenticatedClient)

	apiKeyHeaderAuth := httptransport.APIKeyAuth("X-API-TOKEN", "header", "THIS-SHALL-BE-REMOVED")
	apiclient := client.New(customTransport, strfmt.Default)
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
