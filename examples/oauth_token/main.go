package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
	"golang.org/x/oauth2/clientcredentials"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	flag.Parse()

	if *clientId == "" {
		*clientId = falcon_util.PromptUser("Please provide your Falcon Client ID")
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser("Please provide your Falcon Client Secret")
	}

	config := clientcredentials.Config{
		ClientID:     *clientId,
		ClientSecret: *clientSecret,
		TokenURL:     "https://" + falcon.Cloud(*clientCloud).Host() + "/oauth2/token",
	}
	token, err := config.Token(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(token.AccessToken)
}
