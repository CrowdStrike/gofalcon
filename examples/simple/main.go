package main

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon"
)

func main() {
	client, err := falcon.NewApiClient(context.Background(), &falcon.ApiConfig{
		ClientId: falconClientId,
		ClientSecret: falconClientSecret,
	})
	if err != nil {
		panic(err)
	}
	_ = client
}
