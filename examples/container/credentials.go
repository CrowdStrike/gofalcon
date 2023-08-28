package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/crowdstrike/gofalcon/examples"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container"
)

func main() {
	commonAuthFlags := examples.SetupAuthFlags()

	flag.Parse()
	commonAuthFlags.PromptForRequiredFlags()

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     commonAuthFlags.ClientId,
		ClientSecret: commonAuthFlags.ClientSecret,
		MemberCID:    commonAuthFlags.MemberCID,
		Cloud:        falcon.Cloud(commonAuthFlags.Cloud),
		Context:      context.Background(),
	})

	examples.HandleError(err)

	res, err := client.FalconContainer.GetCredentials(&falcon_container.GetCredentialsParams{
		Context: context.Background(),
	})

	examples.HandleError(err)

	fmt.Printf("Falcon Container Token: %s\n", *res.GetPayload().Resources[0].Token)
}
