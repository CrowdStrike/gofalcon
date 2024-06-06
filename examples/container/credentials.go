package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/aslape/gofalcon/examples"
	"github.com/aslape/gofalcon/falcon"
	"github.com/aslape/gofalcon/falcon/client/falcon_container"
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
