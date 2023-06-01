package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cspm_registration"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

var (
	clientId     = flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret = flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID    = flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	clientCloud  = flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
)

func main() {
	flag.Parse()

	if *clientId == "" {
		*clientId = falcon_util.PromptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		MemberCID:    *memberCID,
		Cloud:        falcon.Cloud(*clientCloud),
		Context:      context.Background(),
	})
	if err != nil {
		panic(err)
	}

	res, multiStatus, err := GetAWSAccounts(client)
	if err != nil {
		panic(err)
	}

	if res != nil {
		payload := res.GetPayload()

		for _, resource := range payload.Resources {
			fmt.Printf("AWS Account ID: %s Account Status: %s\n", resource.AccountID, resource.Status)
		}
	}

	if multiStatus != nil {
		payload := multiStatus.GetPayload()

		for _, resource := range payload.Resources {
			fmt.Println(resource.AccountID)
		}
	}
}

func GetAWSAccounts(client *client.CrowdStrikeAPISpecification) (*cspm_registration.GetCSPMAwsAccountOK, *cspm_registration.GetCSPMAwsAccountMultiStatus, error) {
	params := cspm_registration.NewGetCSPMAwsAccountParams().WithDefaults()

	res, multiStatus, err := client.CspmRegistration.GetCSPMAwsAccount(params)

	if err != nil {
		return nil, nil, err
	}

	if err := falcon.AssertNoError(res.GetPayload().Errors); err != nil {
		return nil, nil, err
	}

	if multiStatus != nil {
		if err := falcon.AssertNoError(multiStatus.GetPayload().Errors); err != nil {
			return nil, nil, err
		}
	}

	return res, multiStatus, err
}
