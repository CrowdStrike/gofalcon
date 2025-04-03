package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cspm_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
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

	ioms, err := GetIOMs(client)
	if err != nil {
		panic(err)
	}

	json, err := falcon_util.PrettyJson(ioms)
	if err != nil {
		panic(err)
	}
	fmt.Println(json)
}

func GetIOMs(client *client.CrowdStrikeAPISpecification) (ioms []models.RegistrationIOMEvent, err error) {
	limit := 200

	for nextToken := ""; ; {
		params := cspm_registration.NewGetConfigurationDetectionsParams().WithDefaults()
		params.NextToken = &nextToken

		res, err := client.CspmRegistration.GetConfigurationDetections(params)
		if err != nil {
			return ioms, err
		}
		if err = falcon.AssertNoError(res.GetPayload().Errors); err != nil {
			return ioms, err
		}

		events := res.GetPayload().Resources.Events
		if len(events) == 0 {
			break
		}

		for _, iom := range events {
			ioms = append(ioms, *iom)
		}

		if len(events) < limit {
			break // received last page as results are less than the limit
		}

		if res.Payload.Meta == nil && res.Payload.Meta.Pagination == nil && res.Payload.Meta.Pagination.NextToken == "" {
			return ioms, errors.New("cannot paginate IOMs, pagination information missing")
		}

		nextToken = res.Payload.Meta.Pagination.NextToken
	}

	return ioms, err
}
