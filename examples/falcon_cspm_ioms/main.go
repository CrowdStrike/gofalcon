package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_detections"
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

func GetIOMs(client *client.CrowdStrikeAPISpecification) (ioms []*models.EvaluationsEvaluation, err error) {
	limit := int64(500)

	for after := ""; ; {
		queryParams := cloud_security_detections.NewCspmEvaluationsIomQueriesParams()
		queryParams.Limit = &limit
		if after != "" {
			queryParams.After = &after
		}

		queryRes, err := client.CloudSecurityDetections.CspmEvaluationsIomQueries(queryParams)
		if err != nil {
			return ioms, err
		}
		if err = falcon.AssertNoError(queryRes.GetPayload().Errors); err != nil {
			return ioms, err
		}

		ids := queryRes.GetPayload().Resources
		if len(ids) == 0 {
			break
		}

		entityParams := cloud_security_detections.NewCspmEvaluationsIomEntitiesPostParams()
		entityParams.Body = &models.EvaluationsGetIOMsRequest{Ids: ids}

		entityRes, err := client.CloudSecurityDetections.CspmEvaluationsIomEntitiesPost(entityParams)
		if err != nil {
			return ioms, err
		}
		if err = falcon.AssertNoError(entityRes.GetPayload().Errors); err != nil {
			return ioms, err
		}

		ioms = append(ioms, entityRes.GetPayload().Resources...)

		meta := queryRes.GetPayload().Meta
		if meta == nil || meta.Next == "" {
			break // no further pages available
		}

		after = meta.Next
	}

	return ioms, err
}
