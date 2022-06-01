package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	filter := flag.String("filter", "", "Custom IOAs search expression using Falcon Query Language (FQL)")

	flag.Parse()

	if *clientId == "" {
		*clientId = falcon_util.PromptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}
	if *filter == "" {
		filter = nil
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

	fmt.Println("[")
	empty := true
	for ruleGroupIdBatch := range getIoaRuleGroupIds(client, filter) {
		if len(ruleGroupIdBatch) == 0 {
			continue
		}
		ioaDetailBatch := getIoaRuleGroupDetails(client, ruleGroupIdBatch)
		for _, ioa := range ioaDetailBatch {
			json, err := falcon_util.PrettyJson(ioa)
			if err != nil {
				panic(err)
			}
			if !empty {
				json = "," + json
			} else {
				empty = false
			}

			fmt.Println(json)
		}
	}
	fmt.Println("]")
}

func getIoaRuleGroupDetails(client *client.CrowdStrikeAPISpecification, ruleGroupIds []string) []*models.APIRuleGroupV1 {
	response, err := client.CustomIoa.GetRuleGroupsMixin0(&custom_ioa.GetRuleGroupsMixin0Params{
		Ids:     ruleGroupIds,
		Context: context.Background(),
	})
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		panic(err)
	}

	return response.Payload.Resources
}

func getIoaRuleGroupIds(client *client.CrowdStrikeAPISpecification, filter *string) <-chan []string {
	ruleGroupsChan := make(chan []string)

	go func() {
		limit := int64(500)
		for offset := ""; ; {
			response, err := client.CustomIoa.QueryRuleGroupsMixin0(&custom_ioa.QueryRuleGroupsMixin0Params{
				Context: context.Background(),
				Limit:   &limit,
				Offset:  &offset,
				Filter:  filter,
			})
			if err != nil {
				panic(falcon.ErrorExplain(err))
			}
			if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
				panic(err)
			}

			ruleGroupIds := response.Payload.Resources
			if len(ruleGroupIds) == 0 {
				break
			}

			ruleGroupsChan <- ruleGroupIds

			if response.Payload.Meta.Pagination.Offset == nil || int64(*response.Payload.Meta.Pagination.Offset) > *response.Payload.Meta.Pagination.Total {
				break // no more next page indicates we are done
			}

			offset = fmt.Sprintf("%d", *response.Payload.Meta.Pagination.Offset)
		}
		close(ruleGroupsChan)
	}()
	return ruleGroupsChan
}
