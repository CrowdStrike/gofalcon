package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/client/zero_trust_assessment"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	cloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	filter := flag.String("filter", "", "Host search expression using Falcon Query Language (FQL)")
	statistics := flag.Bool("statistics", false, "Output statistics across all hosts")
	flag.Parse()

	if *filter == "" {
		filter = nil
	}

	if *statistics && filter != nil {
		panic("Cannot output statistics for a given filter. Please remove filter to see statistics for whole CID")
	}

	if *clientId == "" {
		*clientId = falcon_util.PromptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}

	ctx := context.Background()

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Cloud:        falcon.Cloud(*cloud),
		Context:      ctx,
		MemberCID:    *memberCID,
	})
	if err != nil {
		panic(err)
	}
	if *statistics {
		response, err := client.ZeroTrustAssessment.GetAssessmentV1(&zero_trust_assessment.GetAssessmentV1Params{
			Context: ctx,
		})
		if err != nil {
			panic(falcon.ErrorExplain(err))
		}
		payload := response.GetPayload()
		if err = falcon.AssertNoError(payload.Errors); err != nil {
			panic(err)
		}

		json, err := falcon_util.PrettyJson(payload.Resources)
		if err != nil {
			panic(err)
		}
		fmt.Println(json)
	} else {
		fmt.Println("[")
		empty := true
		for hostZta := range zta(ctx, client, filter) {
			json, err := falcon_util.PrettyJson(hostZta)
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
		fmt.Println("]")
	}
}

func zta(ctx context.Context, client *client.CrowdStrikeAPISpecification, filter *string) <-chan *models.DomainSignalProperties {
	ztaChannel := make(chan *models.DomainSignalProperties)

	go func() {
		for hostIdsBatch := range getHostIds(ctx, client, filter) {
			if len(hostIdsBatch) == 0 {
				continue
			}

			ztaBatch, err := getHostsZta(ctx, client, hostIdsBatch)
			if err != nil {
				panic(err)
			}
			for _, zta := range ztaBatch {
				ztaChannel <- zta
			}
		}
		close(ztaChannel)
	}()
	return ztaChannel
}

func getHostsZta(ctx context.Context, client *client.CrowdStrikeAPISpecification, hostIds []string) ([]*models.DomainSignalProperties, error) {
	response, err := client.ZeroTrustAssessment.GetAssessmentV1(&zero_trust_assessment.GetAssessmentV1Params{
		Context: ctx,
		Ids:     hostIds,
	})
	if err != nil {
		return nil, err
	}
	payload := response.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		return nil, err
	}
	return payload.Resources, nil

}

func getHostIds(ctx context.Context, client *client.CrowdStrikeAPISpecification, filter *string) <-chan []string {
	hostIds := make(chan []string)

	go func() {
		limit := int64(500)
		for offset := ""; ; {
			response, err := client.Hosts.QueryDevicesByFilterScroll(&hosts.QueryDevicesByFilterScrollParams{
				Context: ctx,
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

			hosts := response.Payload.Resources
			if len(hosts) == 0 {
				break
			}

			hostIds <- hosts

			if *response.Payload.Meta.Pagination.Offset == "" {
				break // no more next page indicates we are done
			}

			offset = *response.Payload.Meta.Pagination.Offset
		}
		close(hostIds)
	}()
	return hostIds
}
