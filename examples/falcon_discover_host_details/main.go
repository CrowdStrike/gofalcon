package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/discover"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	filter := flag.String("filter", "", "Host search expression using Falcon Query Language (FQL)")

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
	for hostIdBatch := range getHostIds(client, filter) {
		hostDetailBatch := getHostsDetails(client, hostIdBatch)
		for _, host := range hostDetailBatch {
			json, err := falcon_util.PrettyJson(host)
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

func getHostsDetails(client *client.CrowdStrikeAPISpecification, hostIds []string) []*models.DomainDiscoverAPIHost {
	response, err := client.Discover.GetHosts(&discover.GetHostsParams{
		Ids:     hostIds,
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

func getHostIds(client *client.CrowdStrikeAPISpecification, filter *string) <-chan []string {
	hostIds := make(chan []string)

	go func() {
		limit := int64(100)
		for offset := int64(0); ; {
			response, err := client.Discover.QueryHosts(&discover.QueryHostsParams{
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

			hosts := response.Payload.Resources
			if len(hosts) == 0 {
				break
			}
			hostIds <- hosts
			offset = offset + int64(len(hosts))
			if offset >= *response.Payload.Meta.Pagination.Total {
				break
			}
		}
		close(hostIds)
	}()
	return hostIds
}
