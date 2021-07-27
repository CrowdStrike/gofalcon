package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")

	flag.Parse()

	if *clientId == "" {
		*clientId = promptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = promptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
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

	fmt.Println("[")
	empty := true
	for hostIdBatch := range getHostIds(client) {
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

func HostDetails(client *client.CrowdStrikeAPISpecification) []*models.DomainDeviceSwagger {
	return nil
}

func getHostsDetails(client *client.CrowdStrikeAPISpecification, hostIds []string) []*models.DomainDeviceSwagger {
	response, err := client.Hosts.GetDeviceDetails(&hosts.GetDeviceDetailsParams{
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

func getHostIds(client *client.CrowdStrikeAPISpecification) <-chan []string {
	hostIds := make(chan []string)

	go func() {
		limit := int64(100)
		for offset := int64(0); ; {
			response, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{
				Limit:   &limit,
				Offset:  &offset,
				Context: context.Background(),
			})
			if err != nil {
				panic(falcon.ErrorExplain(err))
			}
			if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
				panic(err)
			}

			hosts := response.Payload.Resources
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

func promptUser(prompt string) string {
	fmt.Printf("%s: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	s, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(s)
}
