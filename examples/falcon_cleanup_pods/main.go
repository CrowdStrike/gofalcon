package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	inactiveDays := flag.Uint("inactive-days", 14, "Number of days for which the pod has been inactive (won't delete or recently active pods)")
	dryRun := flag.Bool("dry-run", false, "Dry run will not remove the devices from Falcon")

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

	podIds := getInactivePodIds(client, *inactiveDays)
	hideHosts(client, podIds, *dryRun)
}

func hideHosts(client *client.CrowdStrikeAPISpecification, podIds <-chan string, dryRun bool) {
	dryRunString := ""
	if dryRun {
		dryRunString = "(DRY-RUN) "
	}

	for podId := range podIds {
		details := getHostDetails(client, podId)
		fmt.Printf("%sRemoving pod %s (name=%s, inactive_since=%s)\n", dryRunString, podId, details.PodName, details.LastSeen)
		if dryRun == false {
			hideHost(client, podId)
		}
	}
}

func hideHost(client *client.CrowdStrikeAPISpecification, id string) error {
	response, err := client.Hosts.PerformActionV2(&hosts.PerformActionV2Params{
		ActionName: "hide_host",
		Body: &models.MsaEntityActionRequestV2{
			Ids: []string{id},
		},
		Context: context.Background(),
	})
	if err != nil {
		return err
	}
	return checkPayloadErrors(response.Payload.Errors)
}

// checkPayloadErrors converts MsaAPIError to golang error
func checkPayloadErrors(payloadErrors []*models.MsaAPIError) error {
	if len(payloadErrors) == 0 {
		return nil
	}
	var sb strings.Builder

	for _, payloadError := range payloadErrors {
		sb.WriteString("API Error " + payloadError.ID + ": " + *payloadError.Message)
	}
	return errors.New(sb.String())
}

func getHostDetails(client *client.CrowdStrikeAPISpecification, hostId string) *models.DomainDeviceSwagger {
	response, err := client.Hosts.GetDeviceDetails(&hosts.GetDeviceDetailsParams{
		Ids:     []string{hostId},
		Context: context.Background(),
	})
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	for _, e := range response.Payload.Errors {
		fmt.Println(e)
		panic("Error received when querying Host Details API")
	}

	return response.Payload.Resources[0]
}

func getInactivePodIds(client *client.CrowdStrikeAPISpecification, inactiveDays uint) <-chan string {
	hostIds := make(chan string)

	go func() {
		cutOffDate := time.Now().AddDate(0, 0, -1*int(inactiveDays)).Format("2006-01-02")
		filter := fmt.Sprintf("product_type_desc:'Pod'+last_seen:<'%s'", cutOffDate)
		fmt.Printf("Querying Pods that has not been active since %s\n", cutOffDate)

		one := int64(1)
		response, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{
			Filter:  &filter,
			Limit:   &one,
			Context: context.Background(),
		})
		if err != nil {
			panic(falcon.ErrorExplain(err))
		}
		for _, e := range response.Payload.Errors {
			fmt.Println(e)
			panic("Error received when querying Hosts API")
		}
		podCount := *response.Payload.Meta.Pagination.Total
		fmt.Printf("Found %d pods that have been inactive\n", podCount)

		limit := int64(100)
		for offset := int64(0); ; {
			response, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{
				Filter:  &filter,
				Limit:   &limit,
				Offset:  &offset,
				Context: context.Background(),
			})
			if err != nil {
				panic(falcon.ErrorExplain(err))
			}
			for _, e := range response.Payload.Errors {
				fmt.Println(e)
				panic("Error received when querying Hosts API")
			}

			hosts := response.Payload.Resources
			for _, host := range hosts {
				hostIds <- host
			}
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
