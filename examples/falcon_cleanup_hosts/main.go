package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

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
	dryRun := flag.Bool("dry-run", true, "Dry run will not remove the devices from Falcon")
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

	hosts := getAllHostDetails(client, filter)
	if len(hosts) == 0 {
		fmt.Printf("No host found by filter: '%s'\n", *filter)
		return
	}

	fmt.Println("Following hosts will be removed:")
	for _, host := range hosts {
		visualizeHost(host)
	}
	fmt.Printf("\nTotal of %d hosts is scheduled to be removed.\n", len(hosts))
	userInput := falcon_util.PromptUser(`Please enter 'hide hosts' in capital letters to hide hosts in the falcon UI`)
	if userInput != "HIDE HOSTS" {
		fmt.Printf("Cancelling '%s' != 'HIDE HOSTS'\n", userInput)
		return
	}

	err = hideHosts(client, hosts, *dryRun)
	if err != nil {
		panic(err)
	}
}

func visualizeHost(host *models.DomainDeviceSwagger) {
	cloud := "NoCloud"
	if host.ServiceProvider != "" {
		cloud = host.ServiceProvider

		if host.ServiceProviderAccountID != "" || host.InstanceID != "" {
			if host.ServiceProviderAccountID != "" {
				cloud += "(account=" + host.ServiceProviderAccountID + ")"
			}

			if host.InstanceID != "" && host.ProductTypeDesc != "Pod" {
				cloud += "(instance_id=" + host.InstanceID + ")"
			}
		}
	}
	typ := "UNKNOWN TYPE"
	if host.ProductTypeDesc != "" {
		typ = host.ProductTypeDesc
	}
	platform := "UNKNOWN PLATFORM"
	if host.PlatformName != "" {
		platform = host.PlatformName

		if host.OsVersion != "" && host.OsVersion != "Linux" {
			platform += "(" + host.OsVersion + ")"
		}
	}

	name := "UNKNOWN NAME"
	switch typ {
	case "Pod":
		namespace := "UNKNOWN NAMESPACE"
		if host.PodNamespace != "" {
			namespace = host.PodNamespace
		}

		podname := "UNKNOWN PODNAME/" + host.Hostname
		if host.PodName != "" {
			podname = host.PodName
		}
		name = fmt.Sprintf("%s/%s", namespace, podname)
	case "Server":
		hostname := "UNKNOWN HOSTNAME"
		if host.Hostname != "" {
			hostname = host.Hostname
		}
		name = hostname
	case "Workstation":
		if host.Hostname != "" {
			name = host.Hostname
		}
		if host.SystemProductName != "" {
			name += " / " + host.SystemProductName
		}
	default:
		debug(host)
	}
	active := "active"
	lifeSpan := "unknown"
	layout := "2006-01-02T15:04:05Z"
	lastSeen, err := time.Parse(layout, host.LastSeen)
	if err == nil {
		inactiveDuration := time.Since(lastSeen)
		if inactiveDuration.Hours() > 48 {
			active = fmt.Sprintf("inactive for %d days", uint64(inactiveDuration.Hours()/24))
		}
		firstSeen, err := time.Parse(layout, host.FirstSeen)
		if err == nil {
			lifeDuration := lastSeen.Sub(firstSeen)

			if lifeDuration.Hours() < 0 {
				lifeSpan = lifeDuration.String()
			} else if lifeDuration.Hours() > 48 {
				lifeSpan = fmt.Sprintf("%ddays", uint64(lifeDuration.Hours()/24))
			} else {
				lifeSpan = lifeDuration.String()
			}
		}
	}

	fmt.Printf("%s - %s %s %s (%s) (life_span=%s) (%s) \n", *host.DeviceID, cloud, platform, typ, name, lifeSpan, active)
}

func debug(host *models.DomainDeviceSwagger) {
	json, err := falcon_util.PrettyJson(host)
	if err != nil {
		panic(err)
	}
	fmt.Println(json)
}

func hideHosts(client *client.CrowdStrikeAPISpecification, hosts []*models.DomainDeviceSwagger, dryRun bool) error {
	dryRunString := ""
	if dryRun {
		dryRunString = "(DRY-RUN) "
	}

	for _, hostChunk := range chunkBy(hosts, 25) {
		for _, host := range hostChunk {
			fmt.Printf("%sRemoving host:", dryRunString)
			visualizeHost(host)
		}
		if dryRun == false {
			err := hideHostsInternal(client, hostChunk)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func hideHostsInternal(client *client.CrowdStrikeAPISpecification, hostList []*models.DomainDeviceSwagger) error {
	hostIds := []string{}
	for _, host := range hostList {
		hostIds = append(hostIds, *host.DeviceID)

	}

	response, err := client.Hosts.PerformActionV2(&hosts.PerformActionV2Params{
		ActionName: "hide_host",
		Body: &models.MsaEntityActionRequestV2{
			Ids: hostIds,
		},
		Context: context.Background(),
	})
	if err != nil {
		return err
	}
	return falcon.AssertNoError(response.Payload.Errors)
}

func getAllHostDetails(client *client.CrowdStrikeAPISpecification, filter *string) []*models.DomainDeviceSwagger {
	result := []*models.DomainDeviceSwagger{}

	for hostIdBatch := range getHostIds(client, filter) {
		if len(hostIdBatch) == 0 {
			return result
		}
		result = append(result, getHostsDetails(client, hostIdBatch)...)
	}

	return result
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

func getHostIds(client *client.CrowdStrikeAPISpecification, filter *string) <-chan []string {
	hostIds := make(chan []string)

	go func() {
		limit := int64(500)
		for offset := int64(0); ; {
			response, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{
				Limit:   &limit,
				Offset:  &offset,
				Filter:  filter,
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

func chunkBy(items []*models.DomainDeviceSwagger, chunkSize int) (chunks [][]*models.DomainDeviceSwagger) {
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}

	return append(chunks, items)
}
