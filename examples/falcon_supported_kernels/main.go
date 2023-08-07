package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	distro := flag.String("distro", "", "Name of Linux distribution")
	arch := flag.String("arch", "", "Name of architecture supported by distribution")

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
		Debug:        false,
	})
	if err != nil {
		panic(err)
	}

	if *distro == "" {
		validDistroNames := getValidDistroNames(client)
		fmt.Printf("Missing --distro command-line option. Available distributions are: [%s]\n", strings.Join(validDistroNames, ", "))
		*distro = falcon_util.PromptUser("Selected distro")
	}
	if *arch == "" {
		validArchNames := getValidArchNames(client, *distro)
		switch len(validArchNames) {
		case 0:
			panic(fmt.Sprintf("Invalid distro selected: '%s', valid options are: [%s]", *distro, strings.Join(getValidDistroNames(client), ", ")))
		case 1:
			*arch = validArchNames[0]
		default:
			fmt.Printf("Missing --arch command-line option. Available architectures are: [%s]\n", strings.Join(validArchNames, ", "))
			*arch = falcon_util.PromptUser("Selected architecture")
		}
	}

	filter := fmt.Sprintf("distro:'%s'+architecture:'%s'", *distro, *arch)

	list := []string{}
	for _, kernel := range query(client, filter) {
		list = append(list, *kernel.Release)
	}
	pretty, err := falcon_util.PrettyJson(list)
	if err != nil {
		panic(err)
	}
	fmt.Println(pretty)
}

func getValidArchNames(client *client.CrowdStrikeAPISpecification, distro string) []string {
	archs := make(map[string]void)
	for _, kernel := range query(client, fmt.Sprintf("distro:'%s'", distro)) {
		archs[*kernel.Architecture] = void{}
	}
	list := []string{}
	for k := range archs {
		list = append(list, k)
	}
	sort.Strings(list)
	return list
}

func getValidDistroNames(client *client.CrowdStrikeAPISpecification) []string {
	distros := make(map[string]void)
	for _, kernel := range query(client, "") {
		distros[*kernel.Distro] = void{}
	}
	list := []string{}
	for k := range distros {
		list = append(list, k)
	}
	sort.Strings(list)
	return list
}

func query(client *client.CrowdStrikeAPISpecification, filter string) []*models.SensorUpdateKernelRespV1 {
	limit := int64(100)
	response, err := client.SensorUpdatePolicies.QueryCombinedSensorUpdateKernels(&sensor_update_policies.QueryCombinedSensorUpdateKernelsParams{
		Filter:  &filter,
		Limit:   &limit,
		Context: context.Background(),
	})
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	payload := response.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		panic(err)
	}
	return response.Payload.Resources
}

type void struct{}
