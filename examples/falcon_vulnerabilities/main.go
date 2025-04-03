package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	filter := flag.String("filter", "", "Vulnerability search expression using Falcon Query Language (FQL)")
	sort := flag.String("sort", "", "Vulnerability sort expression using Falcon Query Language (FQL) ")
	flag.Parse()

	if *clientId == "" {
		*clientId = falcon_util.PromptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}
	for *filter == "" {
		*filter = falcon_util.PromptUser(`Missing --filter attribute. Please provide FQL (Falcon Query Language) expression for vulnerability search.
Examples:
    created_timestamp:>'2019-11-25T22:36:12Z'
    closed_timestamp:>'2019-11-25T22:36:12Z'
    aid:'abcde123456789a34a1af416424d6231'
    status:'open'
    cve.severity:'CRITICAL'
    cve.severity:'HIGH'+status:!'closed'
    last_seen_within:'10'
filter`)
		*filter = strings.TrimSpace(*filter)
	}
	if *sort == "" {
		sort = nil
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

	vulnerabilityBatches := queryVulnerabilities(client, *filter, sort)

	fmt.Println("[")
	empty := true
	for vulnBatch := range vulnerabilityBatches {
		for _, vuln := range vulnBatch {
			json, err := falcon_util.PrettyJson(vuln)
			if err != nil {
				panic(err)
			}
			if !empty {
				json = "," + json
			} else {
				empty = false
			}

			fmt.Printf("%s", json)
		}
	}
	fmt.Println("]")
}

func queryVulnerabilities(client *client.CrowdStrikeAPISpecification, filter string, sort *string) <-chan []*models.DomainBaseAPIVulnerabilityV2 {
	vulnsBatches := make(chan []*models.DomainBaseAPIVulnerabilityV2)

	go func() {
		lastSeen := (*string)(nil)
		for {
			response, err := client.SpotlightVulnerabilities.CombinedQueryVulnerabilities(
				&spotlight_vulnerabilities.CombinedQueryVulnerabilitiesParams{
					Context: context.Background(),
					Facet:   []string{"cve", "host_info", "remediation", "evaluation_logic"},
					Filter:  filter,
					Sort:    sort,
					After:   lastSeen,
				},
			)

			if err != nil {
				panic(falcon.ErrorExplain(err))
			}
			if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
				panic(err)
			}

			vulns := response.Payload.Resources
			if len(vulns) == 0 {
				break
			}

			vulnsBatches <- vulns

			if response.Payload.Meta == nil && response.Payload.Meta.Pagination == nil && response.Payload.Meta.Pagination.Limit == nil {
				panic("Cannot paginate Vulnerabilities, pagination information missing")
			}
			// Convert limit to int (the wider type) to avoid overflow
			if int(*response.Payload.Meta.Pagination.Limit) > len(vulns) {
				// We have got less items than what was the limit. Meaning, this is last batch, continuation is futile.
				break
			} else {
				lastSeen = response.Payload.Meta.Pagination.After
			}
		}
		close(vulnsBatches)
	}()

	return vulnsBatches
}
