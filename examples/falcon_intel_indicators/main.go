package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	filter := flag.String("filter", "", "Indicators filter expression using Falcon Query Language (FQL)")
	sort := flag.String("sort", "", "Indicators sort expression using Falcon Query Language (FQL) ")
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
		*filter = falcon_util.PromptUser(`Missing --filter attribute. Please provide FQL (Falcon Query Language) expression for Intelligence Indicators search.
filter`)
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

	fmt.Println("[")
	empty := true
	indicatorsChannel, errorChannel := queryIntelIndicators(client, filter, sort)
	for openChannels := 2; openChannels > 0; {
		select {
		case err, ok := <-errorChannel:
			if ok {
				panic(err)
			} else {
				openChannels--
			}
		case indicator, ok := <-indicatorsChannel:
			if ok {
				prettyJson, err := falcon_util.PrettyJson(indicator)
				if err != nil {
					panic(err)
				}
				if !empty {
					fmt.Println(",")
				} else {
					empty = false
				}
				fmt.Printf("%s", prettyJson)
			} else {
				openChannels--

			}
		}
	}
	fmt.Println("]")
}

func queryIntelIndicators(client *client.CrowdStrikeAPISpecification, filter, sort *string) (<-chan *models.DomainPublicIndicatorV3, <-chan error) {
	indicatorsChannel := make(chan *models.DomainPublicIndicatorV3)
	errorChannel := make(chan error)

	go func() {
		limit := int64(1000)
		var err error

		for response := (*intel.QueryIntelIndicatorEntitiesOK)(nil); response.HasNextPage(); {
			response, err = client.Intel.QueryIntelIndicatorEntities(&intel.QueryIntelIndicatorEntitiesParams{
				Context: context.Background(),
				Filter:  filter,
				Sort:    sort,
				Limit:   &limit,
			},
				response.Paginate(),
			)
			if err != nil {
				errorChannel <- err
			}
			if response == nil || response.Payload == nil {
				break
			}

			if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
				errorChannel <- err
			}

			indicators := response.Payload.Resources
			for _, indicator := range indicators {
				indicatorsChannel <- indicator
			}
		}
		close(indicatorsChannel)
		close(errorChannel)
	}()
	return indicatorsChannel, errorChannel
}
