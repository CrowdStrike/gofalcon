package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/detects"
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

	for d := range streamDetections(client) {
		json, err := falcon_util.PrettyJson(d)
		if err != nil {
			panic(err)
		}
		fmt.Println("# ---------------------------- ")
		fmt.Println(json)
	}
}

func streamDetections(c *client.CrowdStrikeAPISpecification) <-chan *models.DomainAPIDetectionDocument {
	out := make(chan *models.DomainAPIDetectionDocument)
	ticker := time.NewTicker(90 * time.Second)

	go func() {
		defer ticker.Stop()
		seen := map[string]void{}
		latestFirst := "last_behavior|desc"

		for ; true; <-ticker.C {
			response, err := c.Detects.QueryDetects(&detects.QueryDetectsParams{
				Sort:    &latestFirst,
				Context: context.Background(),
			})
			if err != nil {
				panic(falcon.ErrorExplain(err))
			}
			if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
				panic(err)
			}
			unseen := []string{}
			for _, d := range response.Payload.Resources {
				if _, ok := seen[d]; !ok {
					// New Detection ID
					unseen = append(unseen, d)
				}
			}

			if len(unseen) > 0 {
				response, err := c.Detects.GetDetectSummaries(&detects.GetDetectSummariesParams{
					Body:    &models.MsaIdsRequest{Ids: unseen},
					Context: context.Background(),
				})
				if err != nil {
					panic(falcon.ErrorExplain(err))
				}
				if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
					panic(err)
				}

				res := response.Payload.Resources

				sort.SliceStable(res, func(i, j int) bool {
					return time.Time(*res[i].CreatedTimestamp).Before(
						time.Time(*res[j].CreatedTimestamp))
				})

				for _, d := range res {
					seen[*d.DetectionID] = void{}
					out <- d
				}
			}
		}
		close(out)
	}()

	return out
}

type void struct{}
