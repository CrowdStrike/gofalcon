package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"

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
	filter := flag.String("filter", "", "Host search expression using Falcon Query Language (FQL)")
	thresholdString := flag.String("rate-limit-threshold", os.Getenv("FALCON_RATE_LIMIT_THRESHOLD"), "Minimum remaining requests before taking further action (default taken from FALCON_RATE_LIMIT_THRESHOLD)")

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
	if *thresholdString == "" {
		*thresholdString = "100"
	}

	threshold, err := strconv.ParseInt(*thresholdString, 10, 64)
	if err != nil {
		panic(err)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:           *clientId,
		ClientSecret:       *clientSecret,
		MemberCID:          *memberCID,
		Cloud:              falcon.Cloud(*clientCloud),
		Context:            context.Background(),
		TransportDecorator: newRateLimitingInspectingTransportDecorator(threshold),
	})
	if err != nil {
		panic(err)
	}

	empty := true
	firstIteration := true
	for hostIdBatch := range getHostIds(client, filter) {
		if len(hostIdBatch) == 0 {
			continue
		}
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
			if firstIteration {
				fmt.Println("[")
				firstIteration = false
			}
			fmt.Println(json)
		}
	}
	fmt.Println("]")
}

func getHostsDetails(client *client.CrowdStrikeAPISpecification, hostIds []string) []*models.DeviceapiDeviceSwagger {
	response, err := client.Hosts.PostDeviceDetailsV2(&hosts.PostDeviceDetailsV2Params{
		Body:    &models.MsaIdsRequest{Ids: hostIds},
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
		limit := int64(5000)
		for offset := ""; ; {
			response, err := client.Hosts.QueryDevicesByFilterScroll(&hosts.QueryDevicesByFilterScrollParams{
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

			if *response.Payload.Meta.Pagination.Offset == "" || int64(len(hosts)) < limit {
				break // no more next page indicates we are done
			}

			offset = *response.Payload.Meta.Pagination.Offset
		}
		close(hostIds)
	}()
	return hostIds
}

// rateLimitInspectingTransport provides information about the number of requests remaining in the ratelimit window.
type rateLimitInspectingTransport struct {
	wrapped   http.RoundTripper
	threshold int64
	remaining int64
}

// newRateLimitingInspectingTransportDecorator returns a falcon.TransportDecorator that
// when invoked returns a configured rateLimitInspectingTransport around the given transport.
func newRateLimitingInspectingTransportDecorator(threshold int64) func(http.RoundTripper) http.RoundTripper {
	return func(wrapped http.RoundTripper) http.RoundTripper {
		return &rateLimitInspectingTransport{wrapped: wrapped, threshold: threshold, remaining: -1}
	}
}

// RoundTrip decorates the behavior of the wrapped transport with support for Falcon API rate limiting.
func (t *rateLimitInspectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.remaining != -1 {
		fmt.Printf("Remaining calls: %d. Threshold: %d.\n", t.remaining, t.threshold)
		if t.remaining <= t.threshold {
			fmt.Println("Remaining call threshold reached. Consider a delay and/or retry with backoff.")
		}
	}

	response, err := t.wrapped.RoundTrip(req)
	if response != nil {
		remaining, err := strconv.ParseInt(response.Header.Get("X-Ratelimit-Remaining"), 10, 64)
		if err == nil {
			t.remaining = remaining
		}
	}

	return response, err
}
