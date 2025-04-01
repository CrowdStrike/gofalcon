package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/go-openapi/strfmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

// getCrowdstrikeIOCs returns a list of all the Custom IOC values in the system.
func getCrowdstrikeIOCs(client *client.CrowdStrikeAPISpecification) ([]string, error) {
	iocs := []string{}
	var limit, offset, total int64
	limit = 2000
	offset = 0
	total = 0

	for offset <= total {
		params := ioc.NewIndicatorCombinedV1Params().WithDefaults()
		params.SetOffset(&offset)
		params.SetLimit(&limit)
		res, err := client.Ioc.IndicatorCombinedV1(params)
		if err != nil {
			return []string{}, err
		}
		if err = falcon.AssertNoError(res.GetPayload().Errors); err != nil {
			return []string{}, err
		}

		for _, ioc := range res.GetPayload().Resources {
			iocs = append(iocs, ioc.Value)
		}

		total = *res.GetPayload().Meta.Pagination.Total
		offset += limit
	}

	return iocs, nil
}

// getIOCType returns the IOC type as supported by crowdstrike (domain, ipv4, ipv6, md5, sha256).
func getIOCType(iocStr string) (string, error) {
	var RegexIPv4 = regexp.MustCompile(`^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$`)
	var RegexIPv6 = regexp.MustCompile(`(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`)
	var RegexURL = regexp.MustCompile(`^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)$`)
	var RegexDomain = regexp.MustCompile(`(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})`)
	var RegexEmail = regexp.MustCompile(`^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$`)
	var RegexMD5 = regexp.MustCompile(`^[a-f0-9]{32}$`)
	var RegexSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)

	switch {
	case RegexEmail.MatchString(iocStr):
		return "", errors.New("email is an unsupported IOC type")
	case RegexURL.MatchString(iocStr):
		return "", errors.New("URLs are an unsupported IOC type")
	case RegexDomain.MatchString(iocStr):
		return "domain", nil
	case RegexIPv4.MatchString(iocStr):
		return "ipv4", nil
	case RegexIPv6.MatchString(iocStr):
		return "ipv6", nil
	case RegexMD5.MatchString(iocStr):
		return "md5", nil
	case RegexSHA256.MatchString(iocStr):
		return "sha256", nil
	default:
		return "", errors.New("unknown IOC type")
	}
}

// addCrowdStrikeIOC will add a supported iocs with an optional description.
// defaults to an expiration date of 10 years & a severity of medium.
// will detect on domains/ips and block on hashes. Retro detection enabled by default.
func addCrowdStrikeIOCs(
	iocs []string,
	description string,
	client *client.CrowdStrikeAPISpecification,
) error {

	body := models.APIIndicatorCreateReqsV1{}

	for _, iocStr := range iocs {

		// validate ioc & get type of ioc
		iocType, err := getIOCType(iocStr)
		if err != nil {
			return err
		}

		// set default action
		action := "detect"
		if iocType == "md5" || iocType == "sha256" {
			action = "prevent"
		}

		expiration := strfmt.DateTime(time.Now().Add(24 * time.Hour * 365 * 10))

		// add iocs to body
		truth := true
		body.Indicators = append(body.Indicators, &models.APIIndicatorCreateReqV1{
			AppliedGlobally: &truth,
			Type:            iocType,  // sha256, md5, domain, ipv4, ipv6
			Action:          action,   // no_action, allow, prevent_no_ui, prevent, detect
			Severity:        "medium", // informational, low, medium, high, critical
			Description:     description,
			Platforms:       []string{"windows", "mac", "linux"},
			Value:           iocStr,
			Expiration:      &expiration,
			// Tags:   []string{"example_tag1", "example_tag2"},
		})
	}

	// create params
	params := ioc.NewIndicatorCreateV1Params().WithBody(&body)

	// trigger an alert if this IOC has been detected in the past
	t := true
	params.SetRetrodetects(&t)

	// ignore warnings on invalid IOCs
	//params.IgnoreWarnings = &t

	// send request off to CS
	_, err := client.Ioc.IndicatorCreateV1(params)
	if err != nil {
		return err
	}

	return nil
}

func addCrowdStrikeIOC(
	iocStr string,
	description string,
	client *client.CrowdStrikeAPISpecification,
) error {
	return addCrowdStrikeIOCs([]string{iocStr}, description, client)
}

// searchCrowdStrikeIOC searches custom IOCs for an IOC and returns an id if found.
// if no IOC is found, an empty string is returned.
func _getCrowdStrikeIOCID(
	iocStr string,
	client *client.CrowdStrikeAPISpecification,
) (id string, err error) {
	fql := fmt.Sprintf(`value:"%s"`, iocStr)

	params := ioc.NewIndicatorSearchV1Params().WithFilter(&fql)
	res, err := client.Ioc.IndicatorSearchV1(params)

	if err != nil {
		return "", err
	}
	if err = falcon.AssertNoError(res.GetPayload().Errors); err != nil {
		return "", err
	}

	resources := res.GetPayload().Resources
	if len(resources) != 1 {
		return "", errors.New("IOC not found: " + iocStr)
	}

	return resources[0], nil
}

// deleteCrowdStrikeIOCs deletes IOCs from the system.
func deleteCrowdStrikeIOCs(iocs []string, client *client.CrowdStrikeAPISpecification) error {
	iocIDs := []string{}
	for _, iocStr := range iocs {
		id, err := _getCrowdStrikeIOCID(iocStr, client)
		if err != nil {
			return err
		}
		iocIDs = append(iocIDs, id)
	}
	if len(iocIDs) == 0 {
		return errors.New("could not find any IOCs in the system matching that value")
	}
	params := ioc.NewIndicatorDeleteV1Params().WithIds(iocIDs)
	_, err := client.Ioc.IndicatorDeleteV1(params)
	if err != nil {
		return err
	}
	return nil
}

// deleteCrowdStrikeIOCs deletes a single IOC from the system.
func deleteCrowdStrikeIOC(iocStr string, client *client.CrowdStrikeAPISpecification) error {
	return deleteCrowdStrikeIOCs([]string{iocStr}, client)
}

func showCrowdStrikeIOC(iocStr string, client *client.CrowdStrikeAPISpecification) error {
	id, err := _getCrowdStrikeIOCID(iocStr, client)
	if err != nil {
		return err
	}
	res, err := client.Ioc.IndicatorGetV1(
		ioc.NewIndicatorGetV1Params().WithIds([]string{id}),
	)
	if err != nil {
		return err
	}

	if res.GetPayload() == nil {
		return nil
	}

	if err = falcon.AssertNoError(res.GetPayload().Errors); err != nil {
		panic(err)
	}

	if len(res.GetPayload().Resources) != 0 {
		json, err := falcon_util.PrettyJson(res.GetPayload().Resources[0])
		if err != nil {
			return err
		}
		fmt.Println(json)
	}
	return nil
}

func main() {

	falconClientId := flag.String(
		"client-id",
		os.Getenv("FALCON_CLIENT_ID"),
		"Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)",
	)
	falconClientSecret := flag.String(
		"client-secret",
		os.Getenv("FALCON_CLIENT_SECRET"),
		"Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)",
	)
	clientCloud := flag.String(
		"cloud",
		os.Getenv("FALCON_CLOUD"),
		"Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)",
	)
	debug := flag.Bool("debug", false, "Debug requests")

	list := flag.Bool("list", false, "list all IOC values in the IOC management panel")
	add := flag.String("add", "", "block an IOC (valid types: md5, sha256, domain, ipv4, ipv6)")
	description := flag.String("description", "", "add a IOC description for blocking")
	deleteIOC := flag.String("delete", "", "unblock an IOC, if present in the IOC management panel")
	show := flag.String("show", "", "show details of given IOC")

	flag.Parse()

	if !*list && *add == "" && *deleteIOC == "" && *show == "" {
		flag.Usage()
		return
	}

	// initialize api client
	// falconClientId := os.Getenv("FALCON_CLIENT_ID")
	// falconClientSecret := os.Getenv("FALCON_CLIENT_SECRET")
	// clientCloud := os.Getenv("FALCON_CLOUD")
	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     *falconClientId,
		ClientSecret: *falconClientSecret,
		Cloud:        falcon.Cloud(*clientCloud),
		Context:      context.Background(),
		Debug:        *debug,
	})
	if err != nil {
		panic(err)
	}

	if *list {
		iocs, err := getCrowdstrikeIOCs(client)
		if err != nil {
			panic(err)
		}
		for _, ioc := range iocs {
			fmt.Println(ioc)
		}
		return
	}

	if *add != "" {
		err := addCrowdStrikeIOC(*add, *description, client)
		if err != nil {
			panic(err)
		}
	}

	if *deleteIOC != "" {
		err := deleteCrowdStrikeIOC(*deleteIOC, client)
		if err != nil {
			panic(err)
		}
	}

	if *show != "" {
		err := showCrowdStrikeIOC(*show, client)
		if err != nil {
			panic(falcon.ErrorExplain(err))
		}
	}
}
