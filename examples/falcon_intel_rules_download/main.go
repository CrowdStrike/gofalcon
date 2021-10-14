package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	intelRuleType := flag.String("rule-type", "", fmt.Sprintf("Falcon Intelligence Rule Type: available types: %s", intel.RuleTypeValidValues))
	flag.Parse()

	if *clientId == "" {
		*clientId = falcon_util.PromptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}

	if !intel.RuleType(*intelRuleType).Valid() {
		*intelRuleType = falcon_util.PromptUser(fmt.Sprintf("Missing--rule-type argument. Valid options are %s. \nRequested Rule type", intel.RuleTypeValidValues))
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

	intelType := *intelRuleType
	filepath := fmt.Sprintf("%s.tar.gz", intelType)
	fmt.Printf("Downloading file %s\n", filepath)
	err = DownloadLatestRuleFile(client, filepath, intelType)
	if err != nil {
		panic(err)

	}
}

func DownloadLatestRuleFile(client *client.CrowdStrikeAPISpecification, filename, intelType string) error {
	safeLocation := filepath.Clean(filename)
	if strings.Contains(safeLocation, "/") || strings.Contains(safeLocation, "\\") || strings.Contains(safeLocation, "..") {
		panic("Suspicious file location: " + safeLocation)
	}

	file, err := os.OpenFile(safeLocation, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	/* #nosec */
	defer func() {
		// (ignore possibly false positive https://github.com/securego/gosec/issues/714)
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file: %s\n", err)
		}
	}()

	gzip := "gzip"
	_, err = client.Intel.GetLatestIntelRuleFile(&intel.GetLatestIntelRuleFileParams{
		Context: context.Background(),
		Type:    intelType,
		Format:  &gzip,
	}, file)
	if err != nil {
		return err
	}
	return nil
}
