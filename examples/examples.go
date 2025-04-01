package examples

import (
	"flag"
	"os"

	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

// CommonAuthFlags is a struct that holds common authentication flags used for most examples.
type CommonAuthFlags struct {
	ClientId     string
	ClientSecret string
	MemberCID    string
	Cloud        string
}

func (c *CommonAuthFlags) PromptForRequiredFlags() {
	if c.ClientId == "" {
		c.ClientId = falcon_util.PromptUser("Please provide your OAuth2 API Client ID")
	}

	if c.ClientSecret == "" {
		c.ClientSecret = falcon_util.PromptUser("Please provide your OAuth2 API Client Secret")
	}
}

// SetupAuthFlags parses command line flags and returns a CommonAuthFlags struct.
func SetupAuthFlags() *CommonAuthFlags {
	commonAuthFlags := CommonAuthFlags{}
	flag.StringVar(&commonAuthFlags.ClientId, "client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	flag.StringVar(&commonAuthFlags.ClientSecret, "client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	flag.StringVar(&commonAuthFlags.MemberCID, "member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	flag.StringVar(&commonAuthFlags.Cloud, "cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")

	return &commonAuthFlags
}

// HandleError panics when err is not nil.
func HandleError(err error) {
	if err != nil {
		panic(err)
	}
}
