package falcon

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/oauth2"
	"github.com/go-openapi/strfmt"
)

// CloudType represents type of CrowdStrike Falcon cloud region.
type CloudType int

const (
	CloudAutoDiscover = iota
	CloudUs1
	CloudUs2
	CloudEu1
	CloudUsGov1
)

// Cloud parses clould string (example: us-1, us-2, eu-1, us-gov-1, etc). If a string is not recognised CloudUs1 is returned.
func Cloud(cloudString string) CloudType {
	c, _ := CloudValidate(cloudString)
	return c
}

// CloudValidate parses cloud string (example: us-1, us-2, eu-1, us-gov-1, etc.). Error is returned when string cannot be recognised
func CloudValidate(cloudString string) (CloudType, error) {
	trimmed := strings.TrimSpace(cloudString)
	lower := strings.ToLower(trimmed)
	switch lower {
	case "":
		fallthrough
	case "autodiscover":
		return CloudAutoDiscover, nil
	case "us-1":
		return CloudUs1, nil
	case "us-2":
		return CloudUs2, nil
	case "eu-1":
		return CloudEu1, nil
	case "us-gov-1":
		return CloudUsGov1, nil
	}
	return CloudUs1, fmt.Errorf("unrecognized CrowdStrike Falcon Cloud: %s", lower)
}

// Host returns default hostname for given cloud.
func (c CloudType) Host() string {
	switch c {
	default:
		fallthrough
	case CloudUs1:
		return "api.crowdstrike.com"
	case CloudUs2:
		return "api.us-2.crowdstrike.com"
	case CloudEu1:
		return "api.eu-1.crowdstrike.com"
	case CloudUsGov1:
		return "api.laggar.gcw.crowdstrike.com"
	}
}

func (c CloudType) String() string {
	switch c {
	case CloudAutoDiscover:
		return "autodiscover"
	case CloudUs1:
		return "us-1"
	case CloudUs2:
		return "us-2"
	case CloudEu1:
		return "eu-1"
	case CloudUsGov1:
		return "us-gov-1"
	default:
		return "UNKNOWN FALCON CLOUD REGION"
	}
}

func (c *CloudType) Autodiscover(ctx context.Context, clientId, clientSecret string) error {
	if *c != CloudAutoDiscover {
		return nil
	}

	// (1) Request our cloud-region information from us-1 cloud-region
	cli := client.NewHTTPClient(strfmt.Default)
	token, err := cli.Oauth2.Oauth2AccessToken(&oauth2.Oauth2AccessTokenParams{
		Context:      ctx,
		ClientID:     clientId,
		ClientSecret: clientSecret,
	})
	if err != nil {
		switch e := err.(type) {
		case *oauth2.Oauth2AccessTokenForbidden:
			if e.Payload != nil && len(e.Payload.Errors) == 1 && e.Payload.Errors[0] != nil && e.Payload.Errors[0].Message != nil && *e.Payload.Errors[0].Message == "access denied, authorization failed" {
				return fmt.Errorf("Please check the settings of IP-based allowlisting in CrowdStrike Falcon Console. %s", e)
			}
			return fmt.Errorf("Insufficient CrowdStrike privileges, please grant [Falcon Images Download: Read] to CrowdStrike API Key. Error was: %s", err)
		}
		return fmt.Errorf("Could not autodiscover Falcon cloud region: %v", err)
	}
	// (2) Parse & save the cloud-region information
	cld, err := CloudValidate(token.XCSRegion)
	if err != nil {
		return fmt.Errorf("Could not validate Falcon cloud region '%s' during autodiscover: %v", token.XCSRegion, err)
	}
	(*c) = cld

	// (3) Revoke the API token we have got from us-1 region
	if (*c) != CloudUs1 {
		// (4) Revocation needs to be done in our *local* region
		transportConfig := client.DefaultTransportConfig().WithHost(c.Host())
		cli = client.NewHTTPClientWithConfig(strfmt.Default, transportConfig)
	}

	revocation, err := cli.Oauth2.Oauth2RevokeToken(&oauth2.Oauth2RevokeTokenParams{
		Context: ctx,
		Token:   *token.Payload.AccessToken,
	},
		oauth2.AuthenticateRevocation(clientId, clientSecret),
	)
	if err != nil {
		return nil
	}
	if err = AssertNoError(revocation.Payload.Errors); err != nil {
		return err
	}
	return nil
}
