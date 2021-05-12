package falcon

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client"
)

// ApiConfig object is used to initialise and configure API Client. Together with NewClient function, ApiConfig provides preferred way to initiate API communication.
type ApiConfig struct {
	// Client ID used for authentication with CrowdStrike Falcon platform. *required*
	ClientId string
	// Client Secret used for authentication with CrowdStrike Falcon platform. *required*
	ClientSecret string
	// Optional: CID selector for cases when the ClientID/ClientSecret has access to multiple CIDs
	MemberCID string
	// This Context object will be used only when authenticating with the OAuth interface.
	Context context.Context
	// Cloud allows us to select Falcon Cloud to connect
	Cloud CloudType
	// HostOverride allows to override default host (default: api.crowdstrike.com)
	HostOverride string
	// BasePathOverride allows to override default base path (default: /)
	BasePathOverride string
	// Debug forces print out of all http traffic going through the API Runtime
	Debug bool
}

func (ac *ApiConfig) Host() string {
	if ac.HostOverride != "" {
		return ac.HostOverride
	}
	return ac.Cloud.Host()
}

func (ac *ApiConfig) BasePath() string {
	if ac.BasePathOverride == "" {
		return client.DefaultBasePath
	}
	return ac.BasePathOverride
}
