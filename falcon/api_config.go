package falcon

import (
	"context"
	"time"

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
	// HttpTimeOutOverride allows users to override default HTTP Time-out (5 minutes). This timeout should rarely be hit. The time-out protects user-application should an unlikely event of CrowdStrike outage occur. Users that need to have more control over HTTP time-outs are advised to use context.Context argument to API calls instead of this variable.
	HttpTimeOutOverride *time.Duration

	// Debug forces print out of all http traffic going through the API Runtime
	Debug bool
}

// Host returns FQDN of CrowdStrike API Gateway to be used by this ApiConfig
func (ac *ApiConfig) Host() string {
	if ac.HostOverride != "" {
		return ac.HostOverride
	}
	return ac.Cloud.Host()
}

// Host returns base URL path to be used by this ApiConfig
func (ac *ApiConfig) BasePath() string {
	if ac.BasePathOverride == "" {
		return client.DefaultBasePath
	}
	return ac.BasePathOverride
}

func (ac *ApiConfig) HttpTimeout() time.Duration {
	if ac.HttpTimeOutOverride == nil {
		return 5 * time.Minute
	}
	return *ac.HttpTimeOutOverride
}
