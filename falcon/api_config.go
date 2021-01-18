package falcon

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client"
)

// TODO authenticate with token
type ApiConfig struct {
	ClientId         string
	ClientSecret     string
	Context          context.Context
	HostOverride     string
	BasePathOverride string
}

func (ac *ApiConfig) Host() string {
	if ac.HostOverride == "" {
		return client.DefaultHost
	}
	return ac.HostOverride
}

func (ac *ApiConfig) BasePath() string {
	if ac.BasePathOverride == "" {
		return client.DefaultBasePath
	}
	return ac.BasePathOverride
}
