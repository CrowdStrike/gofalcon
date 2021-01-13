package falcon

import (
	"context"
	"errors"
	"net/http"

	"golang.org/x/oauth2/clientcredentials"
)

type ApiClient struct {
	client *http.Client
	config *ApiConfig
}

// NewApiClient returns a new CrowdStrike Falcon API client
func NewApiClient(ctx context.Context, config *ApiConfig) (*ApiClient, error) {
	if ctx == nil {
		return nil, errors.New("context must be non-nil")
	}
	ac := &ApiClient{
		config: config,
	}
	ac.oauth(ctx)
	return ac, nil
}

func (ac *ApiClient) oauth(ctx context.Context) {
	config := clientcredentials.Config{
		ClientID: ac.config.ClientId,
		ClientSecret: ac.config.ClientSecret,
		TokenURL: ac.config.GetBaseUrl() + "/oauth2/token",
	}
	ac.client = config.Client(ctx)
}
