package falcon

import "context"

// TODO other options, base URL override, Start with token, etc.
type ApiConfig struct {
	ClientId string
	ClientSecret string
	Context context.Context
}
