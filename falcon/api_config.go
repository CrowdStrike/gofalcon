package falcon

type ApiConfig struct {
	ClientId string
	ClientSecret string
	BaseUrl string
}

func (ac *ApiConfig) GetBaseUrl() string {
	if ac.BaseUrl == "" {
		return "https://api.crowdstrike.com"
	}
	return ac.BaseUrl
}
