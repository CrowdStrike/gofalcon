package falcon

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	httpruntime "github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// NewClient return newly configured API Client based on configuration supplied by user.
// NewClient function is preferred entry-point to gofalcon SDK.
func NewClient(ac *ApiConfig) (*client.CrowdStrikeAPISpecification, error) {
	if ok, err := credentialsOk(ac); !ok {
		return nil, err
	}
	if ac.Context == nil {
		return nil, errors.New("invalid context for falcon.ApiConfig.Context. Make that ApiConfig.Context is set")
	}

	// If HostOverride is provided we do not need to discover the cloud
	if ac.HostOverride == "" {
		if ac.AccessToken == "" {
			if err := ac.Cloud.Autodiscover(ac.Context, ac.ClientId, ac.ClientSecret); err != nil {
				return nil, err
			}
		} else if ac.Cloud == CloudAutoDiscover {
			// There is nothing in the access token (JWT) which identifies the cloud.
			return nil, errors.New("cannot autodiscover cloud when using an access token. Please specify the cloud explicitly")
		}
	}

	var authenticatedClient *http.Client
	if ac.AccessToken == "" {
		authenticatedClient = clientCredentialsHTTPClient(ac)
	} else {
		authenticatedClient = accessTokenHTTPClient(ac)
	}

	customTransport := httptransport.NewWithClient(ac.Host(), ac.BasePath(), []string{}, authenticatedClient)
	customTransport.Debug = ac.Debug
	customTransport.Consumers["application/pdf"] = httpruntime.ByteStreamConsumer()
	customTransport.Consumers["application/x-7z-compressed"] = httpruntime.ByteStreamConsumer()

	return client.New(customTransport, strfmt.Default), nil
}

func credentialsOk(ac *ApiConfig) (bool, error) {
	hasAccessToken := ac.AccessToken != ""
	hasClientIDSecret := ac.ClientId != "" && ac.ClientSecret != ""

	if (hasAccessToken && hasClientIDSecret) || (!hasAccessToken && !hasClientIDSecret) {
		return false, errors.New("must provide either an access token or a client ID and secret, but not both and not neither")
	}
	return true, nil
}

func accessTokenHTTPClient(ac *ApiConfig) *http.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: ac.AccessToken})
	return commonHTTPClientConfig(oauth2.NewClient(ac.Context, ts), ac)
}

func clientCredentialsHTTPClient(ac *ApiConfig) *http.Client {
	config := clientcredentials.Config{
		ClientID:     ac.ClientId,
		ClientSecret: ac.ClientSecret,
		TokenURL:     "https://" + ac.Host() + "/oauth2/token",
	}

	if ac.MemberCID != "" {
		config.EndpointParams = url.Values{
			"member_cid": []string{ac.MemberCID},
		}
	}
	return commonHTTPClientConfig(config.Client(ac.Context), ac)
}

func commonHTTPClientConfig(c *http.Client, ac *ApiConfig) *http.Client {
	c.Timeout = ac.HttpTimeout()
	c.Transport = &roundTripper{
		T:         &workaround{T: c.Transport},
		UserAgent: ac.UserAgent(),
	}

	if ac.TransportDecorator != nil {
		c.Transport = ac.TransportDecorator(c.Transport)
	}

	return c
}

type roundTripper struct {
	T                   http.RoundTripper
	UserAgent           string
	LastRateLimitDigits int
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", rt.UserAgent)
	req.Header.Add("CrowdStrike-SDK", "crowdstrike-gofalcon/"+Version.String())

	if rt.LastRateLimitDigits == 1 || rt.LastRateLimitDigits == 2 {
		log.Debug("Approaching CrowdStrike API rate limits. Waiting 500 millisecond.")
		time.Sleep(500 * time.Millisecond)
	}
	response, err := rt.T.RoundTrip(req)
	if response != nil {
		rt.LastRateLimitDigits = len(response.Header.Get("X-Ratelimit-Remaining"))
	}

	return response, err
}

type workaround struct {
	T http.RoundTripper
}

// RoundTrip workarounds missing content-type header when body is empty.
// This temporary workaround is needed as the recent go-openapi/runtime middleware
// won't send the content-type while the CrowdStrike service requires it for a time being
// https://github.com/go-openapi/runtime/commit/753b551e6b4a36e461ac877874fd0a79d0ffcf53
// Streaming session refresh within examples/falcon_event_stream can be used trigger this code.
func (w *workaround) RoundTrip(req *http.Request) (*http.Response, error) {
	contentType := req.Header.Get("Content-Type")
	if contentType == "" {
		req.Header.Add("Content-Type", "application/json")
	}
	return w.T.RoundTrip(req)
}

// TransportDecorator accepts a RoundTripper and returns a RoundTripper.
// This can be used to wrap or decorate the authenticated client's built-in
// HTTP client operation behavior for all API requests.
type TransportDecorator func(http.RoundTripper) http.RoundTripper
