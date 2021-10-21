package falcon

import (
	"net/http"
	"net/url"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	httpruntime "github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2/clientcredentials"
)

// NewClient return newly configured API Client based on configuration supplied by user.
// NewClient function is preferred entry-point to gofalcon SDK.
func NewClient(ac *ApiConfig) (*client.CrowdStrikeAPISpecification, error) {
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
	authenticatedClient := config.Client(ac.Context)
	authenticatedClient.Timeout = ac.HttpTimeout()
	authenticatedClient.Transport = &roundTripper{
		T: authenticatedClient.Transport,
	}
	customTransport := httptransport.NewWithClient(
		ac.Host(), ac.BasePath(), []string{}, authenticatedClient)
	customTransport.Debug = ac.Debug
	customTransport.Consumers["application/pdf"] = httpruntime.ByteStreamConsumer()

	return client.New(customTransport, strfmt.Default), nil
}

type roundTripper struct {
	T                   http.RoundTripper
	LastRateLimitDigits int
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", userAgent)

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

var userAgent = "gofalcon/" + Version.String()
