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
	"golang.org/x/oauth2/clientcredentials"
)

// NewClient return newly configured API Client based on configuration supplied by user.
// NewClient function is preferred entry-point to gofalcon SDK.
func NewClient(ac *ApiConfig) (*client.CrowdStrikeAPISpecification, error) {
	if ac.ClientId == "" || ac.ClientSecret == "" {
		return nil, errors.New("Invalid Falcon API Credentials, received empty value")
	}
	if ac.Context == nil {
		return nil, errors.New("Invalid Context for falcon.ApiConfig.Context. Make that ApiConfig.Context is set.")
	}
	if err := ac.Cloud.Autodiscover(ac.Context, ac.ClientId, ac.ClientSecret); err != nil {
		return nil, err
	}

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
		T: &workaround{
			T: authenticatedClient.Transport,
		},
	}
	customTransport := httptransport.NewWithClient(
		ac.Host(), ac.BasePath(), []string{}, authenticatedClient)
	customTransport.Debug = ac.Debug
	customTransport.Consumers["application/pdf"] = httpruntime.ByteStreamConsumer()
	customTransport.Consumers["application/x-7z-compressed"] = httpruntime.ByteStreamConsumer()

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

type workaround struct {
	T http.RoundTripper
}

// RoundTrip workarounds missing content-type header when body is empty.
// This temporary workaround is needed as the recent go-openapi/runtime middleware
// won't send the content-type while the CrowdStrike service requires it for a time being
// https://github.com/go-openapi/runtime/commit/753b551e6b4a36e461ac877874fd0a79d0ffcf53
// Streaming session refresh within examples/falcon_event_stream can be used trigger this code
func (w *workaround) RoundTrip(req *http.Request) (*http.Response, error) {
	contentType := req.Header.Get("Content-Type")
	if contentType == "" {
		req.Header.Add("Content-Type", "application/json")
	}
	return w.T.RoundTrip(req)
}
