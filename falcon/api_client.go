package falcon

import (
	"net/http"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
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
	authenticatedClient := config.Client(ac.Context)
	authenticatedClient.Transport = &roundTripper{
		T: authenticatedClient.Transport,
	}
	customTransport := httptransport.NewWithClient(
		ac.Host(), ac.BasePath(), []string{}, authenticatedClient)
	customTransport.Debug = ac.Debug

	return client.New(customTransport, strfmt.Default), nil
}

type roundTripper struct{
	T http.RoundTripper
	LastRateLimitDigits int
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", userAgent)

	if rt.LastRateLimitDigits == 1 || rt.LastRateLimitDigits == 2 {
		log.Debug("Approaching API rate limits. Waiting 500 milisecond.")
		time.Sleep(500 * time.Millisecond)
	}
	response, err := rt.T.RoundTrip(req)
	if response != nil {
		rt.LastRateLimitDigits = len(response.Header.Get("X-Ratelimit-Remaining"))
	}

	return response, err
}

var userAgent = "gofalcon/" + Version
