package falcon

import (
	"github.com/crowdstrike/gofalcon/falcon/client"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"golang.org/x/oauth2/clientcredentials"
)

func NewClient(ac *ApiConfig) (*client.CrowdStrikeAPISpecification, error) {
	config := clientcredentials.Config{
		ClientID: ac.ClientId,
		ClientSecret: ac.ClientSecret,
		TokenURL: "https://" + ac.Host() + "/oauth2/token",
	}
	authenticatedClient := config.Client(ac.Context)
	customTransport := httptransport.NewWithClient(
		ac.Host(), ac.BasePath(), []string{}, authenticatedClient)

	return client.New(customTransport, strfmt.Default), nil
}
