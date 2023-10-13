// Code generated by go-swagger; DO NOT EDIT.

package discover_iot

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new discover iot API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for discover iot API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetIotHosts(params *GetIotHostsParams, opts ...ClientOption) (*GetIotHostsOK, error)

	QueryIotHosts(params *QueryIotHostsParams, opts ...ClientOption) (*QueryIotHostsOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  GetIotHosts gets details on io t assets by providing one or more i ds
*/
func (a *Client) GetIotHosts(params *GetIotHostsParams, opts ...ClientOption) (*GetIotHostsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIotHostsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "get-iot-hosts",
		Method:             "GET",
		PathPattern:        "/discover/entities/iot-hosts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetIotHostsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetIotHostsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get-iot-hosts: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  QueryIotHosts searches for io t assets in your environment by providing an f q l falcon query language filter and paging details returns a set of asset i ds which match the filter criteria
*/
func (a *Client) QueryIotHosts(params *QueryIotHostsParams, opts ...ClientOption) (*QueryIotHostsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryIotHostsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "query-iot-hosts",
		Method:             "GET",
		PathPattern:        "/discover/queries/iot-hosts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryIotHostsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*QueryIotHostsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for query-iot-hosts: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
