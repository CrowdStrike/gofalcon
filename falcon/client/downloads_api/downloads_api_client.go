// Code generated by go-swagger; DO NOT EDIT.

package downloads_api

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new downloads api API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for downloads api API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	DownloadFile(params *DownloadFileParams, opts ...ClientOption) (*DownloadFileOK, error)

	EnumerateFile(params *EnumerateFileParams, opts ...ClientOption) (*EnumerateFileOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
DownloadFile gets pre signed URL for the file
*/
func (a *Client) DownloadFile(params *DownloadFileParams, opts ...ClientOption) (*DownloadFileOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDownloadFileParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DownloadFile",
		Method:             "GET",
		PathPattern:        "/csdownloads/entities/files/download/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DownloadFileReader{formats: a.formats},
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
	success, ok := result.(*DownloadFileOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DownloadFile: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
EnumerateFile enumerates a list of files available for c ID
*/
func (a *Client) EnumerateFile(params *EnumerateFileParams, opts ...ClientOption) (*EnumerateFileOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewEnumerateFileParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "EnumerateFile",
		Method:             "GET",
		PathPattern:        "/csdownloads/entities/files/enumerate/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &EnumerateFileReader{formats: a.formats},
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
	success, ok := result.(*EnumerateFileOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for EnumerateFile: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
