// Code generated by go-swagger; DO NOT EDIT.

package real_time_response_audit

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new real time response audit API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for real time response audit API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	RTRAuditSessions(params *RTRAuditSessionsParams, opts ...ClientOption) (*RTRAuditSessionsOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
RTRAuditSessions gets all the r t r sessions created for a customer in a specified duration
*/
func (a *Client) RTRAuditSessions(params *RTRAuditSessionsParams, opts ...ClientOption) (*RTRAuditSessionsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRTRAuditSessionsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "RTRAuditSessions",
		Method:             "GET",
		PathPattern:        "/real-time-response-audit/combined/sessions/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RTRAuditSessionsReader{formats: a.formats},
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
	success, ok := result.(*RTRAuditSessionsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for RTRAuditSessions: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
