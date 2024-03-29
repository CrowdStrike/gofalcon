// Code generated by go-swagger; DO NOT EDIT.

package configuration_assessment

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new configuration assessment API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for configuration assessment API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetCombinedAssessmentsQuery(params *GetCombinedAssessmentsQueryParams, opts ...ClientOption) (*GetCombinedAssessmentsQueryOK, error)

	GetRuleDetails(params *GetRuleDetailsParams, opts ...ClientOption) (*GetRuleDetailsOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GetCombinedAssessmentsQuery searches for assessments in your environment by providing an f q l filter and paging details returns a set of host finding entities which match the filter criteria
*/
func (a *Client) GetCombinedAssessmentsQuery(params *GetCombinedAssessmentsQueryParams, opts ...ClientOption) (*GetCombinedAssessmentsQueryOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetCombinedAssessmentsQueryParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getCombinedAssessmentsQuery",
		Method:             "GET",
		PathPattern:        "/configuration-assessment/combined/assessments/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetCombinedAssessmentsQueryReader{formats: a.formats},
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
	success, ok := result.(*GetCombinedAssessmentsQueryOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getCombinedAssessmentsQuery: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetRuleDetails gets rules details for provided one or more rule i ds
*/
func (a *Client) GetRuleDetails(params *GetRuleDetailsParams, opts ...ClientOption) (*GetRuleDetailsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetRuleDetailsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getRuleDetails",
		Method:             "GET",
		PathPattern:        "/configuration-assessment/entities/rule-details/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetRuleDetailsReader{formats: a.formats},
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
	success, ok := result.(*GetRuleDetailsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getRuleDetails: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
