// Code generated by go-swagger; DO NOT EDIT.

package drift_indicators

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new drift indicators API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for drift indicators API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetDriftIndicatorsValuesByDate(params *GetDriftIndicatorsValuesByDateParams, opts ...ClientOption) (*GetDriftIndicatorsValuesByDateOK, error)

	ReadDriftIndicatorEntities(params *ReadDriftIndicatorEntitiesParams, opts ...ClientOption) (*ReadDriftIndicatorEntitiesOK, error)

	ReadDriftIndicatorsCount(params *ReadDriftIndicatorsCountParams, opts ...ClientOption) (*ReadDriftIndicatorsCountOK, error)

	SearchAndReadDriftIndicatorEntities(params *SearchAndReadDriftIndicatorEntitiesParams, opts ...ClientOption) (*SearchAndReadDriftIndicatorEntitiesOK, error)

	SearchDriftIndicators(params *SearchDriftIndicatorsParams, opts ...ClientOption) (*SearchDriftIndicatorsOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GetDriftIndicatorsValuesByDate returns the count of drift indicators by the date by default it s for 7 days
*/
func (a *Client) GetDriftIndicatorsValuesByDate(params *GetDriftIndicatorsValuesByDateParams, opts ...ClientOption) (*GetDriftIndicatorsValuesByDateOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetDriftIndicatorsValuesByDateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetDriftIndicatorsValuesByDate",
		Method:             "GET",
		PathPattern:        "/container-security/aggregates/drift-indicators/count-by-date/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetDriftIndicatorsValuesByDateReader{formats: a.formats},
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
	success, ok := result.(*GetDriftIndicatorsValuesByDateOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetDriftIndicatorsValuesByDate: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadDriftIndicatorEntities retrieves drift indicator entities identified by the provided i ds
*/
func (a *Client) ReadDriftIndicatorEntities(params *ReadDriftIndicatorEntitiesParams, opts ...ClientOption) (*ReadDriftIndicatorEntitiesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadDriftIndicatorEntitiesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadDriftIndicatorEntities",
		Method:             "GET",
		PathPattern:        "/container-security/entities/drift-indicators/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadDriftIndicatorEntitiesReader{formats: a.formats},
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
	success, ok := result.(*ReadDriftIndicatorEntitiesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadDriftIndicatorEntities: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadDriftIndicatorsCount returns the total count of drift indicators over a time period
*/
func (a *Client) ReadDriftIndicatorsCount(params *ReadDriftIndicatorsCountParams, opts ...ClientOption) (*ReadDriftIndicatorsCountOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadDriftIndicatorsCountParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadDriftIndicatorsCount",
		Method:             "GET",
		PathPattern:        "/container-security/aggregates/drift-indicators/count/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadDriftIndicatorsCountReader{formats: a.formats},
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
	success, ok := result.(*ReadDriftIndicatorsCountOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadDriftIndicatorsCount: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
SearchAndReadDriftIndicatorEntities maximums offset 10000 limit
*/
func (a *Client) SearchAndReadDriftIndicatorEntities(params *SearchAndReadDriftIndicatorEntitiesParams, opts ...ClientOption) (*SearchAndReadDriftIndicatorEntitiesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSearchAndReadDriftIndicatorEntitiesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "SearchAndReadDriftIndicatorEntities",
		Method:             "GET",
		PathPattern:        "/container-security/combined/drift-indicators/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SearchAndReadDriftIndicatorEntitiesReader{formats: a.formats},
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
	success, ok := result.(*SearchAndReadDriftIndicatorEntitiesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for SearchAndReadDriftIndicatorEntities: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
SearchDriftIndicators maximums offset 10000 limit
*/
func (a *Client) SearchDriftIndicators(params *SearchDriftIndicatorsParams, opts ...ClientOption) (*SearchDriftIndicatorsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSearchDriftIndicatorsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "SearchDriftIndicators",
		Method:             "GET",
		PathPattern:        "/container-security/queries/drift-indicators/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SearchDriftIndicatorsReader{formats: a.formats},
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
	success, ok := result.(*SearchDriftIndicatorsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for SearchDriftIndicators: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
