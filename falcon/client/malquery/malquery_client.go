// Code generated by go-swagger; DO NOT EDIT.

package malquery

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new malquery API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for malquery API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetMalQueryDownloadV1(params *GetMalQueryDownloadV1Params, opts ...ClientOption) (*GetMalQueryDownloadV1OK, error)

	GetMalQueryEntitiesSamplesFetchV1(params *GetMalQueryEntitiesSamplesFetchV1Params, opts ...ClientOption) (*GetMalQueryEntitiesSamplesFetchV1OK, error)

	GetMalQueryMetadataV1(params *GetMalQueryMetadataV1Params, opts ...ClientOption) (*GetMalQueryMetadataV1OK, error)

	GetMalQueryQuotasV1(params *GetMalQueryQuotasV1Params, opts ...ClientOption) (*GetMalQueryQuotasV1OK, error)

	GetMalQueryRequestV1(params *GetMalQueryRequestV1Params, opts ...ClientOption) (*GetMalQueryRequestV1OK, error)

	PostMalQueryEntitiesSamplesMultidownloadV1(params *PostMalQueryEntitiesSamplesMultidownloadV1Params, opts ...ClientOption) (*PostMalQueryEntitiesSamplesMultidownloadV1OK, error)

	PostMalQueryExactSearchV1(params *PostMalQueryExactSearchV1Params, opts ...ClientOption) (*PostMalQueryExactSearchV1OK, error)

	PostMalQueryFuzzySearchV1(params *PostMalQueryFuzzySearchV1Params, opts ...ClientOption) (*PostMalQueryFuzzySearchV1OK, error)

	PostMalQueryHuntV1(params *PostMalQueryHuntV1Params, opts ...ClientOption) (*PostMalQueryHuntV1OK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  GetMalQueryDownloadV1 downloads a file indexed by mal query specify the file using its s h a256 only one file is supported at this time
*/
func (a *Client) GetMalQueryDownloadV1(params *GetMalQueryDownloadV1Params, opts ...ClientOption) (*GetMalQueryDownloadV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetMalQueryDownloadV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetMalQueryDownloadV1",
		Method:             "GET",
		PathPattern:        "/malquery/entities/download-files/v1",
		ProducesMediaTypes: []string{"application/json", "application/octet-stream"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetMalQueryDownloadV1Reader{formats: a.formats},
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
	success, ok := result.(*GetMalQueryDownloadV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetMalQueryDownloadV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetMalQueryEntitiesSamplesFetchV1 fetches a zip archive with password infected containing the samples call this once the entities samples multidownload request has finished processing
*/
func (a *Client) GetMalQueryEntitiesSamplesFetchV1(params *GetMalQueryEntitiesSamplesFetchV1Params, opts ...ClientOption) (*GetMalQueryEntitiesSamplesFetchV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetMalQueryEntitiesSamplesFetchV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetMalQueryEntitiesSamplesFetchV1",
		Method:             "GET",
		PathPattern:        "/malquery/entities/samples-fetch/v1",
		ProducesMediaTypes: []string{"application/json", "application/zip"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetMalQueryEntitiesSamplesFetchV1Reader{formats: a.formats},
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
	success, ok := result.(*GetMalQueryEntitiesSamplesFetchV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetMalQueryEntitiesSamplesFetchV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetMalQueryMetadataV1 retrieves indexed files metadata by their hash
*/
func (a *Client) GetMalQueryMetadataV1(params *GetMalQueryMetadataV1Params, opts ...ClientOption) (*GetMalQueryMetadataV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetMalQueryMetadataV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetMalQueryMetadataV1",
		Method:             "GET",
		PathPattern:        "/malquery/entities/metadata/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetMalQueryMetadataV1Reader{formats: a.formats},
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
	success, ok := result.(*GetMalQueryMetadataV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetMalQueryMetadataV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetMalQueryQuotasV1 gets information about search and download quotas in your environment
*/
func (a *Client) GetMalQueryQuotasV1(params *GetMalQueryQuotasV1Params, opts ...ClientOption) (*GetMalQueryQuotasV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetMalQueryQuotasV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetMalQueryQuotasV1",
		Method:             "GET",
		PathPattern:        "/malquery/aggregates/quotas/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetMalQueryQuotasV1Reader{formats: a.formats},
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
	success, ok := result.(*GetMalQueryQuotasV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetMalQueryQuotasV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetMalQueryRequestV1 checks the status and results of an asynchronous request such as hunt or exact search supports a single request id at this time
*/
func (a *Client) GetMalQueryRequestV1(params *GetMalQueryRequestV1Params, opts ...ClientOption) (*GetMalQueryRequestV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetMalQueryRequestV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetMalQueryRequestV1",
		Method:             "GET",
		PathPattern:        "/malquery/entities/requests/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetMalQueryRequestV1Reader{formats: a.formats},
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
	success, ok := result.(*GetMalQueryRequestV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetMalQueryRequestV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PostMalQueryEntitiesSamplesMultidownloadV1 schedules samples for download use the result id with the request endpoint to check if the download is ready after which you can call the entities samples fetch to get the zip
*/
func (a *Client) PostMalQueryEntitiesSamplesMultidownloadV1(params *PostMalQueryEntitiesSamplesMultidownloadV1Params, opts ...ClientOption) (*PostMalQueryEntitiesSamplesMultidownloadV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostMalQueryEntitiesSamplesMultidownloadV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostMalQueryEntitiesSamplesMultidownloadV1",
		Method:             "POST",
		PathPattern:        "/malquery/entities/samples-multidownload/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostMalQueryEntitiesSamplesMultidownloadV1Reader{formats: a.formats},
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
	success, ok := result.(*PostMalQueryEntitiesSamplesMultidownloadV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PostMalQueryEntitiesSamplesMultidownloadV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PostMalQueryExactSearchV1 searches falcon mal query for a combination of hex patterns and strings in order to identify samples based upon file content at byte level granularity you can filter results on criteria such as file type file size and first seen date returns a request id which can be used with the request endpoint
*/
func (a *Client) PostMalQueryExactSearchV1(params *PostMalQueryExactSearchV1Params, opts ...ClientOption) (*PostMalQueryExactSearchV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostMalQueryExactSearchV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostMalQueryExactSearchV1",
		Method:             "POST",
		PathPattern:        "/malquery/queries/exact-search/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostMalQueryExactSearchV1Reader{formats: a.formats},
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
	success, ok := result.(*PostMalQueryExactSearchV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PostMalQueryExactSearchV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PostMalQueryFuzzySearchV1 searches falcon mal query quickly but with more potential for false positives search for a combination of hex patterns and strings in order to identify samples based upon file content at byte level granularity
*/
func (a *Client) PostMalQueryFuzzySearchV1(params *PostMalQueryFuzzySearchV1Params, opts ...ClientOption) (*PostMalQueryFuzzySearchV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostMalQueryFuzzySearchV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostMalQueryFuzzySearchV1",
		Method:             "POST",
		PathPattern:        "/malquery/combined/fuzzy-search/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostMalQueryFuzzySearchV1Reader{formats: a.formats},
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
	success, ok := result.(*PostMalQueryFuzzySearchV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PostMalQueryFuzzySearchV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PostMalQueryHuntV1 schedules a y a r a based search for execution returns a request id which can be used with the request endpoint
*/
func (a *Client) PostMalQueryHuntV1(params *PostMalQueryHuntV1Params, opts ...ClientOption) (*PostMalQueryHuntV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostMalQueryHuntV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostMalQueryHuntV1",
		Method:             "POST",
		PathPattern:        "/malquery/queries/hunt/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostMalQueryHuntV1Reader{formats: a.formats},
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
	success, ok := result.(*PostMalQueryHuntV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PostMalQueryHuntV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
