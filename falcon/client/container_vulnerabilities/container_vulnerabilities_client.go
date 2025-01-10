// Code generated by go-swagger; DO NOT EDIT.

package container_vulnerabilities

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new container vulnerabilities API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for container vulnerabilities API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	ReadCombinedVulnerabilities(params *ReadCombinedVulnerabilitiesParams, opts ...ClientOption) (*ReadCombinedVulnerabilitiesOK, error)

	ReadCombinedVulnerabilitiesDetails(params *ReadCombinedVulnerabilitiesDetailsParams, opts ...ClientOption) (*ReadCombinedVulnerabilitiesDetailsOK, error)

	ReadCombinedVulnerabilitiesInfo(params *ReadCombinedVulnerabilitiesInfoParams, opts ...ClientOption) (*ReadCombinedVulnerabilitiesInfoOK, error)

	ReadVulnerabilitiesByImageCount(params *ReadVulnerabilitiesByImageCountParams, opts ...ClientOption) (*ReadVulnerabilitiesByImageCountOK, error)

	ReadVulnerabilitiesPublicationDate(params *ReadVulnerabilitiesPublicationDateParams, opts ...ClientOption) (*ReadVulnerabilitiesPublicationDateOK, error)

	ReadVulnerabilityCount(params *ReadVulnerabilityCountParams, opts ...ClientOption) (*ReadVulnerabilityCountOK, error)

	ReadVulnerabilityCountByActivelyExploited(params *ReadVulnerabilityCountByActivelyExploitedParams, opts ...ClientOption) (*ReadVulnerabilityCountByActivelyExploitedOK, error)

	ReadVulnerabilityCountByCPSRating(params *ReadVulnerabilityCountByCPSRatingParams, opts ...ClientOption) (*ReadVulnerabilityCountByCPSRatingOK, error)

	ReadVulnerabilityCountByCVSSScore(params *ReadVulnerabilityCountByCVSSScoreParams, opts ...ClientOption) (*ReadVulnerabilityCountByCVSSScoreOK, error)

	ReadVulnerabilityCountBySeverity(params *ReadVulnerabilityCountBySeverityParams, opts ...ClientOption) (*ReadVulnerabilityCountBySeverityOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
ReadCombinedVulnerabilities maximums offset 9900
*/
func (a *Client) ReadCombinedVulnerabilities(params *ReadCombinedVulnerabilitiesParams, opts ...ClientOption) (*ReadCombinedVulnerabilitiesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadCombinedVulnerabilitiesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadCombinedVulnerabilities",
		Method:             "GET",
		PathPattern:        "/container-security/combined/vulnerabilities/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadCombinedVulnerabilitiesReader{formats: a.formats},
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
	success, ok := result.(*ReadCombinedVulnerabilitiesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadCombinedVulnerabilities: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadCombinedVulnerabilitiesDetails maximums offset 9900
*/
func (a *Client) ReadCombinedVulnerabilitiesDetails(params *ReadCombinedVulnerabilitiesDetailsParams, opts ...ClientOption) (*ReadCombinedVulnerabilitiesDetailsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadCombinedVulnerabilitiesDetailsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadCombinedVulnerabilitiesDetails",
		Method:             "GET",
		PathPattern:        "/container-security/combined/vulnerabilities/details/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadCombinedVulnerabilitiesDetailsReader{formats: a.formats},
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
	success, ok := result.(*ReadCombinedVulnerabilitiesDetailsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadCombinedVulnerabilitiesDetails: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadCombinedVulnerabilitiesInfo maximums offset 9900
*/
func (a *Client) ReadCombinedVulnerabilitiesInfo(params *ReadCombinedVulnerabilitiesInfoParams, opts ...ClientOption) (*ReadCombinedVulnerabilitiesInfoOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadCombinedVulnerabilitiesInfoParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadCombinedVulnerabilitiesInfo",
		Method:             "GET",
		PathPattern:        "/container-security/combined/vulnerabilities/info/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadCombinedVulnerabilitiesInfoReader{formats: a.formats},
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
	success, ok := result.(*ReadCombinedVulnerabilitiesInfoOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadCombinedVulnerabilitiesInfo: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadVulnerabilitiesByImageCount maximums offset 9900
*/
func (a *Client) ReadVulnerabilitiesByImageCount(params *ReadVulnerabilitiesByImageCountParams, opts ...ClientOption) (*ReadVulnerabilitiesByImageCountOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadVulnerabilitiesByImageCountParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadVulnerabilitiesByImageCount",
		Method:             "GET",
		PathPattern:        "/container-security/combined/vulnerabilities/by-image-count/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadVulnerabilitiesByImageCountReader{formats: a.formats},
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
	success, ok := result.(*ReadVulnerabilitiesByImageCountOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadVulnerabilitiesByImageCount: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadVulnerabilitiesPublicationDate maximums offset 9900
*/
func (a *Client) ReadVulnerabilitiesPublicationDate(params *ReadVulnerabilitiesPublicationDateParams, opts ...ClientOption) (*ReadVulnerabilitiesPublicationDateOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadVulnerabilitiesPublicationDateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadVulnerabilitiesPublicationDate",
		Method:             "GET",
		PathPattern:        "/container-security/combined/vulnerabilities/by-published-date/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadVulnerabilitiesPublicationDateReader{formats: a.formats},
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
	success, ok := result.(*ReadVulnerabilitiesPublicationDateOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadVulnerabilitiesPublicationDate: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadVulnerabilityCount maximums offset 9900
*/
func (a *Client) ReadVulnerabilityCount(params *ReadVulnerabilityCountParams, opts ...ClientOption) (*ReadVulnerabilityCountOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadVulnerabilityCountParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadVulnerabilityCount",
		Method:             "GET",
		PathPattern:        "/container-security/aggregates/vulnerabilities/count/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadVulnerabilityCountReader{formats: a.formats},
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
	success, ok := result.(*ReadVulnerabilityCountOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadVulnerabilityCount: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadVulnerabilityCountByActivelyExploited maximums offset 9900
*/
func (a *Client) ReadVulnerabilityCountByActivelyExploited(params *ReadVulnerabilityCountByActivelyExploitedParams, opts ...ClientOption) (*ReadVulnerabilityCountByActivelyExploitedOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadVulnerabilityCountByActivelyExploitedParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadVulnerabilityCountByActivelyExploited",
		Method:             "GET",
		PathPattern:        "/container-security/aggregates/vulnerabilities/count-by-actively-exploited/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadVulnerabilityCountByActivelyExploitedReader{formats: a.formats},
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
	success, ok := result.(*ReadVulnerabilityCountByActivelyExploitedOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadVulnerabilityCountByActivelyExploited: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadVulnerabilityCountByCPSRating maximums offset 9900
*/
func (a *Client) ReadVulnerabilityCountByCPSRating(params *ReadVulnerabilityCountByCPSRatingParams, opts ...ClientOption) (*ReadVulnerabilityCountByCPSRatingOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadVulnerabilityCountByCPSRatingParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadVulnerabilityCountByCPSRating",
		Method:             "GET",
		PathPattern:        "/container-security/aggregates/vulnerabilities/count-by-cps-rating/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadVulnerabilityCountByCPSRatingReader{formats: a.formats},
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
	success, ok := result.(*ReadVulnerabilityCountByCPSRatingOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadVulnerabilityCountByCPSRating: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadVulnerabilityCountByCVSSScore maximums offset 9900
*/
func (a *Client) ReadVulnerabilityCountByCVSSScore(params *ReadVulnerabilityCountByCVSSScoreParams, opts ...ClientOption) (*ReadVulnerabilityCountByCVSSScoreOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadVulnerabilityCountByCVSSScoreParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadVulnerabilityCountByCVSSScore",
		Method:             "GET",
		PathPattern:        "/container-security/aggregates/vulnerabilities/count-by-cvss-score/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadVulnerabilityCountByCVSSScoreReader{formats: a.formats},
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
	success, ok := result.(*ReadVulnerabilityCountByCVSSScoreOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadVulnerabilityCountByCVSSScore: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ReadVulnerabilityCountBySeverity maximums offset 9900
*/
func (a *Client) ReadVulnerabilityCountBySeverity(params *ReadVulnerabilityCountBySeverityParams, opts ...ClientOption) (*ReadVulnerabilityCountBySeverityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReadVulnerabilityCountBySeverityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ReadVulnerabilityCountBySeverity",
		Method:             "GET",
		PathPattern:        "/container-security/aggregates/vulnerabilities/count-by-severity/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ReadVulnerabilityCountBySeverityReader{formats: a.formats},
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
	success, ok := result.(*ReadVulnerabilityCountBySeverityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ReadVulnerabilityCountBySeverity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
