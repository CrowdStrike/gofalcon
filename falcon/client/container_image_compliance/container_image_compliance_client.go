// Code generated by go-swagger; DO NOT EDIT.

package container_image_compliance

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new container image compliance API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for container image compliance API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	ExtAggregateClusterAssessments(params *ExtAggregateClusterAssessmentsParams, opts ...ClientOption) (*ExtAggregateClusterAssessmentsOK, error)

	ExtAggregateFailedContainersByRulesPath(params *ExtAggregateFailedContainersByRulesPathParams, opts ...ClientOption) (*ExtAggregateFailedContainersByRulesPathOK, error)

	ExtAggregateFailedContainersCountBySeverity(params *ExtAggregateFailedContainersCountBySeverityParams, opts ...ClientOption) (*ExtAggregateFailedContainersCountBySeverityOK, error)

	ExtAggregateFailedImagesByRulesPath(params *ExtAggregateFailedImagesByRulesPathParams, opts ...ClientOption) (*ExtAggregateFailedImagesByRulesPathOK, error)

	ExtAggregateFailedImagesCountBySeverity(params *ExtAggregateFailedImagesCountBySeverityParams, opts ...ClientOption) (*ExtAggregateFailedImagesCountBySeverityOK, error)

	ExtAggregateFailedRulesByClusters(params *ExtAggregateFailedRulesByClustersParams, opts ...ClientOption) (*ExtAggregateFailedRulesByClustersOK, error)

	ExtAggregateFailedRulesByImages(params *ExtAggregateFailedRulesByImagesParams, opts ...ClientOption) (*ExtAggregateFailedRulesByImagesOK, error)

	ExtAggregateFailedRulesCountBySeverity(params *ExtAggregateFailedRulesCountBySeverityParams, opts ...ClientOption) (*ExtAggregateFailedRulesCountBySeverityOK, error)

	ExtAggregateImageAssessments(params *ExtAggregateImageAssessmentsParams, opts ...ClientOption) (*ExtAggregateImageAssessmentsOK, error)

	ExtAggregateRulesAssessments(params *ExtAggregateRulesAssessmentsParams, opts ...ClientOption) (*ExtAggregateRulesAssessmentsOK, error)

	ExtAggregateRulesByStatus(params *ExtAggregateRulesByStatusParams, opts ...ClientOption) (*ExtAggregateRulesByStatusOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
ExtAggregateClusterAssessments gets the assessments for each cluster
*/
func (a *Client) ExtAggregateClusterAssessments(params *ExtAggregateClusterAssessmentsParams, opts ...ClientOption) (*ExtAggregateClusterAssessmentsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateClusterAssessmentsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateClusterAssessments",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/compliance-by-clusters/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateClusterAssessmentsReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateClusterAssessmentsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateClusterAssessments: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExtAggregateFailedContainersByRulesPath gets the containers grouped into rules on which they failed
*/
func (a *Client) ExtAggregateFailedContainersByRulesPath(params *ExtAggregateFailedContainersByRulesPathParams, opts ...ClientOption) (*ExtAggregateFailedContainersByRulesPathOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateFailedContainersByRulesPathParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateFailedContainersByRulesPath",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/failed-containers-by-rules/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateFailedContainersByRulesPathReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateFailedContainersByRulesPathOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateFailedContainersByRulesPath: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExtAggregateFailedContainersCountBySeverity gets the failed containers count grouped into severity levels
*/
func (a *Client) ExtAggregateFailedContainersCountBySeverity(params *ExtAggregateFailedContainersCountBySeverityParams, opts ...ClientOption) (*ExtAggregateFailedContainersCountBySeverityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateFailedContainersCountBySeverityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateFailedContainersCountBySeverity",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/failed-containers-count-by-severity/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateFailedContainersCountBySeverityReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateFailedContainersCountBySeverityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateFailedContainersCountBySeverity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExtAggregateFailedImagesByRulesPath gets the images grouped into rules on which they failed
*/
func (a *Client) ExtAggregateFailedImagesByRulesPath(params *ExtAggregateFailedImagesByRulesPathParams, opts ...ClientOption) (*ExtAggregateFailedImagesByRulesPathOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateFailedImagesByRulesPathParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateFailedImagesByRulesPath",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/failed-images-by-rules/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateFailedImagesByRulesPathReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateFailedImagesByRulesPathOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateFailedImagesByRulesPath: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExtAggregateFailedImagesCountBySeverity gets the failed images count grouped into severity levels
*/
func (a *Client) ExtAggregateFailedImagesCountBySeverity(params *ExtAggregateFailedImagesCountBySeverityParams, opts ...ClientOption) (*ExtAggregateFailedImagesCountBySeverityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateFailedImagesCountBySeverityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateFailedImagesCountBySeverity",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/failed-images-count-by-severity/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateFailedImagesCountBySeverityReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateFailedImagesCountBySeverityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateFailedImagesCountBySeverity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExtAggregateFailedRulesByClusters gets the failed rules for each cluster grouped into severity levels
*/
func (a *Client) ExtAggregateFailedRulesByClusters(params *ExtAggregateFailedRulesByClustersParams, opts ...ClientOption) (*ExtAggregateFailedRulesByClustersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateFailedRulesByClustersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateFailedRulesByClusters",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/failed-rules-by-clusters/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateFailedRulesByClustersReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateFailedRulesByClustersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateFailedRulesByClusters: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExtAggregateFailedRulesByImages gets images with failed rules rule count grouped by severity for each image
*/
func (a *Client) ExtAggregateFailedRulesByImages(params *ExtAggregateFailedRulesByImagesParams, opts ...ClientOption) (*ExtAggregateFailedRulesByImagesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateFailedRulesByImagesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateFailedRulesByImages",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/failed-rules-by-images/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateFailedRulesByImagesReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateFailedRulesByImagesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateFailedRulesByImages: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExtAggregateFailedRulesCountBySeverity gets the failed rules count grouped into severity levels
*/
func (a *Client) ExtAggregateFailedRulesCountBySeverity(params *ExtAggregateFailedRulesCountBySeverityParams, opts ...ClientOption) (*ExtAggregateFailedRulesCountBySeverityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateFailedRulesCountBySeverityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateFailedRulesCountBySeverity",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/failed-rules-count-by-severity/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateFailedRulesCountBySeverityReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateFailedRulesCountBySeverityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateFailedRulesCountBySeverity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExtAggregateImageAssessments gets the assessments for each image
*/
func (a *Client) ExtAggregateImageAssessments(params *ExtAggregateImageAssessmentsParams, opts ...ClientOption) (*ExtAggregateImageAssessmentsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateImageAssessmentsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateImageAssessments",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/compliance-by-images/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateImageAssessmentsReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateImageAssessmentsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateImageAssessments: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExtAggregateRulesAssessments gets the assessments for each rule
*/
func (a *Client) ExtAggregateRulesAssessments(params *ExtAggregateRulesAssessmentsParams, opts ...ClientOption) (*ExtAggregateRulesAssessmentsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateRulesAssessmentsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateRulesAssessments",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/compliance-by-rules/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateRulesAssessmentsReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateRulesAssessmentsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateRulesAssessments: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExtAggregateRulesByStatus gets the rules grouped by their statuses
*/
func (a *Client) ExtAggregateRulesByStatus(params *ExtAggregateRulesByStatusParams, opts ...ClientOption) (*ExtAggregateRulesByStatusOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExtAggregateRulesByStatusParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "extAggregateRulesByStatus",
		Method:             "GET",
		PathPattern:        "/container-compliance/aggregates/rules-by-status/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExtAggregateRulesByStatusReader{formats: a.formats},
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
	success, ok := result.(*ExtAggregateRulesByStatusOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for extAggregateRulesByStatus: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
