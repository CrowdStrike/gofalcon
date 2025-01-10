// Code generated by go-swagger; DO NOT EDIT.

package content_update_policies

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new content update policies API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for content update policies API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateContentUpdatePolicies(params *CreateContentUpdatePoliciesParams, opts ...ClientOption) (*CreateContentUpdatePoliciesCreated, error)

	DeleteContentUpdatePolicies(params *DeleteContentUpdatePoliciesParams, opts ...ClientOption) (*DeleteContentUpdatePoliciesOK, error)

	GetContentUpdatePolicies(params *GetContentUpdatePoliciesParams, opts ...ClientOption) (*GetContentUpdatePoliciesOK, error)

	PerformContentUpdatePoliciesAction(params *PerformContentUpdatePoliciesActionParams, opts ...ClientOption) (*PerformContentUpdatePoliciesActionOK, error)

	QueryCombinedContentUpdatePolicies(params *QueryCombinedContentUpdatePoliciesParams, opts ...ClientOption) (*QueryCombinedContentUpdatePoliciesOK, error)

	QueryCombinedContentUpdatePolicyMembers(params *QueryCombinedContentUpdatePolicyMembersParams, opts ...ClientOption) (*QueryCombinedContentUpdatePolicyMembersOK, error)

	QueryContentUpdatePolicies(params *QueryContentUpdatePoliciesParams, opts ...ClientOption) (*QueryContentUpdatePoliciesOK, error)

	QueryContentUpdatePolicyMembers(params *QueryContentUpdatePolicyMembersParams, opts ...ClientOption) (*QueryContentUpdatePolicyMembersOK, error)

	SetContentUpdatePoliciesPrecedence(params *SetContentUpdatePoliciesPrecedenceParams, opts ...ClientOption) (*SetContentUpdatePoliciesPrecedenceOK, error)

	UpdateContentUpdatePolicies(params *UpdateContentUpdatePoliciesParams, opts ...ClientOption) (*UpdateContentUpdatePoliciesOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CreateContentUpdatePolicies creates content update policies by specifying details about the policy to create
*/
func (a *Client) CreateContentUpdatePolicies(params *CreateContentUpdatePoliciesParams, opts ...ClientOption) (*CreateContentUpdatePoliciesCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateContentUpdatePoliciesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createContentUpdatePolicies",
		Method:             "POST",
		PathPattern:        "/policy/entities/content-update/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateContentUpdatePoliciesReader{formats: a.formats},
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
	success, ok := result.(*CreateContentUpdatePoliciesCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createContentUpdatePolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteContentUpdatePolicies deletes a set of content update policies by specifying their i ds
*/
func (a *Client) DeleteContentUpdatePolicies(params *DeleteContentUpdatePoliciesParams, opts ...ClientOption) (*DeleteContentUpdatePoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteContentUpdatePoliciesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteContentUpdatePolicies",
		Method:             "DELETE",
		PathPattern:        "/policy/entities/content-update/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteContentUpdatePoliciesReader{formats: a.formats},
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
	success, ok := result.(*DeleteContentUpdatePoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteContentUpdatePolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetContentUpdatePolicies retrieves a set of content update policies by specifying their i ds
*/
func (a *Client) GetContentUpdatePolicies(params *GetContentUpdatePoliciesParams, opts ...ClientOption) (*GetContentUpdatePoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetContentUpdatePoliciesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getContentUpdatePolicies",
		Method:             "GET",
		PathPattern:        "/policy/entities/content-update/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetContentUpdatePoliciesReader{formats: a.formats},
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
	success, ok := result.(*GetContentUpdatePoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getContentUpdatePolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
PerformContentUpdatePoliciesAction performs the specified action on the content update policies specified in the request
*/
func (a *Client) PerformContentUpdatePoliciesAction(params *PerformContentUpdatePoliciesActionParams, opts ...ClientOption) (*PerformContentUpdatePoliciesActionOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPerformContentUpdatePoliciesActionParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "performContentUpdatePoliciesAction",
		Method:             "POST",
		PathPattern:        "/policy/entities/content-update-actions/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PerformContentUpdatePoliciesActionReader{formats: a.formats},
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
	success, ok := result.(*PerformContentUpdatePoliciesActionOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for performContentUpdatePoliciesAction: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryCombinedContentUpdatePolicies searches for content update policies in your environment by providing an f q l filter and paging details returns a set of content update policies which match the filter criteria
*/
func (a *Client) QueryCombinedContentUpdatePolicies(params *QueryCombinedContentUpdatePoliciesParams, opts ...ClientOption) (*QueryCombinedContentUpdatePoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryCombinedContentUpdatePoliciesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "queryCombinedContentUpdatePolicies",
		Method:             "GET",
		PathPattern:        "/policy/combined/content-update/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryCombinedContentUpdatePoliciesReader{formats: a.formats},
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
	success, ok := result.(*QueryCombinedContentUpdatePoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for queryCombinedContentUpdatePolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryCombinedContentUpdatePolicyMembers searches for members of a content update policy in your environment by providing an f q l filter and paging details returns a set of host details which match the filter criteria
*/
func (a *Client) QueryCombinedContentUpdatePolicyMembers(params *QueryCombinedContentUpdatePolicyMembersParams, opts ...ClientOption) (*QueryCombinedContentUpdatePolicyMembersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryCombinedContentUpdatePolicyMembersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "queryCombinedContentUpdatePolicyMembers",
		Method:             "GET",
		PathPattern:        "/policy/combined/content-update-members/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryCombinedContentUpdatePolicyMembersReader{formats: a.formats},
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
	success, ok := result.(*QueryCombinedContentUpdatePolicyMembersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for queryCombinedContentUpdatePolicyMembers: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryContentUpdatePolicies searches for content update policies in your environment by providing an f q l filter and paging details returns a set of content update policy i ds which match the filter criteria
*/
func (a *Client) QueryContentUpdatePolicies(params *QueryContentUpdatePoliciesParams, opts ...ClientOption) (*QueryContentUpdatePoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryContentUpdatePoliciesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "queryContentUpdatePolicies",
		Method:             "GET",
		PathPattern:        "/policy/queries/content-update/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryContentUpdatePoliciesReader{formats: a.formats},
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
	success, ok := result.(*QueryContentUpdatePoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for queryContentUpdatePolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryContentUpdatePolicyMembers searches for members of a content update policy in your environment by providing an f q l filter and paging details returns a set of agent i ds which match the filter criteria
*/
func (a *Client) QueryContentUpdatePolicyMembers(params *QueryContentUpdatePolicyMembersParams, opts ...ClientOption) (*QueryContentUpdatePolicyMembersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryContentUpdatePolicyMembersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "queryContentUpdatePolicyMembers",
		Method:             "GET",
		PathPattern:        "/policy/queries/content-update-members/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryContentUpdatePolicyMembersReader{formats: a.formats},
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
	success, ok := result.(*QueryContentUpdatePolicyMembersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for queryContentUpdatePolicyMembers: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
SetContentUpdatePoliciesPrecedence sets the precedence of content update policies based on the order of i ds specified in the request the first ID specified will have the highest precedence and the last ID specified will have the lowest you must specify all non default policies when updating precedence
*/
func (a *Client) SetContentUpdatePoliciesPrecedence(params *SetContentUpdatePoliciesPrecedenceParams, opts ...ClientOption) (*SetContentUpdatePoliciesPrecedenceOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetContentUpdatePoliciesPrecedenceParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setContentUpdatePoliciesPrecedence",
		Method:             "POST",
		PathPattern:        "/policy/entities/content-update-precedence/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetContentUpdatePoliciesPrecedenceReader{formats: a.formats},
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
	success, ok := result.(*SetContentUpdatePoliciesPrecedenceOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setContentUpdatePoliciesPrecedence: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateContentUpdatePolicies updates content update policies by specifying the ID of the policy and details to update
*/
func (a *Client) UpdateContentUpdatePolicies(params *UpdateContentUpdatePoliciesParams, opts ...ClientOption) (*UpdateContentUpdatePoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateContentUpdatePoliciesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateContentUpdatePolicies",
		Method:             "PATCH",
		PathPattern:        "/policy/entities/content-update/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateContentUpdatePoliciesReader{formats: a.formats},
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
	success, ok := result.(*UpdateContentUpdatePoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateContentUpdatePolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
