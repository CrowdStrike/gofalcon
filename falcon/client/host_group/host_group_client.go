// Code generated by go-swagger; DO NOT EDIT.

package host_group

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new host group API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for host group API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateHostGroups(params *CreateHostGroupsParams, opts ...ClientOption) (*CreateHostGroupsCreated, error)

	DeleteHostGroups(params *DeleteHostGroupsParams, opts ...ClientOption) (*DeleteHostGroupsOK, error)

	GetHostGroups(params *GetHostGroupsParams, opts ...ClientOption) (*GetHostGroupsOK, error)

	PerformGroupAction(params *PerformGroupActionParams, opts ...ClientOption) (*PerformGroupActionOK, error)

	QueryCombinedGroupMembers(params *QueryCombinedGroupMembersParams, opts ...ClientOption) (*QueryCombinedGroupMembersOK, error)

	QueryCombinedHostGroups(params *QueryCombinedHostGroupsParams, opts ...ClientOption) (*QueryCombinedHostGroupsOK, error)

	QueryGroupMembers(params *QueryGroupMembersParams, opts ...ClientOption) (*QueryGroupMembersOK, error)

	QueryHostGroups(params *QueryHostGroupsParams, opts ...ClientOption) (*QueryHostGroupsOK, error)

	UpdateHostGroups(params *UpdateHostGroupsParams, opts ...ClientOption) (*UpdateHostGroupsOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  CreateHostGroups creates host groups by specifying details about the group to create
*/
func (a *Client) CreateHostGroups(params *CreateHostGroupsParams, opts ...ClientOption) (*CreateHostGroupsCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateHostGroupsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createHostGroups",
		Method:             "POST",
		PathPattern:        "/devices/entities/host-groups/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateHostGroupsReader{formats: a.formats},
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
	success, ok := result.(*CreateHostGroupsCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createHostGroups: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteHostGroups deletes a set of host groups by specifying their i ds
*/
func (a *Client) DeleteHostGroups(params *DeleteHostGroupsParams, opts ...ClientOption) (*DeleteHostGroupsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteHostGroupsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteHostGroups",
		Method:             "DELETE",
		PathPattern:        "/devices/entities/host-groups/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteHostGroupsReader{formats: a.formats},
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
	success, ok := result.(*DeleteHostGroupsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteHostGroups: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetHostGroups retrieves a set of host groups by specifying their i ds
*/
func (a *Client) GetHostGroups(params *GetHostGroupsParams, opts ...ClientOption) (*GetHostGroupsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetHostGroupsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getHostGroups",
		Method:             "GET",
		PathPattern:        "/devices/entities/host-groups/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetHostGroupsReader{formats: a.formats},
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
	success, ok := result.(*GetHostGroupsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getHostGroups: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PerformGroupAction performs the specified action on the host groups specified in the request
*/
func (a *Client) PerformGroupAction(params *PerformGroupActionParams, opts ...ClientOption) (*PerformGroupActionOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPerformGroupActionParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "performGroupAction",
		Method:             "POST",
		PathPattern:        "/devices/entities/host-group-actions/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PerformGroupActionReader{formats: a.formats},
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
	success, ok := result.(*PerformGroupActionOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for performGroupAction: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  QueryCombinedGroupMembers searches for members of a host group in your environment by providing an f q l filter and paging details returns a set of host details which match the filter criteria
*/
func (a *Client) QueryCombinedGroupMembers(params *QueryCombinedGroupMembersParams, opts ...ClientOption) (*QueryCombinedGroupMembersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryCombinedGroupMembersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "queryCombinedGroupMembers",
		Method:             "GET",
		PathPattern:        "/devices/combined/host-group-members/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryCombinedGroupMembersReader{formats: a.formats},
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
	success, ok := result.(*QueryCombinedGroupMembersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for queryCombinedGroupMembers: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  QueryCombinedHostGroups searches for host groups in your environment by providing an f q l filter and paging details returns a set of host groups which match the filter criteria
*/
func (a *Client) QueryCombinedHostGroups(params *QueryCombinedHostGroupsParams, opts ...ClientOption) (*QueryCombinedHostGroupsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryCombinedHostGroupsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "queryCombinedHostGroups",
		Method:             "GET",
		PathPattern:        "/devices/combined/host-groups/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryCombinedHostGroupsReader{formats: a.formats},
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
	success, ok := result.(*QueryCombinedHostGroupsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for queryCombinedHostGroups: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  QueryGroupMembers searches for members of a host group in your environment by providing an f q l filter and paging details returns a set of agent i ds which match the filter criteria
*/
func (a *Client) QueryGroupMembers(params *QueryGroupMembersParams, opts ...ClientOption) (*QueryGroupMembersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryGroupMembersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "queryGroupMembers",
		Method:             "GET",
		PathPattern:        "/devices/queries/host-group-members/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryGroupMembersReader{formats: a.formats},
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
	success, ok := result.(*QueryGroupMembersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for queryGroupMembers: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  QueryHostGroups searches for host groups in your environment by providing an f q l filter and paging details returns a set of host group i ds which match the filter criteria
*/
func (a *Client) QueryHostGroups(params *QueryHostGroupsParams, opts ...ClientOption) (*QueryHostGroupsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryHostGroupsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "queryHostGroups",
		Method:             "GET",
		PathPattern:        "/devices/queries/host-groups/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryHostGroupsReader{formats: a.formats},
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
	success, ok := result.(*QueryHostGroupsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for queryHostGroups: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateHostGroups updates host groups by specifying the ID of the group and details to update
*/
func (a *Client) UpdateHostGroups(params *UpdateHostGroupsParams, opts ...ClientOption) (*UpdateHostGroupsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateHostGroupsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateHostGroups",
		Method:             "PATCH",
		PathPattern:        "/devices/entities/host-groups/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateHostGroupsReader{formats: a.formats},
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
	success, ok := result.(*UpdateHostGroupsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateHostGroups: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
