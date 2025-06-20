// Code generated by go-swagger; DO NOT EDIT.

package user_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new user management API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for user management API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CombinedUserRolesV2(params *CombinedUserRolesV2Params, opts ...ClientOption) (*CombinedUserRolesV2OK, error)

	CreateUser(params *CreateUserParams, opts ...ClientOption) (*CreateUserCreated, error)

	DeleteUser(params *DeleteUserParams, opts ...ClientOption) (*DeleteUserOK, error)

	GetAvailableRoleIds(params *GetAvailableRoleIdsParams, opts ...ClientOption) (*GetAvailableRoleIdsOK, error)

	GetRoles(params *GetRolesParams, opts ...ClientOption) (*GetRolesOK, error)

	GetUserRoleIds(params *GetUserRoleIdsParams, opts ...ClientOption) (*GetUserRoleIdsOK, error)

	GrantUserRoleIds(params *GrantUserRoleIdsParams, opts ...ClientOption) (*GrantUserRoleIdsOK, error)

	RetrieveEmailsByCID(params *RetrieveEmailsByCIDParams, opts ...ClientOption) (*RetrieveEmailsByCIDOK, error)

	RetrieveUserUUID(params *RetrieveUserUUIDParams, opts ...ClientOption) (*RetrieveUserUUIDOK, error)

	RetrieveUserUUIDsByCID(params *RetrieveUserUUIDsByCIDParams, opts ...ClientOption) (*RetrieveUserUUIDsByCIDOK, error)

	RevokeUserRoleIds(params *RevokeUserRoleIdsParams, opts ...ClientOption) (*RevokeUserRoleIdsOK, error)

	UpdateUser(params *UpdateUserParams, opts ...ClientOption) (*UpdateUserOK, error)

	AggregateUsersV1(params *AggregateUsersV1Params, opts ...ClientOption) (*AggregateUsersV1OK, error)

	CombinedUserRolesV1(params *CombinedUserRolesV1Params, opts ...ClientOption) (*CombinedUserRolesV1OK, error)

	CreateUserV1(params *CreateUserV1Params, opts ...ClientOption) (*CreateUserV1Created, error)

	DeleteUserV1(params *DeleteUserV1Params, opts ...ClientOption) (*DeleteUserV1OK, error)

	EntitiesRolesV1(params *EntitiesRolesV1Params, opts ...ClientOption) (*EntitiesRolesV1OK, error)

	QueriesRolesV1(params *QueriesRolesV1Params, opts ...ClientOption) (*QueriesRolesV1OK, error)

	QueryUserV1(params *QueryUserV1Params, opts ...ClientOption) (*QueryUserV1OK, error)

	RetrieveUser(params *RetrieveUserParams, opts ...ClientOption) (*RetrieveUserOK, error)

	RetrieveUsersGETV1(params *RetrieveUsersGETV1Params, opts ...ClientOption) (*RetrieveUsersGETV1OK, error)

	UpdateUserV1(params *UpdateUserV1Params, opts ...ClientOption) (*UpdateUserV1OK, error)

	UserActionV1(params *UserActionV1Params, opts ...ClientOption) (*UserActionV1OK, error)

	UserRolesActionV1(params *UserRolesActionV1Params, opts ...ClientOption) (*UserRolesActionV1OK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CombinedUserRolesV2 gets user grant s this endpoint lists both direct as well as flight control grants between a user and a customer
*/
func (a *Client) CombinedUserRolesV2(params *CombinedUserRolesV2Params, opts ...ClientOption) (*CombinedUserRolesV2OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCombinedUserRolesV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "CombinedUserRolesV2",
		Method:             "GET",
		PathPattern:        "/user-management/combined/user-roles/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CombinedUserRolesV2Reader{formats: a.formats},
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
	success, ok := result.(*CombinedUserRolesV2OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CombinedUserRolesV2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreateUser deprecateds please use p o s t user management entities users v1 create a new user after creating a user assign one or more roles with p o s t user roles entities user roles v1
*/
func (a *Client) CreateUser(params *CreateUserParams, opts ...ClientOption) (*CreateUserCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateUser",
		Method:             "POST",
		PathPattern:        "/users/entities/users/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateUserReader{formats: a.formats},
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
	success, ok := result.(*CreateUserCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteUser deprecateds please use d e l e t e user management entities users v1 delete a user permanently
*/
func (a *Client) DeleteUser(params *DeleteUserParams, opts ...ClientOption) (*DeleteUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteUser",
		Method:             "DELETE",
		PathPattern:        "/users/entities/users/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteUserReader{formats: a.formats},
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
	success, ok := result.(*DeleteUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetAvailableRoleIds deprecateds please use g e t user management queries roles v1 show role i ds for all roles available in your customer account for more information on each role provide the role ID to customer entities roles v1
*/
func (a *Client) GetAvailableRoleIds(params *GetAvailableRoleIdsParams, opts ...ClientOption) (*GetAvailableRoleIdsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAvailableRoleIdsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAvailableRoleIds",
		Method:             "GET",
		PathPattern:        "/user-roles/queries/user-role-ids-by-cid/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAvailableRoleIdsReader{formats: a.formats},
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
	success, ok := result.(*GetAvailableRoleIdsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetAvailableRoleIds: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetRoles deprecateds please use g e t user management entities roles v1 get info about a role
*/
func (a *Client) GetRoles(params *GetRolesParams, opts ...ClientOption) (*GetRolesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetRolesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetRoles",
		Method:             "GET",
		PathPattern:        "/user-roles/entities/user-roles/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetRolesReader{formats: a.formats},
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
	success, ok := result.(*GetRolesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetRoles: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetUserRoleIds deprecateds please use g e t user management combined user roles v1 show role i ds of roles assigned to a user for more information on each role provide the role ID to customer entities roles v1
*/
func (a *Client) GetUserRoleIds(params *GetUserRoleIdsParams, opts ...ClientOption) (*GetUserRoleIdsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetUserRoleIdsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetUserRoleIds",
		Method:             "GET",
		PathPattern:        "/user-roles/queries/user-role-ids-by-user-uuid/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetUserRoleIdsReader{formats: a.formats},
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
	success, ok := result.(*GetUserRoleIdsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetUserRoleIds: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GrantUserRoleIds deprecateds please use p o s t user management entities user role actions v1 assign one or more roles to a user
*/
func (a *Client) GrantUserRoleIds(params *GrantUserRoleIdsParams, opts ...ClientOption) (*GrantUserRoleIdsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGrantUserRoleIdsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GrantUserRoleIds",
		Method:             "POST",
		PathPattern:        "/user-roles/entities/user-roles/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GrantUserRoleIdsReader{formats: a.formats},
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
	success, ok := result.(*GrantUserRoleIdsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GrantUserRoleIds: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RetrieveEmailsByCID deprecateds please use p o s t user management entities users g e t v1 list the usernames usually an email address for all users in your customer account
*/
func (a *Client) RetrieveEmailsByCID(params *RetrieveEmailsByCIDParams, opts ...ClientOption) (*RetrieveEmailsByCIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRetrieveEmailsByCIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "RetrieveEmailsByCID",
		Method:             "GET",
		PathPattern:        "/users/queries/emails-by-cid/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RetrieveEmailsByCIDReader{formats: a.formats},
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
	success, ok := result.(*RetrieveEmailsByCIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for RetrieveEmailsByCID: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RetrieveUserUUID deprecateds please use g e t user management queries users v1 get a user s ID by providing a username usually an email address
*/
func (a *Client) RetrieveUserUUID(params *RetrieveUserUUIDParams, opts ...ClientOption) (*RetrieveUserUUIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRetrieveUserUUIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "RetrieveUserUUID",
		Method:             "GET",
		PathPattern:        "/users/queries/user-uuids-by-email/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RetrieveUserUUIDReader{formats: a.formats},
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
	success, ok := result.(*RetrieveUserUUIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for RetrieveUserUUID: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RetrieveUserUUIDsByCID deprecateds please use g e t user management queries users v1 list user i ds for all users in your customer account for more information on each user provide the user ID to users entities user v1
*/
func (a *Client) RetrieveUserUUIDsByCID(params *RetrieveUserUUIDsByCIDParams, opts ...ClientOption) (*RetrieveUserUUIDsByCIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRetrieveUserUUIDsByCIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "RetrieveUserUUIDsByCID",
		Method:             "GET",
		PathPattern:        "/users/queries/user-uuids-by-cid/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RetrieveUserUUIDsByCIDReader{formats: a.formats},
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
	success, ok := result.(*RetrieveUserUUIDsByCIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for RetrieveUserUUIDsByCID: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RevokeUserRoleIds deprecateds please use p o s t user management entities user role actions v1 revoke one or more roles from a user
*/
func (a *Client) RevokeUserRoleIds(params *RevokeUserRoleIdsParams, opts ...ClientOption) (*RevokeUserRoleIdsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeUserRoleIdsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "RevokeUserRoleIds",
		Method:             "DELETE",
		PathPattern:        "/user-roles/entities/user-roles/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeUserRoleIdsReader{formats: a.formats},
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
	success, ok := result.(*RevokeUserRoleIdsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for RevokeUserRoleIds: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateUser deprecateds please use p a t c h user management entities users v1 modify an existing user s first or last name
*/
func (a *Client) UpdateUser(params *UpdateUserParams, opts ...ClientOption) (*UpdateUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "UpdateUser",
		Method:             "PATCH",
		PathPattern:        "/users/entities/users/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateUserReader{formats: a.formats},
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
	success, ok := result.(*UpdateUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for UpdateUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
AggregateUsersV1 gets host aggregates as specified via json in request body
*/
func (a *Client) AggregateUsersV1(params *AggregateUsersV1Params, opts ...ClientOption) (*AggregateUsersV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAggregateUsersV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "aggregateUsersV1",
		Method:             "POST",
		PathPattern:        "/user-management/aggregates/users/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AggregateUsersV1Reader{formats: a.formats},
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
	success, ok := result.(*AggregateUsersV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for aggregateUsersV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CombinedUserRolesV1 deprecateds please use g e t user management combined user roles v2 get user grant s this endpoint lists both direct as well as flight control grants between a user and a customer
*/
func (a *Client) CombinedUserRolesV1(params *CombinedUserRolesV1Params, opts ...ClientOption) (*CombinedUserRolesV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCombinedUserRolesV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "combinedUserRolesV1",
		Method:             "GET",
		PathPattern:        "/user-management/combined/user-roles/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CombinedUserRolesV1Reader{formats: a.formats},
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
	success, ok := result.(*CombinedUserRolesV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for combinedUserRolesV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreateUserV1 creates a new user after creating a user assign one or more roles with p o s t user management entities user role actions v1
*/
func (a *Client) CreateUserV1(params *CreateUserV1Params, opts ...ClientOption) (*CreateUserV1Created, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateUserV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "createUserV1",
		Method:             "POST",
		PathPattern:        "/user-management/entities/users/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateUserV1Reader{formats: a.formats},
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
	success, ok := result.(*CreateUserV1Created)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createUserV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteUserV1 deletes a user permanently
*/
func (a *Client) DeleteUserV1(params *DeleteUserV1Params, opts ...ClientOption) (*DeleteUserV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteUserV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteUserV1",
		Method:             "DELETE",
		PathPattern:        "/user-management/entities/users/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteUserV1Reader{formats: a.formats},
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
	success, ok := result.(*DeleteUserV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteUserV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
EntitiesRolesV1 gets info about a role
*/
func (a *Client) EntitiesRolesV1(params *EntitiesRolesV1Params, opts ...ClientOption) (*EntitiesRolesV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewEntitiesRolesV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "entitiesRolesV1",
		Method:             "GET",
		PathPattern:        "/user-management/entities/roles/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &EntitiesRolesV1Reader{formats: a.formats},
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
	success, ok := result.(*EntitiesRolesV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for entitiesRolesV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueriesRolesV1 shows role i ds for all roles available in your customer account for more information on each role provide the role ID to user management entities roles v1
*/
func (a *Client) QueriesRolesV1(params *QueriesRolesV1Params, opts ...ClientOption) (*QueriesRolesV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueriesRolesV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "queriesRolesV1",
		Method:             "GET",
		PathPattern:        "/user-management/queries/roles/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueriesRolesV1Reader{formats: a.formats},
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
	success, ok := result.(*QueriesRolesV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for queriesRolesV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryUserV1 lists user i ds for all users in your customer account for more information on each user provide the user ID to user management entities users g e t v1
*/
func (a *Client) QueryUserV1(params *QueryUserV1Params, opts ...ClientOption) (*QueryUserV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryUserV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "queryUserV1",
		Method:             "GET",
		PathPattern:        "/user-management/queries/users/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryUserV1Reader{formats: a.formats},
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
	success, ok := result.(*QueryUserV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for queryUserV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RetrieveUser deprecateds please use p o s t user management entities users g e t v1 get info about a user
*/
func (a *Client) RetrieveUser(params *RetrieveUserParams, opts ...ClientOption) (*RetrieveUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRetrieveUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "retrieveUser",
		Method:             "GET",
		PathPattern:        "/users/entities/users/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RetrieveUserReader{formats: a.formats},
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
	success, ok := result.(*RetrieveUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for retrieveUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RetrieveUsersGETV1 gets info about users including their name UID and c ID by providing user u UI ds
*/
func (a *Client) RetrieveUsersGETV1(params *RetrieveUsersGETV1Params, opts ...ClientOption) (*RetrieveUsersGETV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRetrieveUsersGETV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "retrieveUsersGETV1",
		Method:             "POST",
		PathPattern:        "/user-management/entities/users/GET/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RetrieveUsersGETV1Reader{formats: a.formats},
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
	success, ok := result.(*RetrieveUsersGETV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for retrieveUsersGETV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateUserV1 modifies an existing user s first or last name
*/
func (a *Client) UpdateUserV1(params *UpdateUserV1Params, opts ...ClientOption) (*UpdateUserV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateUserV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateUserV1",
		Method:             "PATCH",
		PathPattern:        "/user-management/entities/users/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateUserV1Reader{formats: a.formats},
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
	success, ok := result.(*UpdateUserV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateUserV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UserActionV1 applies actions to one or more user available action names reset 2fa reset password user u UI ds can be provided in ids param as part of request payload
*/
func (a *Client) UserActionV1(params *UserActionV1Params, opts ...ClientOption) (*UserActionV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUserActionV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "userActionV1",
		Method:             "POST",
		PathPattern:        "/user-management/entities/user-actions/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UserActionV1Reader{formats: a.formats},
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
	success, ok := result.(*UserActionV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for userActionV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UserRolesActionV1 grants or revoke one or more role s to a user against a c ID user UUID c ID and role ID s can be provided in request payload available action s grant revoke
*/
func (a *Client) UserRolesActionV1(params *UserRolesActionV1Params, opts ...ClientOption) (*UserRolesActionV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUserRolesActionV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "userRolesActionV1",
		Method:             "POST",
		PathPattern:        "/user-management/entities/user-role-actions/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UserRolesActionV1Reader{formats: a.formats},
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
	success, ok := result.(*UserRolesActionV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for userRolesActionV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
