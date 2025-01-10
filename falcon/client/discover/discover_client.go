// Code generated by go-swagger; DO NOT EDIT.

package discover

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new discover API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for discover API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CombinedApplications(params *CombinedApplicationsParams, opts ...ClientOption) (*CombinedApplicationsOK, error)

	CombinedHosts(params *CombinedHostsParams, opts ...ClientOption) (*CombinedHostsOK, error)

	GetAccounts(params *GetAccountsParams, opts ...ClientOption) (*GetAccountsOK, error)

	GetApplications(params *GetApplicationsParams, opts ...ClientOption) (*GetApplicationsOK, error)

	GetHosts(params *GetHostsParams, opts ...ClientOption) (*GetHostsOK, error)

	GetLogins(params *GetLoginsParams, opts ...ClientOption) (*GetLoginsOK, error)

	PostExternalAssetsInventoryV1(params *PostExternalAssetsInventoryV1Params, opts ...ClientOption) (*PostExternalAssetsInventoryV1OK, error)

	QueryAccounts(params *QueryAccountsParams, opts ...ClientOption) (*QueryAccountsOK, error)

	QueryApplications(params *QueryApplicationsParams, opts ...ClientOption) (*QueryApplicationsOK, error)

	QueryHosts(params *QueryHostsParams, opts ...ClientOption) (*QueryHostsOK, error)

	QueryLogins(params *QueryLoginsParams, opts ...ClientOption) (*QueryLoginsOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CombinedApplications searches for applications in your environment by providing an f q l filter and paging details returns details on applications which match the filter criteria
*/
func (a *Client) CombinedApplications(params *CombinedApplicationsParams, opts ...ClientOption) (*CombinedApplicationsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCombinedApplicationsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "combined-applications",
		Method:             "GET",
		PathPattern:        "/discover/combined/applications/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CombinedApplicationsReader{formats: a.formats},
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
	success, ok := result.(*CombinedApplicationsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for combined-applications: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CombinedHosts searches for assets in your environment by providing an f q l falcon query language filter and paging details returns details on assets which match the filter criteria
*/
func (a *Client) CombinedHosts(params *CombinedHostsParams, opts ...ClientOption) (*CombinedHostsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCombinedHostsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "combined-hosts",
		Method:             "GET",
		PathPattern:        "/discover/combined/hosts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CombinedHostsReader{formats: a.formats},
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
	success, ok := result.(*CombinedHostsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for combined-hosts: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetAccounts gets details on accounts by providing one or more i ds
*/
func (a *Client) GetAccounts(params *GetAccountsParams, opts ...ClientOption) (*GetAccountsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAccountsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "get-accounts",
		Method:             "GET",
		PathPattern:        "/discover/entities/accounts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAccountsReader{formats: a.formats},
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
	success, ok := result.(*GetAccountsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get-accounts: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetApplications gets details on applications by providing one or more i ds
*/
func (a *Client) GetApplications(params *GetApplicationsParams, opts ...ClientOption) (*GetApplicationsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetApplicationsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "get-applications",
		Method:             "GET",
		PathPattern:        "/discover/entities/applications/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetApplicationsReader{formats: a.formats},
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
	success, ok := result.(*GetApplicationsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get-applications: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetHosts gets details on assets by providing one or more i ds
*/
func (a *Client) GetHosts(params *GetHostsParams, opts ...ClientOption) (*GetHostsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetHostsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "get-hosts",
		Method:             "GET",
		PathPattern:        "/discover/entities/hosts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetHostsReader{formats: a.formats},
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
	success, ok := result.(*GetHostsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get-hosts: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetLogins gets details on logins by providing one or more i ds
*/
func (a *Client) GetLogins(params *GetLoginsParams, opts ...ClientOption) (*GetLoginsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetLoginsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "get-logins",
		Method:             "GET",
		PathPattern:        "/discover/entities/logins/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetLoginsReader{formats: a.formats},
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
	success, ok := result.(*GetLoginsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get-logins: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
PostExternalAssetsInventoryV1 adds external assets for external asset scanning
*/
func (a *Client) PostExternalAssetsInventoryV1(params *PostExternalAssetsInventoryV1Params, opts ...ClientOption) (*PostExternalAssetsInventoryV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostExternalAssetsInventoryV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "post-external-assets-inventory-v1",
		Method:             "POST",
		PathPattern:        "/fem/entities/external-asset-inventory/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostExternalAssetsInventoryV1Reader{formats: a.formats},
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
	success, ok := result.(*PostExternalAssetsInventoryV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for post-external-assets-inventory-v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryAccounts searches for accounts in your environment by providing an f q l falcon query language filter and paging details returns a set of account i ds which match the filter criteria
*/
func (a *Client) QueryAccounts(params *QueryAccountsParams, opts ...ClientOption) (*QueryAccountsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryAccountsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "query-accounts",
		Method:             "GET",
		PathPattern:        "/discover/queries/accounts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryAccountsReader{formats: a.formats},
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
	success, ok := result.(*QueryAccountsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for query-accounts: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryApplications searches for applications in your environment by providing an f q l filter and paging details returns a set of application i ds which match the filter criteria
*/
func (a *Client) QueryApplications(params *QueryApplicationsParams, opts ...ClientOption) (*QueryApplicationsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryApplicationsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "query-applications",
		Method:             "GET",
		PathPattern:        "/discover/queries/applications/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryApplicationsReader{formats: a.formats},
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
	success, ok := result.(*QueryApplicationsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for query-applications: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryHosts searches for assets in your environment by providing an f q l falcon query language filter and paging details returns a set of asset i ds which match the filter criteria
*/
func (a *Client) QueryHosts(params *QueryHostsParams, opts ...ClientOption) (*QueryHostsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryHostsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "query-hosts",
		Method:             "GET",
		PathPattern:        "/discover/queries/hosts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryHostsReader{formats: a.formats},
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
	success, ok := result.(*QueryHostsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for query-hosts: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryLogins searches for logins in your environment by providing an f q l falcon query language filter and paging details returns a set of login i ds which match the filter criteria
*/
func (a *Client) QueryLogins(params *QueryLoginsParams, opts ...ClientOption) (*QueryLoginsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryLoginsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "query-logins",
		Method:             "GET",
		PathPattern:        "/discover/queries/logins/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryLoginsReader{formats: a.formats},
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
	success, ok := result.(*QueryLoginsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for query-logins: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
