// Code generated by go-swagger; DO NOT EDIT.

package kubernetes_protection

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new kubernetes protection API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for kubernetes protection API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateAWSAccount(params *CreateAWSAccountParams, opts ...ClientOption) (*CreateAWSAccountCreated, *CreateAWSAccountMultiStatus, error)

	CreateAzureSubscription(params *CreateAzureSubscriptionParams, opts ...ClientOption) (*CreateAzureSubscriptionCreated, *CreateAzureSubscriptionMultiStatus, error)

	DeleteAWSAccountsMixin0(params *DeleteAWSAccountsMixin0Params, opts ...ClientOption) (*DeleteAWSAccountsMixin0OK, *DeleteAWSAccountsMixin0MultiStatus, error)

	DeleteAzureSubscription(params *DeleteAzureSubscriptionParams, opts ...ClientOption) (*DeleteAzureSubscriptionOK, *DeleteAzureSubscriptionMultiStatus, error)

	GetAWSAccountsMixin0(params *GetAWSAccountsMixin0Params, opts ...ClientOption) (*GetAWSAccountsMixin0OK, *GetAWSAccountsMixin0MultiStatus, error)

	GetAzureInstallScript(params *GetAzureInstallScriptParams, opts ...ClientOption) (*GetAzureInstallScriptOK, *GetAzureInstallScriptMultiStatus, error)

	GetAzureTenantConfig(params *GetAzureTenantConfigParams, opts ...ClientOption) (*GetAzureTenantConfigOK, *GetAzureTenantConfigMultiStatus, error)

	GetAzureTenantIDs(params *GetAzureTenantIDsParams, opts ...ClientOption) (*GetAzureTenantIDsOK, *GetAzureTenantIDsMultiStatus, error)

	GetClusters(params *GetClustersParams, opts ...ClientOption) (*GetClustersOK, *GetClustersMultiStatus, error)

	GetCombinedCloudClusters(params *GetCombinedCloudClustersParams, opts ...ClientOption) (*GetCombinedCloudClustersOK, *GetCombinedCloudClustersMultiStatus, error)

	GetHelmValuesYaml(params *GetHelmValuesYamlParams, opts ...ClientOption) (*GetHelmValuesYamlOK, error)

	GetLocations(params *GetLocationsParams, opts ...ClientOption) (*GetLocationsOK, *GetLocationsMultiStatus, error)

	GetStaticScripts(params *GetStaticScriptsParams, opts ...ClientOption) (*GetStaticScriptsOK, *GetStaticScriptsMultiStatus, error)

	ListAzureAccounts(params *ListAzureAccountsParams, opts ...ClientOption) (*ListAzureAccountsOK, *ListAzureAccountsMultiStatus, error)

	PatchAzureServicePrincipal(params *PatchAzureServicePrincipalParams, opts ...ClientOption) (*PatchAzureServicePrincipalCreated, *PatchAzureServicePrincipalMultiStatus, error)

	RegenerateAPIKey(params *RegenerateAPIKeyParams, opts ...ClientOption) (*RegenerateAPIKeyOK, *RegenerateAPIKeyMultiStatus, error)

	TriggerScan(params *TriggerScanParams, opts ...ClientOption) (*TriggerScanCreated, *TriggerScanMultiStatus, error)

	UpdateAWSAccount(params *UpdateAWSAccountParams, opts ...ClientOption) (*UpdateAWSAccountOK, *UpdateAWSAccountMultiStatus, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  CreateAWSAccount creates a new a w s account in our system for a customer and generates the installation script
*/
func (a *Client) CreateAWSAccount(params *CreateAWSAccountParams, opts ...ClientOption) (*CreateAWSAccountCreated, *CreateAWSAccountMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateAWSAccountParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateAWSAccount",
		Method:             "POST",
		PathPattern:        "/kubernetes-protection/entities/accounts/aws/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateAWSAccountReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *CreateAWSAccountCreated:
		return value, nil, nil
	case *CreateAWSAccountMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  CreateAzureSubscription creates a new azure subscription in our system
*/
func (a *Client) CreateAzureSubscription(params *CreateAzureSubscriptionParams, opts ...ClientOption) (*CreateAzureSubscriptionCreated, *CreateAzureSubscriptionMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateAzureSubscriptionParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateAzureSubscription",
		Method:             "POST",
		PathPattern:        "/kubernetes-protection/entities/accounts/azure/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateAzureSubscriptionReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *CreateAzureSubscriptionCreated:
		return value, nil, nil
	case *CreateAzureSubscriptionMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteAWSAccountsMixin0 deletes a w s accounts
*/
func (a *Client) DeleteAWSAccountsMixin0(params *DeleteAWSAccountsMixin0Params, opts ...ClientOption) (*DeleteAWSAccountsMixin0OK, *DeleteAWSAccountsMixin0MultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteAWSAccountsMixin0Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteAWSAccountsMixin0",
		Method:             "DELETE",
		PathPattern:        "/kubernetes-protection/entities/accounts/aws/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteAWSAccountsMixin0Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *DeleteAWSAccountsMixin0OK:
		return value, nil, nil
	case *DeleteAWSAccountsMixin0MultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteAzureSubscription deletes a new azure subscription in our system
*/
func (a *Client) DeleteAzureSubscription(params *DeleteAzureSubscriptionParams, opts ...ClientOption) (*DeleteAzureSubscriptionOK, *DeleteAzureSubscriptionMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteAzureSubscriptionParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteAzureSubscription",
		Method:             "DELETE",
		PathPattern:        "/kubernetes-protection/entities/accounts/azure/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteAzureSubscriptionReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *DeleteAzureSubscriptionOK:
		return value, nil, nil
	case *DeleteAzureSubscriptionMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetAWSAccountsMixin0 provides a list of a w s accounts
*/
func (a *Client) GetAWSAccountsMixin0(params *GetAWSAccountsMixin0Params, opts ...ClientOption) (*GetAWSAccountsMixin0OK, *GetAWSAccountsMixin0MultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAWSAccountsMixin0Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAWSAccountsMixin0",
		Method:             "GET",
		PathPattern:        "/kubernetes-protection/entities/accounts/aws/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAWSAccountsMixin0Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *GetAWSAccountsMixin0OK:
		return value, nil, nil
	case *GetAWSAccountsMixin0MultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetAzureInstallScript provides the script to run for a given tenant id and subscription i ds
*/
func (a *Client) GetAzureInstallScript(params *GetAzureInstallScriptParams, opts ...ClientOption) (*GetAzureInstallScriptOK, *GetAzureInstallScriptMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAzureInstallScriptParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAzureInstallScript",
		Method:             "GET",
		PathPattern:        "/kubernetes-protection/entities/user-script/azure/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAzureInstallScriptReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *GetAzureInstallScriptOK:
		return value, nil, nil
	case *GetAzureInstallScriptMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetAzureTenantConfig gets the azure tenant config
*/
func (a *Client) GetAzureTenantConfig(params *GetAzureTenantConfigParams, opts ...ClientOption) (*GetAzureTenantConfigOK, *GetAzureTenantConfigMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAzureTenantConfigParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAzureTenantConfig",
		Method:             "GET",
		PathPattern:        "/kubernetes-protection/entities/config/azure/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAzureTenantConfigReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *GetAzureTenantConfigOK:
		return value, nil, nil
	case *GetAzureTenantConfigMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetAzureTenantIDs provides all the azure subscriptions and tenants
*/
func (a *Client) GetAzureTenantIDs(params *GetAzureTenantIDsParams, opts ...ClientOption) (*GetAzureTenantIDsOK, *GetAzureTenantIDsMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAzureTenantIDsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAzureTenantIDs",
		Method:             "GET",
		PathPattern:        "/kubernetes-protection/entities/tenants/azure/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAzureTenantIDsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *GetAzureTenantIDsOK:
		return value, nil, nil
	case *GetAzureTenantIDsMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetClusters provides the clusters acknowledged by the kubernetes protection service
*/
func (a *Client) GetClusters(params *GetClustersParams, opts ...ClientOption) (*GetClustersOK, *GetClustersMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetClustersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetClusters",
		Method:             "GET",
		PathPattern:        "/kubernetes-protection/entities/kubernetes/clusters/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetClustersReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *GetClustersOK:
		return value, nil, nil
	case *GetClustersMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetCombinedCloudClusters returns a combined list of provisioned cloud accounts and known kubernetes clusters
*/
func (a *Client) GetCombinedCloudClusters(params *GetCombinedCloudClustersParams, opts ...ClientOption) (*GetCombinedCloudClustersOK, *GetCombinedCloudClustersMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetCombinedCloudClustersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetCombinedCloudClusters",
		Method:             "GET",
		PathPattern:        "/kubernetes-protection/entities/cloud_cluster/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetCombinedCloudClustersReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *GetCombinedCloudClustersOK:
		return value, nil, nil
	case *GetCombinedCloudClustersMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetHelmValuesYaml provides a sample helm values yaml file for a customer to install alongside the agent helm chart
*/
func (a *Client) GetHelmValuesYaml(params *GetHelmValuesYamlParams, opts ...ClientOption) (*GetHelmValuesYamlOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetHelmValuesYamlParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetHelmValuesYaml",
		Method:             "GET",
		PathPattern:        "/kubernetes-protection/entities/integration/agent/v1",
		ProducesMediaTypes: []string{"application/yaml"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetHelmValuesYamlReader{formats: a.formats},
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
	success, ok := result.(*GetHelmValuesYamlOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetHelmValuesYaml: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetLocations provides the cloud locations acknowledged by the kubernetes protection service
*/
func (a *Client) GetLocations(params *GetLocationsParams, opts ...ClientOption) (*GetLocationsOK, *GetLocationsMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetLocationsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetLocations",
		Method:             "GET",
		PathPattern:        "/kubernetes-protection/entities/cloud-locations/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetLocationsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *GetLocationsOK:
		return value, nil, nil
	case *GetLocationsMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetStaticScripts gets static bash scripts that are used during registration
*/
func (a *Client) GetStaticScripts(params *GetStaticScriptsParams, opts ...ClientOption) (*GetStaticScriptsOK, *GetStaticScriptsMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetStaticScriptsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetStaticScripts",
		Method:             "GET",
		PathPattern:        "/kubernetes-protection/entities/gen/scripts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetStaticScriptsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *GetStaticScriptsOK:
		return value, nil, nil
	case *GetStaticScriptsMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListAzureAccounts provides the azure subscriptions registered to kubernetes protection
*/
func (a *Client) ListAzureAccounts(params *ListAzureAccountsParams, opts ...ClientOption) (*ListAzureAccountsOK, *ListAzureAccountsMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListAzureAccountsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ListAzureAccounts",
		Method:             "GET",
		PathPattern:        "/kubernetes-protection/entities/accounts/azure/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListAzureAccountsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *ListAzureAccountsOK:
		return value, nil, nil
	case *ListAzureAccountsMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchAzureServicePrincipal adds the client ID for the given tenant ID to our system
*/
func (a *Client) PatchAzureServicePrincipal(params *PatchAzureServicePrincipalParams, opts ...ClientOption) (*PatchAzureServicePrincipalCreated, *PatchAzureServicePrincipalMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchAzureServicePrincipalParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PatchAzureServicePrincipal",
		Method:             "PATCH",
		PathPattern:        "/kubernetes-protection/entities/service-principal/azure/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PatchAzureServicePrincipalReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *PatchAzureServicePrincipalCreated:
		return value, nil, nil
	case *PatchAzureServicePrincipalMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RegenerateAPIKey regenerates API key for docker registry integrations
*/
func (a *Client) RegenerateAPIKey(params *RegenerateAPIKeyParams, opts ...ClientOption) (*RegenerateAPIKeyOK, *RegenerateAPIKeyMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRegenerateAPIKeyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "RegenerateAPIKey",
		Method:             "POST",
		PathPattern:        "/kubernetes-protection/entities/integration/api-key/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RegenerateAPIKeyReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *RegenerateAPIKeyOK:
		return value, nil, nil
	case *RegenerateAPIKeyMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  TriggerScan triggers a dry run or a full scan of a customer s kubernetes footprint
*/
func (a *Client) TriggerScan(params *TriggerScanParams, opts ...ClientOption) (*TriggerScanCreated, *TriggerScanMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewTriggerScanParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "TriggerScan",
		Method:             "POST",
		PathPattern:        "/kubernetes-protection/entities/scan/trigger/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &TriggerScanReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *TriggerScanCreated:
		return value, nil, nil
	case *TriggerScanMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateAWSAccount updates the a w s account per the query parameters provided
*/
func (a *Client) UpdateAWSAccount(params *UpdateAWSAccountParams, opts ...ClientOption) (*UpdateAWSAccountOK, *UpdateAWSAccountMultiStatus, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateAWSAccountParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "UpdateAWSAccount",
		Method:             "PATCH",
		PathPattern:        "/kubernetes-protection/entities/accounts/aws/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/octet-stream"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateAWSAccountReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *UpdateAWSAccountOK:
		return value, nil, nil
	case *UpdateAWSAccountMultiStatus:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for kubernetes_protection: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
