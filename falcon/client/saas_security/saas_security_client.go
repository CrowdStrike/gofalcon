// Code generated by go-swagger; DO NOT EDIT.

package saas_security

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new saas security API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for saas security API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	DismissAffectedEntityV3(params *DismissAffectedEntityV3Params, opts ...ClientOption) (*DismissAffectedEntityV3OK, error)

	DismissSecurityCheckV3(params *DismissSecurityCheckV3Params, opts ...ClientOption) (*DismissSecurityCheckV3OK, error)

	GetActivityMonitorV3(params *GetActivityMonitorV3Params, opts ...ClientOption) (*GetActivityMonitorV3OK, error)

	GetAlertsV3(params *GetAlertsV3Params, opts ...ClientOption) (*GetAlertsV3OK, error)

	GetDeviceInventoryV3(params *GetDeviceInventoryV3Params, opts ...ClientOption) (*GetDeviceInventoryV3OK, error)

	GetIntegrationsV3(params *GetIntegrationsV3Params, opts ...ClientOption) (*GetIntegrationsV3OK, error)

	GetMetricsV3(params *GetMetricsV3Params, opts ...ClientOption) (*GetMetricsV3OK, error)

	GetSecurityCheckAffectedV3(params *GetSecurityCheckAffectedV3Params, opts ...ClientOption) (*GetSecurityCheckAffectedV3OK, error)

	GetSecurityCheckComplianceV3(params *GetSecurityCheckComplianceV3Params, opts ...ClientOption) (*GetSecurityCheckComplianceV3OK, error)

	GetSecurityChecksV3(params *GetSecurityChecksV3Params, opts ...ClientOption) (*GetSecurityChecksV3OK, error)

	GetSupportedSaasV3(params *GetSupportedSaasV3Params, opts ...ClientOption) (*GetSupportedSaasV3OK, error)

	GetSystemLogsV3(params *GetSystemLogsV3Params, opts ...ClientOption) (*GetSystemLogsV3OK, error)

	GetSystemUsersV3(params *GetSystemUsersV3Params, opts ...ClientOption) (*GetSystemUsersV3OK, error)

	GetUserInventoryV3(params *GetUserInventoryV3Params, opts ...ClientOption) (*GetUserInventoryV3OK, error)

	IntegrationBuilderEndTransactionV3(params *IntegrationBuilderEndTransactionV3Params, opts ...ClientOption) (*IntegrationBuilderEndTransactionV3OK, error)

	IntegrationBuilderGetStatusV3(params *IntegrationBuilderGetStatusV3Params, opts ...ClientOption) (*IntegrationBuilderGetStatusV3OK, error)

	IntegrationBuilderResetV3(params *IntegrationBuilderResetV3Params, opts ...ClientOption) (*IntegrationBuilderResetV3OK, error)

	IntegrationBuilderUploadV3(params *IntegrationBuilderUploadV3Params, opts ...ClientOption) (*IntegrationBuilderUploadV3OK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
DismissAffectedEntityV3 ps o s t dismiss affected entity

Preform dismiss to an affected entity in a security check
*/
func (a *Client) DismissAffectedEntityV3(params *DismissAffectedEntityV3Params, opts ...ClientOption) (*DismissAffectedEntityV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDismissAffectedEntityV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "DismissAffectedEntityV3",
		Method:             "POST",
		PathPattern:        "/saas-security/entities/check-dismiss-affected/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DismissAffectedEntityV3Reader{formats: a.formats},
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
	success, ok := result.(*DismissAffectedEntityV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DismissAffectedEntityV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DismissSecurityCheckV3 ps o s t dismiss security check by ID

Perform dismiss to a security check
*/
func (a *Client) DismissSecurityCheckV3(params *DismissSecurityCheckV3Params, opts ...ClientOption) (*DismissSecurityCheckV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDismissSecurityCheckV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "DismissSecurityCheckV3",
		Method:             "POST",
		PathPattern:        "/saas-security/entities/check-dismiss/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DismissSecurityCheckV3Reader{formats: a.formats},
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
	success, ok := result.(*DismissSecurityCheckV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DismissSecurityCheckV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetActivityMonitorV3 gs e t activity monitor

Get a list of all events in monitor
*/
func (a *Client) GetActivityMonitorV3(params *GetActivityMonitorV3Params, opts ...ClientOption) (*GetActivityMonitorV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetActivityMonitorV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetActivityMonitorV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/monitor/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetActivityMonitorV3Reader{formats: a.formats},
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
	success, ok := result.(*GetActivityMonitorV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetActivityMonitorV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetAlertsV3 gs e t alert by ID or g e t alerts

Get a data on a specific alert or get a list of all alerts
*/
func (a *Client) GetAlertsV3(params *GetAlertsV3Params, opts ...ClientOption) (*GetAlertsV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAlertsV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAlertsV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/alerts/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAlertsV3Reader{formats: a.formats},
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
	success, ok := result.(*GetAlertsV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetAlertsV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetDeviceInventoryV3 gs e t device inventory

Get a list of all devices
*/
func (a *Client) GetDeviceInventoryV3(params *GetDeviceInventoryV3Params, opts ...ClientOption) (*GetDeviceInventoryV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetDeviceInventoryV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetDeviceInventoryV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/devices/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetDeviceInventoryV3Reader{formats: a.formats},
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
	success, ok := result.(*GetDeviceInventoryV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetDeviceInventoryV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetIntegrationsV3 gs e t integrations

Get a list of connected integrations in your account
*/
func (a *Client) GetIntegrationsV3(params *GetIntegrationsV3Params, opts ...ClientOption) (*GetIntegrationsV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIntegrationsV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetIntegrationsV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/integrations/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetIntegrationsV3Reader{formats: a.formats},
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
	success, ok := result.(*GetIntegrationsV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetIntegrationsV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetMetricsV3 gs e t metrics

Get metrics on security checks
*/
func (a *Client) GetMetricsV3(params *GetMetricsV3Params, opts ...ClientOption) (*GetMetricsV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetMetricsV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetMetricsV3",
		Method:             "GET",
		PathPattern:        "/saas-security/aggregates/check-metrics/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetMetricsV3Reader{formats: a.formats},
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
	success, ok := result.(*GetMetricsV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetMetricsV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetSecurityCheckAffectedV3 gs e t security check affected

Get a list of affected entities
*/
func (a *Client) GetSecurityCheckAffectedV3(params *GetSecurityCheckAffectedV3Params, opts ...ClientOption) (*GetSecurityCheckAffectedV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetSecurityCheckAffectedV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetSecurityCheckAffectedV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/check-affected/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetSecurityCheckAffectedV3Reader{formats: a.formats},
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
	success, ok := result.(*GetSecurityCheckAffectedV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetSecurityCheckAffectedV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetSecurityCheckComplianceV3 gs e t compliance

Get a list of compliance standards attached to a check
*/
func (a *Client) GetSecurityCheckComplianceV3(params *GetSecurityCheckComplianceV3Params, opts ...ClientOption) (*GetSecurityCheckComplianceV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetSecurityCheckComplianceV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetSecurityCheckComplianceV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/compliance/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetSecurityCheckComplianceV3Reader{formats: a.formats},
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
	success, ok := result.(*GetSecurityCheckComplianceV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetSecurityCheckComplianceV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetSecurityChecksV3 gs e t security check by ID or g e t list security checks

Get a specific security check by ID or Get all security checks
*/
func (a *Client) GetSecurityChecksV3(params *GetSecurityChecksV3Params, opts ...ClientOption) (*GetSecurityChecksV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetSecurityChecksV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetSecurityChecksV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/checks/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetSecurityChecksV3Reader{formats: a.formats},
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
	success, ok := result.(*GetSecurityChecksV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetSecurityChecksV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetSupportedSaasV3 gs e t supported saa s

Get a list of supported integrations
*/
func (a *Client) GetSupportedSaasV3(params *GetSupportedSaasV3Params, opts ...ClientOption) (*GetSupportedSaasV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetSupportedSaasV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetSupportedSaasV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/supported-saas/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetSupportedSaasV3Reader{formats: a.formats},
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
	success, ok := result.(*GetSupportedSaasV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetSupportedSaasV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetSystemLogsV3 gs e t system logs

Get a list of all system logs
*/
func (a *Client) GetSystemLogsV3(params *GetSystemLogsV3Params, opts ...ClientOption) (*GetSystemLogsV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetSystemLogsV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetSystemLogsV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/system-logs/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetSystemLogsV3Reader{formats: a.formats},
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
	success, ok := result.(*GetSystemLogsV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetSystemLogsV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetSystemUsersV3 gs e t system users

Get a list of system users
*/
func (a *Client) GetSystemUsersV3(params *GetSystemUsersV3Params, opts ...ClientOption) (*GetSystemUsersV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetSystemUsersV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetSystemUsersV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/system-users/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetSystemUsersV3Reader{formats: a.formats},
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
	success, ok := result.(*GetSystemUsersV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetSystemUsersV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetUserInventoryV3 gs e t user inventory

Get a list of all users
*/
func (a *Client) GetUserInventoryV3(params *GetUserInventoryV3Params, opts ...ClientOption) (*GetUserInventoryV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetUserInventoryV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetUserInventoryV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/users/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetUserInventoryV3Reader{formats: a.formats},
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
	success, ok := result.(*GetUserInventoryV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetUserInventoryV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IntegrationBuilderEndTransactionV3 ps o s t data upload transaction completion

Make a close transaction call after uploading the data
*/
func (a *Client) IntegrationBuilderEndTransactionV3(params *IntegrationBuilderEndTransactionV3Params, opts ...ClientOption) (*IntegrationBuilderEndTransactionV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIntegrationBuilderEndTransactionV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "IntegrationBuilderEndTransactionV3",
		Method:             "POST",
		PathPattern:        "/saas-security/entities/custom-integration-close/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IntegrationBuilderEndTransactionV3Reader{formats: a.formats},
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
	success, ok := result.(*IntegrationBuilderEndTransactionV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for IntegrationBuilderEndTransactionV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IntegrationBuilderGetStatusV3 gs e t status

Get transaction status for a custom integration
*/
func (a *Client) IntegrationBuilderGetStatusV3(params *IntegrationBuilderGetStatusV3Params, opts ...ClientOption) (*IntegrationBuilderGetStatusV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIntegrationBuilderGetStatusV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "IntegrationBuilderGetStatusV3",
		Method:             "GET",
		PathPattern:        "/saas-security/entities/custom-integration-status/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IntegrationBuilderGetStatusV3Reader{formats: a.formats},
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
	success, ok := result.(*IntegrationBuilderGetStatusV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for IntegrationBuilderGetStatusV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IntegrationBuilderResetV3 resets

Make a reset call to a custom integration
*/
func (a *Client) IntegrationBuilderResetV3(params *IntegrationBuilderResetV3Params, opts ...ClientOption) (*IntegrationBuilderResetV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIntegrationBuilderResetV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "IntegrationBuilderResetV3",
		Method:             "POST",
		PathPattern:        "/saas-security/entities/custom-integration-reset/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IntegrationBuilderResetV3Reader{formats: a.formats},
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
	success, ok := result.(*IntegrationBuilderResetV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for IntegrationBuilderResetV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IntegrationBuilderUploadV3 ps o s t upload

Send data to a specific source in a custom integration
*/
func (a *Client) IntegrationBuilderUploadV3(params *IntegrationBuilderUploadV3Params, opts ...ClientOption) (*IntegrationBuilderUploadV3OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIntegrationBuilderUploadV3Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "IntegrationBuilderUploadV3",
		Method:             "POST",
		PathPattern:        "/saas-security/entities/custom-integration-upload/v3",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IntegrationBuilderUploadV3Reader{formats: a.formats},
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
	success, ok := result.(*IntegrationBuilderUploadV3OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for IntegrationBuilderUploadV3: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
