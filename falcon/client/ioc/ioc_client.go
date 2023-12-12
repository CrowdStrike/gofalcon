// Code generated by go-swagger; DO NOT EDIT.

package ioc

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new ioc API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for ioc API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetIndicatorsReport(params *GetIndicatorsReportParams, opts ...ClientOption) (*GetIndicatorsReportOK, error)

	ActionGetV1(params *ActionGetV1Params, opts ...ClientOption) (*ActionGetV1OK, error)

	ActionQueryV1(params *ActionQueryV1Params, opts ...ClientOption) (*ActionQueryV1OK, error)

	IndicatorAggregateV1(params *IndicatorAggregateV1Params, opts ...ClientOption) (*IndicatorAggregateV1OK, error)

	IndicatorCombinedV1(params *IndicatorCombinedV1Params, opts ...ClientOption) (*IndicatorCombinedV1OK, error)

	IndicatorCreateV1(params *IndicatorCreateV1Params, opts ...ClientOption) (*IndicatorCreateV1Created, error)

	IndicatorDeleteV1(params *IndicatorDeleteV1Params, opts ...ClientOption) (*IndicatorDeleteV1OK, error)

	IndicatorGetDeviceCountV1(params *IndicatorGetDeviceCountV1Params, opts ...ClientOption) (*IndicatorGetDeviceCountV1OK, error)

	IndicatorGetDevicesRanOnV1(params *IndicatorGetDevicesRanOnV1Params, opts ...ClientOption) (*IndicatorGetDevicesRanOnV1OK, error)

	IndicatorGetProcessesRanOnV1(params *IndicatorGetProcessesRanOnV1Params, opts ...ClientOption) (*IndicatorGetProcessesRanOnV1OK, error)

	IndicatorGetV1(params *IndicatorGetV1Params, opts ...ClientOption) (*IndicatorGetV1OK, error)

	IndicatorSearchV1(params *IndicatorSearchV1Params, opts ...ClientOption) (*IndicatorSearchV1OK, error)

	IndicatorUpdateV1(params *IndicatorUpdateV1Params, opts ...ClientOption) (*IndicatorUpdateV1OK, error)

	IocTypeQueryV1(params *IocTypeQueryV1Params, opts ...ClientOption) (*IocTypeQueryV1OK, error)

	PlatformQueryV1(params *PlatformQueryV1Params, opts ...ClientOption) (*PlatformQueryV1OK, error)

	SeverityQueryV1(params *SeverityQueryV1Params, opts ...ClientOption) (*SeverityQueryV1OK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GetIndicatorsReport launches an indicators report creation job
*/
func (a *Client) GetIndicatorsReport(params *GetIndicatorsReportParams, opts ...ClientOption) (*GetIndicatorsReportOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIndicatorsReportParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetIndicatorsReport",
		Method:             "POST",
		PathPattern:        "/iocs/entities/indicators-reports/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetIndicatorsReportReader{formats: a.formats},
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
	success, ok := result.(*GetIndicatorsReportOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetIndicatorsReport: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ActionGetV1 gets actions by ids
*/
func (a *Client) ActionGetV1(params *ActionGetV1Params, opts ...ClientOption) (*ActionGetV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewActionGetV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "action.get.v1",
		Method:             "GET",
		PathPattern:        "/iocs/entities/actions/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ActionGetV1Reader{formats: a.formats},
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
	success, ok := result.(*ActionGetV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for action.get.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ActionQueryV1 queries actions
*/
func (a *Client) ActionQueryV1(params *ActionQueryV1Params, opts ...ClientOption) (*ActionQueryV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewActionQueryV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "action.query.v1",
		Method:             "GET",
		PathPattern:        "/iocs/queries/actions/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ActionQueryV1Reader{formats: a.formats},
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
	success, ok := result.(*ActionQueryV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for action.query.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IndicatorAggregateV1 gets indicators aggregates as specified via json in the request body
*/
func (a *Client) IndicatorAggregateV1(params *IndicatorAggregateV1Params, opts ...ClientOption) (*IndicatorAggregateV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIndicatorAggregateV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "indicator.aggregate.v1",
		Method:             "POST",
		PathPattern:        "/iocs/aggregates/indicators/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IndicatorAggregateV1Reader{formats: a.formats},
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
	success, ok := result.(*IndicatorAggregateV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for indicator.aggregate.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IndicatorCombinedV1 gets combined for indicators
*/
func (a *Client) IndicatorCombinedV1(params *IndicatorCombinedV1Params, opts ...ClientOption) (*IndicatorCombinedV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIndicatorCombinedV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "indicator.combined.v1",
		Method:             "GET",
		PathPattern:        "/iocs/combined/indicator/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IndicatorCombinedV1Reader{formats: a.formats},
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
	success, ok := result.(*IndicatorCombinedV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for indicator.combined.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IndicatorCreateV1 creates indicators
*/
func (a *Client) IndicatorCreateV1(params *IndicatorCreateV1Params, opts ...ClientOption) (*IndicatorCreateV1Created, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIndicatorCreateV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "indicator.create.v1",
		Method:             "POST",
		PathPattern:        "/iocs/entities/indicators/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IndicatorCreateV1Reader{formats: a.formats},
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
	success, ok := result.(*IndicatorCreateV1Created)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for indicator.create.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IndicatorDeleteV1 deletes indicators by ids
*/
func (a *Client) IndicatorDeleteV1(params *IndicatorDeleteV1Params, opts ...ClientOption) (*IndicatorDeleteV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIndicatorDeleteV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "indicator.delete.v1",
		Method:             "DELETE",
		PathPattern:        "/iocs/entities/indicators/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IndicatorDeleteV1Reader{formats: a.formats},
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
	success, ok := result.(*IndicatorDeleteV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for indicator.delete.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IndicatorGetDeviceCountV1 gets the number of devices the indicator has run on
*/
func (a *Client) IndicatorGetDeviceCountV1(params *IndicatorGetDeviceCountV1Params, opts ...ClientOption) (*IndicatorGetDeviceCountV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIndicatorGetDeviceCountV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "indicator.get.device_count.v1",
		Method:             "GET",
		PathPattern:        "/iocs/aggregates/indicators/device-count/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IndicatorGetDeviceCountV1Reader{formats: a.formats},
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
	success, ok := result.(*IndicatorGetDeviceCountV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for indicator.get.device_count.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IndicatorGetDevicesRanOnV1 gets the i ds of devices the indicator has run on
*/
func (a *Client) IndicatorGetDevicesRanOnV1(params *IndicatorGetDevicesRanOnV1Params, opts ...ClientOption) (*IndicatorGetDevicesRanOnV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIndicatorGetDevicesRanOnV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "indicator.get.devices_ran_on.v1",
		Method:             "GET",
		PathPattern:        "/iocs/queries/indicators/devices/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IndicatorGetDevicesRanOnV1Reader{formats: a.formats},
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
	success, ok := result.(*IndicatorGetDevicesRanOnV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for indicator.get.devices_ran_on.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IndicatorGetProcessesRanOnV1 gets the number of processes the indicator has run on
*/
func (a *Client) IndicatorGetProcessesRanOnV1(params *IndicatorGetProcessesRanOnV1Params, opts ...ClientOption) (*IndicatorGetProcessesRanOnV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIndicatorGetProcessesRanOnV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "indicator.get.processes_ran_on.v1",
		Method:             "GET",
		PathPattern:        "/iocs/queries/indicators/processes/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IndicatorGetProcessesRanOnV1Reader{formats: a.formats},
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
	success, ok := result.(*IndicatorGetProcessesRanOnV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for indicator.get.processes_ran_on.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IndicatorGetV1 gets indicators by ids
*/
func (a *Client) IndicatorGetV1(params *IndicatorGetV1Params, opts ...ClientOption) (*IndicatorGetV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIndicatorGetV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "indicator.get.v1",
		Method:             "GET",
		PathPattern:        "/iocs/entities/indicators/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IndicatorGetV1Reader{formats: a.formats},
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
	success, ok := result.(*IndicatorGetV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for indicator.get.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IndicatorSearchV1 searches for indicators
*/
func (a *Client) IndicatorSearchV1(params *IndicatorSearchV1Params, opts ...ClientOption) (*IndicatorSearchV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIndicatorSearchV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "indicator.search.v1",
		Method:             "GET",
		PathPattern:        "/iocs/queries/indicators/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IndicatorSearchV1Reader{formats: a.formats},
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
	success, ok := result.(*IndicatorSearchV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for indicator.search.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IndicatorUpdateV1 updates indicators
*/
func (a *Client) IndicatorUpdateV1(params *IndicatorUpdateV1Params, opts ...ClientOption) (*IndicatorUpdateV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIndicatorUpdateV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "indicator.update.v1",
		Method:             "PATCH",
		PathPattern:        "/iocs/entities/indicators/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IndicatorUpdateV1Reader{formats: a.formats},
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
	success, ok := result.(*IndicatorUpdateV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for indicator.update.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
IocTypeQueryV1 queries i o c types
*/
func (a *Client) IocTypeQueryV1(params *IocTypeQueryV1Params, opts ...ClientOption) (*IocTypeQueryV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIocTypeQueryV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "ioc_type.query.v1",
		Method:             "GET",
		PathPattern:        "/iocs/queries/ioc-types/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IocTypeQueryV1Reader{formats: a.formats},
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
	success, ok := result.(*IocTypeQueryV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ioc_type.query.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
PlatformQueryV1 queries platforms
*/
func (a *Client) PlatformQueryV1(params *PlatformQueryV1Params, opts ...ClientOption) (*PlatformQueryV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPlatformQueryV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "platform.query.v1",
		Method:             "GET",
		PathPattern:        "/iocs/queries/platforms/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PlatformQueryV1Reader{formats: a.formats},
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
	success, ok := result.(*PlatformQueryV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for platform.query.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
SeverityQueryV1 queries severities
*/
func (a *Client) SeverityQueryV1(params *SeverityQueryV1Params, opts ...ClientOption) (*SeverityQueryV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSeverityQueryV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "severity.query.v1",
		Method:             "GET",
		PathPattern:        "/iocs/queries/severities/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SeverityQueryV1Reader{formats: a.formats},
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
	success, ok := result.(*SeverityQueryV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for severity.query.v1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
