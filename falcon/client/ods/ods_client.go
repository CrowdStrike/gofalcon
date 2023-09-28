// Code generated by go-swagger; DO NOT EDIT.

package ods

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new ods API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for ods API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	AggregateQueryScanHostMetadata(params *AggregateQueryScanHostMetadataParams, opts ...ClientOption) (*AggregateQueryScanHostMetadataOK, error)

	AggregateScans(params *AggregateScansParams, opts ...ClientOption) (*AggregateScansOK, error)

	AggregateScheduledScans(params *AggregateScheduledScansParams, opts ...ClientOption) (*AggregateScheduledScansOK, error)

	CancelScans(params *CancelScansParams, opts ...ClientOption) (*CancelScansOK, error)

	CreateScan(params *CreateScanParams, opts ...ClientOption) (*CreateScanCreated, error)

	DeleteScheduledScans(params *DeleteScheduledScansParams, opts ...ClientOption) (*DeleteScheduledScansOK, error)

	GetMaliciousFilesByIds(params *GetMaliciousFilesByIdsParams, opts ...ClientOption) (*GetMaliciousFilesByIdsOK, error)

	GetScanHostMetadataByIds(params *GetScanHostMetadataByIdsParams, opts ...ClientOption) (*GetScanHostMetadataByIdsOK, error)

	GetScansByScanIds(params *GetScansByScanIdsParams, opts ...ClientOption) (*GetScansByScanIdsOK, error)

	GetScansByScanIdsV2(params *GetScansByScanIdsV2Params, opts ...ClientOption) (*GetScansByScanIdsV2OK, error)

	GetScheduledScansByScanIds(params *GetScheduledScansByScanIdsParams, opts ...ClientOption) (*GetScheduledScansByScanIdsOK, error)

	QueryMaliciousFiles(params *QueryMaliciousFilesParams, opts ...ClientOption) (*QueryMaliciousFilesOK, error)

	QueryScanHostMetadata(params *QueryScanHostMetadataParams, opts ...ClientOption) (*QueryScanHostMetadataOK, error)

	QueryScans(params *QueryScansParams, opts ...ClientOption) (*QueryScansOK, error)

	QueryScheduledScans(params *QueryScheduledScansParams, opts ...ClientOption) (*QueryScheduledScansOK, error)

	ScheduleScan(params *ScheduleScanParams, opts ...ClientOption) (*ScheduleScanCreated, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
AggregateQueryScanHostMetadata gets aggregates on o d s scan hosts data
*/
func (a *Client) AggregateQueryScanHostMetadata(params *AggregateQueryScanHostMetadataParams, opts ...ClientOption) (*AggregateQueryScanHostMetadataOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAggregateQueryScanHostMetadataParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "aggregate-query-scan-host-metadata",
		Method:             "POST",
		PathPattern:        "/ods/aggregates/scan-hosts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AggregateQueryScanHostMetadataReader{formats: a.formats},
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
	success, ok := result.(*AggregateQueryScanHostMetadataOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for aggregate-query-scan-host-metadata: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
AggregateScans gets aggregates on o d s scan data
*/
func (a *Client) AggregateScans(params *AggregateScansParams, opts ...ClientOption) (*AggregateScansOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAggregateScansParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "aggregate-scans",
		Method:             "POST",
		PathPattern:        "/ods/aggregates/scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AggregateScansReader{formats: a.formats},
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
	success, ok := result.(*AggregateScansOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for aggregate-scans: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
AggregateScheduledScans gets aggregates on o d s scheduled scan data
*/
func (a *Client) AggregateScheduledScans(params *AggregateScheduledScansParams, opts ...ClientOption) (*AggregateScheduledScansOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAggregateScheduledScansParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "aggregate-scheduled-scans",
		Method:             "POST",
		PathPattern:        "/ods/aggregates/scheduled-scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AggregateScheduledScansReader{formats: a.formats},
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
	success, ok := result.(*AggregateScheduledScansOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for aggregate-scheduled-scans: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CancelScans cancels o d s scans for the given scan ids
*/
func (a *Client) CancelScans(params *CancelScansParams, opts ...ClientOption) (*CancelScansOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCancelScansParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "cancel-scans",
		Method:             "POST",
		PathPattern:        "/ods/entities/scan-control-actions/cancel/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CancelScansReader{formats: a.formats},
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
	success, ok := result.(*CancelScansOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for cancel-scans: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreateScan creates o d s scan and start or schedule scan for the given scan request
*/
func (a *Client) CreateScan(params *CreateScanParams, opts ...ClientOption) (*CreateScanCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateScanParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "create-scan",
		Method:             "POST",
		PathPattern:        "/ods/entities/scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateScanReader{formats: a.formats},
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
	success, ok := result.(*CreateScanCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for create-scan: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteScheduledScans deletes o d s scheduled scans for the given scheduled scan ids
*/
func (a *Client) DeleteScheduledScans(params *DeleteScheduledScansParams, opts ...ClientOption) (*DeleteScheduledScansOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteScheduledScansParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "delete-scheduled-scans",
		Method:             "DELETE",
		PathPattern:        "/ods/entities/scheduled-scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteScheduledScansReader{formats: a.formats},
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
	success, ok := result.(*DeleteScheduledScansOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for delete-scheduled-scans: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetMaliciousFilesByIds gets malicious files by ids
*/
func (a *Client) GetMaliciousFilesByIds(params *GetMaliciousFilesByIdsParams, opts ...ClientOption) (*GetMaliciousFilesByIdsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetMaliciousFilesByIdsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "get-malicious-files-by-ids",
		Method:             "GET",
		PathPattern:        "/ods/entities/malicious-files/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetMaliciousFilesByIdsReader{formats: a.formats},
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
	success, ok := result.(*GetMaliciousFilesByIdsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get-malicious-files-by-ids: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetScanHostMetadataByIds gets scan hosts by ids
*/
func (a *Client) GetScanHostMetadataByIds(params *GetScanHostMetadataByIdsParams, opts ...ClientOption) (*GetScanHostMetadataByIdsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetScanHostMetadataByIdsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "get-scan-host-metadata-by-ids",
		Method:             "GET",
		PathPattern:        "/ods/entities/scan-hosts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetScanHostMetadataByIdsReader{formats: a.formats},
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
	success, ok := result.(*GetScanHostMetadataByIdsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get-scan-host-metadata-by-ids: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetScansByScanIds gets scans by i ds
*/
func (a *Client) GetScansByScanIds(params *GetScansByScanIdsParams, opts ...ClientOption) (*GetScansByScanIdsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetScansByScanIdsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "get-scans-by-scan-ids",
		Method:             "GET",
		PathPattern:        "/ods/entities/scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetScansByScanIdsReader{formats: a.formats},
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
	success, ok := result.(*GetScansByScanIdsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get-scans-by-scan-ids: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetScansByScanIdsV2 gets scans by i ds
*/
func (a *Client) GetScansByScanIdsV2(params *GetScansByScanIdsV2Params, opts ...ClientOption) (*GetScansByScanIdsV2OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetScansByScanIdsV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "get-scans-by-scan-ids-v2",
		Method:             "GET",
		PathPattern:        "/ods/entities/scans/v2",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetScansByScanIdsV2Reader{formats: a.formats},
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
	success, ok := result.(*GetScansByScanIdsV2OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get-scans-by-scan-ids-v2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetScheduledScansByScanIds gets scheduled scans by i ds
*/
func (a *Client) GetScheduledScansByScanIds(params *GetScheduledScansByScanIdsParams, opts ...ClientOption) (*GetScheduledScansByScanIdsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetScheduledScansByScanIdsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "get-scheduled-scans-by-scan-ids",
		Method:             "GET",
		PathPattern:        "/ods/entities/scheduled-scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetScheduledScansByScanIdsReader{formats: a.formats},
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
	success, ok := result.(*GetScheduledScansByScanIdsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get-scheduled-scans-by-scan-ids: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryMaliciousFiles queries malicious files
*/
func (a *Client) QueryMaliciousFiles(params *QueryMaliciousFilesParams, opts ...ClientOption) (*QueryMaliciousFilesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryMaliciousFilesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "query-malicious-files",
		Method:             "GET",
		PathPattern:        "/ods/queries/malicious-files/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryMaliciousFilesReader{formats: a.formats},
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
	success, ok := result.(*QueryMaliciousFilesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for query-malicious-files: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryScanHostMetadata queries scan hosts
*/
func (a *Client) QueryScanHostMetadata(params *QueryScanHostMetadataParams, opts ...ClientOption) (*QueryScanHostMetadataOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryScanHostMetadataParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "query-scan-host-metadata",
		Method:             "GET",
		PathPattern:        "/ods/queries/scan-hosts/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryScanHostMetadataReader{formats: a.formats},
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
	success, ok := result.(*QueryScanHostMetadataOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for query-scan-host-metadata: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryScans queries scans
*/
func (a *Client) QueryScans(params *QueryScansParams, opts ...ClientOption) (*QueryScansOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryScansParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "query-scans",
		Method:             "GET",
		PathPattern:        "/ods/queries/scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryScansReader{formats: a.formats},
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
	success, ok := result.(*QueryScansOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for query-scans: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryScheduledScans queries scheduled scans
*/
func (a *Client) QueryScheduledScans(params *QueryScheduledScansParams, opts ...ClientOption) (*QueryScheduledScansOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryScheduledScansParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "query-scheduled-scans",
		Method:             "GET",
		PathPattern:        "/ods/queries/scheduled-scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryScheduledScansReader{formats: a.formats},
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
	success, ok := result.(*QueryScheduledScansOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for query-scheduled-scans: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ScheduleScan creates o d s scan and start or schedule scan for the given scan request
*/
func (a *Client) ScheduleScan(params *ScheduleScanParams, opts ...ClientOption) (*ScheduleScanCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewScheduleScanParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "schedule-scan",
		Method:             "POST",
		PathPattern:        "/ods/entities/scheduled-scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ScheduleScanReader{formats: a.formats},
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
	success, ok := result.(*ScheduleScanCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for schedule-scan: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
