// Code generated by go-swagger; DO NOT EDIT.

package quick_scan_pro

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new quick scan pro API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for quick scan pro API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	DeleteFile(params *DeleteFileParams, opts ...ClientOption) (*DeleteFileOK, error)

	DeleteScanResult(params *DeleteScanResultParams, opts ...ClientOption) (*DeleteScanResultOK, error)

	GetScanResult(params *GetScanResultParams, opts ...ClientOption) (*GetScanResultOK, error)

	LaunchScan(params *LaunchScanParams, opts ...ClientOption) (*LaunchScanOK, error)

	QueryScanResults(params *QueryScanResultsParams, opts ...ClientOption) (*QueryScanResultsOK, error)

	UploadFileMixin0Mixin93(params *UploadFileMixin0Mixin93Params, opts ...ClientOption) (*UploadFileMixin0Mixin93OK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
DeleteFile deletes file by its sha256 identifier
*/
func (a *Client) DeleteFile(params *DeleteFileParams, opts ...ClientOption) (*DeleteFileOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteFileParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteFile",
		Method:             "DELETE",
		PathPattern:        "/quickscanpro/entities/files/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteFileReader{formats: a.formats},
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
	success, ok := result.(*DeleteFileOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteFile: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteScanResult deletes the result of an quick scan pro scan
*/
func (a *Client) DeleteScanResult(params *DeleteScanResultParams, opts ...ClientOption) (*DeleteScanResultOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteScanResultParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteScanResult",
		Method:             "DELETE",
		PathPattern:        "/quickscanpro/entities/scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteScanResultReader{formats: a.formats},
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
	success, ok := result.(*DeleteScanResultOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteScanResult: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetScanResult gets the result of an quick scan pro scan
*/
func (a *Client) GetScanResult(params *GetScanResultParams, opts ...ClientOption) (*GetScanResultOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetScanResultParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetScanResult",
		Method:             "GET",
		PathPattern:        "/quickscanpro/entities/scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetScanResultReader{formats: a.formats},
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
	success, ok := result.(*GetScanResultOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetScanResult: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
LaunchScan starts scanning a file uploaded through quickscanpro entities files v1
*/
func (a *Client) LaunchScan(params *LaunchScanParams, opts ...ClientOption) (*LaunchScanOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewLaunchScanParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "LaunchScan",
		Method:             "POST",
		PathPattern:        "/quickscanpro/entities/scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &LaunchScanReader{formats: a.formats},
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
	success, ok := result.(*LaunchScanOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for LaunchScan: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
QueryScanResults fs q l query specifying the filter parameters
*/
func (a *Client) QueryScanResults(params *QueryScanResultsParams, opts ...ClientOption) (*QueryScanResultsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewQueryScanResultsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "QueryScanResults",
		Method:             "GET",
		PathPattern:        "/quickscanpro/queries/scans/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &QueryScanResultsReader{formats: a.formats},
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
	success, ok := result.(*QueryScanResultsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for QueryScanResults: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UploadFileMixin0Mixin93 uploads a file to be further analyzed with quick scan pro the samples expire according to the retention policies set
*/
func (a *Client) UploadFileMixin0Mixin93(params *UploadFileMixin0Mixin93Params, opts ...ClientOption) (*UploadFileMixin0Mixin93OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUploadFileMixin0Mixin93Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "UploadFileMixin0Mixin93",
		Method:             "POST",
		PathPattern:        "/quickscanpro/entities/files/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"multipart/form-data"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UploadFileMixin0Mixin93Reader{formats: a.formats},
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
	success, ok := result.(*UploadFileMixin0Mixin93OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for UploadFileMixin0Mixin93: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
