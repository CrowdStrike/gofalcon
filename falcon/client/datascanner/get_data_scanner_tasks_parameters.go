// Code generated by go-swagger; DO NOT EDIT.

package datascanner

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetDataScannerTasksParams creates a new GetDataScannerTasksParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetDataScannerTasksParams() *GetDataScannerTasksParams {
	return &GetDataScannerTasksParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetDataScannerTasksParamsWithTimeout creates a new GetDataScannerTasksParams object
// with the ability to set a timeout on a request.
func NewGetDataScannerTasksParamsWithTimeout(timeout time.Duration) *GetDataScannerTasksParams {
	return &GetDataScannerTasksParams{
		timeout: timeout,
	}
}

// NewGetDataScannerTasksParamsWithContext creates a new GetDataScannerTasksParams object
// with the ability to set a context for a request.
func NewGetDataScannerTasksParamsWithContext(ctx context.Context) *GetDataScannerTasksParams {
	return &GetDataScannerTasksParams{
		Context: ctx,
	}
}

// NewGetDataScannerTasksParamsWithHTTPClient creates a new GetDataScannerTasksParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetDataScannerTasksParamsWithHTTPClient(client *http.Client) *GetDataScannerTasksParams {
	return &GetDataScannerTasksParams{
		HTTPClient: client,
	}
}

/*
GetDataScannerTasksParams contains all the parameters to send to the API endpoint

	for the get data scanner tasks operation.

	Typically these are written to a http.Request.
*/
type GetDataScannerTasksParams struct {

	/* XScannerID.

	   ID of the data scanner
	*/
	XScannerID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get data scanner tasks params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDataScannerTasksParams) WithDefaults() *GetDataScannerTasksParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get data scanner tasks params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDataScannerTasksParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get data scanner tasks params
func (o *GetDataScannerTasksParams) WithTimeout(timeout time.Duration) *GetDataScannerTasksParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get data scanner tasks params
func (o *GetDataScannerTasksParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get data scanner tasks params
func (o *GetDataScannerTasksParams) WithContext(ctx context.Context) *GetDataScannerTasksParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get data scanner tasks params
func (o *GetDataScannerTasksParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get data scanner tasks params
func (o *GetDataScannerTasksParams) WithHTTPClient(client *http.Client) *GetDataScannerTasksParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get data scanner tasks params
func (o *GetDataScannerTasksParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithXScannerID adds the xScannerID to the get data scanner tasks params
func (o *GetDataScannerTasksParams) WithXScannerID(xScannerID string) *GetDataScannerTasksParams {
	o.SetXScannerID(xScannerID)
	return o
}

// SetXScannerID adds the xScannerId to the get data scanner tasks params
func (o *GetDataScannerTasksParams) SetXScannerID(xScannerID string) {
	o.XScannerID = xScannerID
}

// WriteToRequest writes these params to a swagger request
func (o *GetDataScannerTasksParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param X-Scanner-Id
	if err := r.SetHeaderParam("X-Scanner-Id", o.XScannerID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
