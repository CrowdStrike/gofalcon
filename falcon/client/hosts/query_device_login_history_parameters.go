// Code generated by go-swagger; DO NOT EDIT.

package hosts

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

	"github.com/aslape/gofalcon/falcon/models"
)

// NewQueryDeviceLoginHistoryParams creates a new QueryDeviceLoginHistoryParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryDeviceLoginHistoryParams() *QueryDeviceLoginHistoryParams {
	return &QueryDeviceLoginHistoryParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryDeviceLoginHistoryParamsWithTimeout creates a new QueryDeviceLoginHistoryParams object
// with the ability to set a timeout on a request.
func NewQueryDeviceLoginHistoryParamsWithTimeout(timeout time.Duration) *QueryDeviceLoginHistoryParams {
	return &QueryDeviceLoginHistoryParams{
		timeout: timeout,
	}
}

// NewQueryDeviceLoginHistoryParamsWithContext creates a new QueryDeviceLoginHistoryParams object
// with the ability to set a context for a request.
func NewQueryDeviceLoginHistoryParamsWithContext(ctx context.Context) *QueryDeviceLoginHistoryParams {
	return &QueryDeviceLoginHistoryParams{
		Context: ctx,
	}
}

// NewQueryDeviceLoginHistoryParamsWithHTTPClient creates a new QueryDeviceLoginHistoryParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryDeviceLoginHistoryParamsWithHTTPClient(client *http.Client) *QueryDeviceLoginHistoryParams {
	return &QueryDeviceLoginHistoryParams{
		HTTPClient: client,
	}
}

/*
QueryDeviceLoginHistoryParams contains all the parameters to send to the API endpoint

	for the query device login history operation.

	Typically these are written to a http.Request.
*/
type QueryDeviceLoginHistoryParams struct {

	// Body.
	Body *models.MsaIdsRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query device login history params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryDeviceLoginHistoryParams) WithDefaults() *QueryDeviceLoginHistoryParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query device login history params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryDeviceLoginHistoryParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query device login history params
func (o *QueryDeviceLoginHistoryParams) WithTimeout(timeout time.Duration) *QueryDeviceLoginHistoryParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query device login history params
func (o *QueryDeviceLoginHistoryParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query device login history params
func (o *QueryDeviceLoginHistoryParams) WithContext(ctx context.Context) *QueryDeviceLoginHistoryParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query device login history params
func (o *QueryDeviceLoginHistoryParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query device login history params
func (o *QueryDeviceLoginHistoryParams) WithHTTPClient(client *http.Client) *QueryDeviceLoginHistoryParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query device login history params
func (o *QueryDeviceLoginHistoryParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the query device login history params
func (o *QueryDeviceLoginHistoryParams) WithBody(body *models.MsaIdsRequest) *QueryDeviceLoginHistoryParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the query device login history params
func (o *QueryDeviceLoginHistoryParams) SetBody(body *models.MsaIdsRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *QueryDeviceLoginHistoryParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
