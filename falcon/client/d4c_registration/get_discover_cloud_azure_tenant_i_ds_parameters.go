// Code generated by go-swagger; DO NOT EDIT.

package d4c_registration

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

// NewGetDiscoverCloudAzureTenantIDsParams creates a new GetDiscoverCloudAzureTenantIDsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetDiscoverCloudAzureTenantIDsParams() *GetDiscoverCloudAzureTenantIDsParams {
	return &GetDiscoverCloudAzureTenantIDsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetDiscoverCloudAzureTenantIDsParamsWithTimeout creates a new GetDiscoverCloudAzureTenantIDsParams object
// with the ability to set a timeout on a request.
func NewGetDiscoverCloudAzureTenantIDsParamsWithTimeout(timeout time.Duration) *GetDiscoverCloudAzureTenantIDsParams {
	return &GetDiscoverCloudAzureTenantIDsParams{
		timeout: timeout,
	}
}

// NewGetDiscoverCloudAzureTenantIDsParamsWithContext creates a new GetDiscoverCloudAzureTenantIDsParams object
// with the ability to set a context for a request.
func NewGetDiscoverCloudAzureTenantIDsParamsWithContext(ctx context.Context) *GetDiscoverCloudAzureTenantIDsParams {
	return &GetDiscoverCloudAzureTenantIDsParams{
		Context: ctx,
	}
}

// NewGetDiscoverCloudAzureTenantIDsParamsWithHTTPClient creates a new GetDiscoverCloudAzureTenantIDsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetDiscoverCloudAzureTenantIDsParamsWithHTTPClient(client *http.Client) *GetDiscoverCloudAzureTenantIDsParams {
	return &GetDiscoverCloudAzureTenantIDsParams{
		HTTPClient: client,
	}
}

/*
GetDiscoverCloudAzureTenantIDsParams contains all the parameters to send to the API endpoint

	for the get discover cloud azure tenant i ds operation.

	Typically these are written to a http.Request.
*/
type GetDiscoverCloudAzureTenantIDsParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get discover cloud azure tenant i ds params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDiscoverCloudAzureTenantIDsParams) WithDefaults() *GetDiscoverCloudAzureTenantIDsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get discover cloud azure tenant i ds params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDiscoverCloudAzureTenantIDsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get discover cloud azure tenant i ds params
func (o *GetDiscoverCloudAzureTenantIDsParams) WithTimeout(timeout time.Duration) *GetDiscoverCloudAzureTenantIDsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get discover cloud azure tenant i ds params
func (o *GetDiscoverCloudAzureTenantIDsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get discover cloud azure tenant i ds params
func (o *GetDiscoverCloudAzureTenantIDsParams) WithContext(ctx context.Context) *GetDiscoverCloudAzureTenantIDsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get discover cloud azure tenant i ds params
func (o *GetDiscoverCloudAzureTenantIDsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get discover cloud azure tenant i ds params
func (o *GetDiscoverCloudAzureTenantIDsParams) WithHTTPClient(client *http.Client) *GetDiscoverCloudAzureTenantIDsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get discover cloud azure tenant i ds params
func (o *GetDiscoverCloudAzureTenantIDsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetDiscoverCloudAzureTenantIDsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
