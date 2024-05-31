// Code generated by go-swagger; DO NOT EDIT.

package cloud_snapshots

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

// NewGetCredentialsMixin0Mixin61Params creates a new GetCredentialsMixin0Mixin61Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetCredentialsMixin0Mixin61Params() *GetCredentialsMixin0Mixin61Params {
	return &GetCredentialsMixin0Mixin61Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetCredentialsMixin0Mixin61ParamsWithTimeout creates a new GetCredentialsMixin0Mixin61Params object
// with the ability to set a timeout on a request.
func NewGetCredentialsMixin0Mixin61ParamsWithTimeout(timeout time.Duration) *GetCredentialsMixin0Mixin61Params {
	return &GetCredentialsMixin0Mixin61Params{
		timeout: timeout,
	}
}

// NewGetCredentialsMixin0Mixin61ParamsWithContext creates a new GetCredentialsMixin0Mixin61Params object
// with the ability to set a context for a request.
func NewGetCredentialsMixin0Mixin61ParamsWithContext(ctx context.Context) *GetCredentialsMixin0Mixin61Params {
	return &GetCredentialsMixin0Mixin61Params{
		Context: ctx,
	}
}

// NewGetCredentialsMixin0Mixin61ParamsWithHTTPClient creates a new GetCredentialsMixin0Mixin61Params object
// with the ability to set a custom HTTPClient for a request.
func NewGetCredentialsMixin0Mixin61ParamsWithHTTPClient(client *http.Client) *GetCredentialsMixin0Mixin61Params {
	return &GetCredentialsMixin0Mixin61Params{
		HTTPClient: client,
	}
}

/*
GetCredentialsMixin0Mixin61Params contains all the parameters to send to the API endpoint

	for the get credentials mixin0 mixin61 operation.

	Typically these are written to a http.Request.
*/
type GetCredentialsMixin0Mixin61Params struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get credentials mixin0 mixin61 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCredentialsMixin0Mixin61Params) WithDefaults() *GetCredentialsMixin0Mixin61Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get credentials mixin0 mixin61 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCredentialsMixin0Mixin61Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get credentials mixin0 mixin61 params
func (o *GetCredentialsMixin0Mixin61Params) WithTimeout(timeout time.Duration) *GetCredentialsMixin0Mixin61Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get credentials mixin0 mixin61 params
func (o *GetCredentialsMixin0Mixin61Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get credentials mixin0 mixin61 params
func (o *GetCredentialsMixin0Mixin61Params) WithContext(ctx context.Context) *GetCredentialsMixin0Mixin61Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get credentials mixin0 mixin61 params
func (o *GetCredentialsMixin0Mixin61Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get credentials mixin0 mixin61 params
func (o *GetCredentialsMixin0Mixin61Params) WithHTTPClient(client *http.Client) *GetCredentialsMixin0Mixin61Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get credentials mixin0 mixin61 params
func (o *GetCredentialsMixin0Mixin61Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetCredentialsMixin0Mixin61Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
