// Code generated by go-swagger; DO NOT EDIT.

package image_assessment_policies

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

// NewReadPoliciesParams creates a new ReadPoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewReadPoliciesParams() *ReadPoliciesParams {
	return &ReadPoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewReadPoliciesParamsWithTimeout creates a new ReadPoliciesParams object
// with the ability to set a timeout on a request.
func NewReadPoliciesParamsWithTimeout(timeout time.Duration) *ReadPoliciesParams {
	return &ReadPoliciesParams{
		timeout: timeout,
	}
}

// NewReadPoliciesParamsWithContext creates a new ReadPoliciesParams object
// with the ability to set a context for a request.
func NewReadPoliciesParamsWithContext(ctx context.Context) *ReadPoliciesParams {
	return &ReadPoliciesParams{
		Context: ctx,
	}
}

// NewReadPoliciesParamsWithHTTPClient creates a new ReadPoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewReadPoliciesParamsWithHTTPClient(client *http.Client) *ReadPoliciesParams {
	return &ReadPoliciesParams{
		HTTPClient: client,
	}
}

/*
ReadPoliciesParams contains all the parameters to send to the API endpoint

	for the read policies operation.

	Typically these are written to a http.Request.
*/
type ReadPoliciesParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the read policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadPoliciesParams) WithDefaults() *ReadPoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the read policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadPoliciesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the read policies params
func (o *ReadPoliciesParams) WithTimeout(timeout time.Duration) *ReadPoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the read policies params
func (o *ReadPoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the read policies params
func (o *ReadPoliciesParams) WithContext(ctx context.Context) *ReadPoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the read policies params
func (o *ReadPoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the read policies params
func (o *ReadPoliciesParams) WithHTTPClient(client *http.Client) *ReadPoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the read policies params
func (o *ReadPoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *ReadPoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
