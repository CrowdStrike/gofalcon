// Code generated by go-swagger; DO NOT EDIT.

package saas_security

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

// NewIntegrationBuilderGetStatusV3Params creates a new IntegrationBuilderGetStatusV3Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIntegrationBuilderGetStatusV3Params() *IntegrationBuilderGetStatusV3Params {
	return &IntegrationBuilderGetStatusV3Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewIntegrationBuilderGetStatusV3ParamsWithTimeout creates a new IntegrationBuilderGetStatusV3Params object
// with the ability to set a timeout on a request.
func NewIntegrationBuilderGetStatusV3ParamsWithTimeout(timeout time.Duration) *IntegrationBuilderGetStatusV3Params {
	return &IntegrationBuilderGetStatusV3Params{
		timeout: timeout,
	}
}

// NewIntegrationBuilderGetStatusV3ParamsWithContext creates a new IntegrationBuilderGetStatusV3Params object
// with the ability to set a context for a request.
func NewIntegrationBuilderGetStatusV3ParamsWithContext(ctx context.Context) *IntegrationBuilderGetStatusV3Params {
	return &IntegrationBuilderGetStatusV3Params{
		Context: ctx,
	}
}

// NewIntegrationBuilderGetStatusV3ParamsWithHTTPClient creates a new IntegrationBuilderGetStatusV3Params object
// with the ability to set a custom HTTPClient for a request.
func NewIntegrationBuilderGetStatusV3ParamsWithHTTPClient(client *http.Client) *IntegrationBuilderGetStatusV3Params {
	return &IntegrationBuilderGetStatusV3Params{
		HTTPClient: client,
	}
}

/*
IntegrationBuilderGetStatusV3Params contains all the parameters to send to the API endpoint

	for the integration builder get status v3 operation.

	Typically these are written to a http.Request.
*/
type IntegrationBuilderGetStatusV3Params struct {

	/* ID.

	   Integration ID
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the integration builder get status v3 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IntegrationBuilderGetStatusV3Params) WithDefaults() *IntegrationBuilderGetStatusV3Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the integration builder get status v3 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IntegrationBuilderGetStatusV3Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the integration builder get status v3 params
func (o *IntegrationBuilderGetStatusV3Params) WithTimeout(timeout time.Duration) *IntegrationBuilderGetStatusV3Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the integration builder get status v3 params
func (o *IntegrationBuilderGetStatusV3Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the integration builder get status v3 params
func (o *IntegrationBuilderGetStatusV3Params) WithContext(ctx context.Context) *IntegrationBuilderGetStatusV3Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the integration builder get status v3 params
func (o *IntegrationBuilderGetStatusV3Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the integration builder get status v3 params
func (o *IntegrationBuilderGetStatusV3Params) WithHTTPClient(client *http.Client) *IntegrationBuilderGetStatusV3Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the integration builder get status v3 params
func (o *IntegrationBuilderGetStatusV3Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the integration builder get status v3 params
func (o *IntegrationBuilderGetStatusV3Params) WithID(id string) *IntegrationBuilderGetStatusV3Params {
	o.SetID(id)
	return o
}

// SetID adds the id to the integration builder get status v3 params
func (o *IntegrationBuilderGetStatusV3Params) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *IntegrationBuilderGetStatusV3Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param id
	qrID := o.ID
	qID := qrID
	if qID != "" {

		if err := r.SetQueryParam("id", qID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
