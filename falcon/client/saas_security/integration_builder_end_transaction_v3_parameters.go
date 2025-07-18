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

// NewIntegrationBuilderEndTransactionV3Params creates a new IntegrationBuilderEndTransactionV3Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIntegrationBuilderEndTransactionV3Params() *IntegrationBuilderEndTransactionV3Params {
	return &IntegrationBuilderEndTransactionV3Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewIntegrationBuilderEndTransactionV3ParamsWithTimeout creates a new IntegrationBuilderEndTransactionV3Params object
// with the ability to set a timeout on a request.
func NewIntegrationBuilderEndTransactionV3ParamsWithTimeout(timeout time.Duration) *IntegrationBuilderEndTransactionV3Params {
	return &IntegrationBuilderEndTransactionV3Params{
		timeout: timeout,
	}
}

// NewIntegrationBuilderEndTransactionV3ParamsWithContext creates a new IntegrationBuilderEndTransactionV3Params object
// with the ability to set a context for a request.
func NewIntegrationBuilderEndTransactionV3ParamsWithContext(ctx context.Context) *IntegrationBuilderEndTransactionV3Params {
	return &IntegrationBuilderEndTransactionV3Params{
		Context: ctx,
	}
}

// NewIntegrationBuilderEndTransactionV3ParamsWithHTTPClient creates a new IntegrationBuilderEndTransactionV3Params object
// with the ability to set a custom HTTPClient for a request.
func NewIntegrationBuilderEndTransactionV3ParamsWithHTTPClient(client *http.Client) *IntegrationBuilderEndTransactionV3Params {
	return &IntegrationBuilderEndTransactionV3Params{
		HTTPClient: client,
	}
}

/*
IntegrationBuilderEndTransactionV3Params contains all the parameters to send to the API endpoint

	for the integration builder end transaction v3 operation.

	Typically these are written to a http.Request.
*/
type IntegrationBuilderEndTransactionV3Params struct {

	/* ID.

	   Integration ID
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the integration builder end transaction v3 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IntegrationBuilderEndTransactionV3Params) WithDefaults() *IntegrationBuilderEndTransactionV3Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the integration builder end transaction v3 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IntegrationBuilderEndTransactionV3Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the integration builder end transaction v3 params
func (o *IntegrationBuilderEndTransactionV3Params) WithTimeout(timeout time.Duration) *IntegrationBuilderEndTransactionV3Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the integration builder end transaction v3 params
func (o *IntegrationBuilderEndTransactionV3Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the integration builder end transaction v3 params
func (o *IntegrationBuilderEndTransactionV3Params) WithContext(ctx context.Context) *IntegrationBuilderEndTransactionV3Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the integration builder end transaction v3 params
func (o *IntegrationBuilderEndTransactionV3Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the integration builder end transaction v3 params
func (o *IntegrationBuilderEndTransactionV3Params) WithHTTPClient(client *http.Client) *IntegrationBuilderEndTransactionV3Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the integration builder end transaction v3 params
func (o *IntegrationBuilderEndTransactionV3Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the integration builder end transaction v3 params
func (o *IntegrationBuilderEndTransactionV3Params) WithID(id string) *IntegrationBuilderEndTransactionV3Params {
	o.SetID(id)
	return o
}

// SetID adds the id to the integration builder end transaction v3 params
func (o *IntegrationBuilderEndTransactionV3Params) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *IntegrationBuilderEndTransactionV3Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
