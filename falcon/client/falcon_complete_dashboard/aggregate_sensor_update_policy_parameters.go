// Code generated by go-swagger; DO NOT EDIT.

package falcon_complete_dashboard

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

// NewAggregateSensorUpdatePolicyParams creates a new AggregateSensorUpdatePolicyParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAggregateSensorUpdatePolicyParams() *AggregateSensorUpdatePolicyParams {
	return &AggregateSensorUpdatePolicyParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAggregateSensorUpdatePolicyParamsWithTimeout creates a new AggregateSensorUpdatePolicyParams object
// with the ability to set a timeout on a request.
func NewAggregateSensorUpdatePolicyParamsWithTimeout(timeout time.Duration) *AggregateSensorUpdatePolicyParams {
	return &AggregateSensorUpdatePolicyParams{
		timeout: timeout,
	}
}

// NewAggregateSensorUpdatePolicyParamsWithContext creates a new AggregateSensorUpdatePolicyParams object
// with the ability to set a context for a request.
func NewAggregateSensorUpdatePolicyParamsWithContext(ctx context.Context) *AggregateSensorUpdatePolicyParams {
	return &AggregateSensorUpdatePolicyParams{
		Context: ctx,
	}
}

// NewAggregateSensorUpdatePolicyParamsWithHTTPClient creates a new AggregateSensorUpdatePolicyParams object
// with the ability to set a custom HTTPClient for a request.
func NewAggregateSensorUpdatePolicyParamsWithHTTPClient(client *http.Client) *AggregateSensorUpdatePolicyParams {
	return &AggregateSensorUpdatePolicyParams{
		HTTPClient: client,
	}
}

/*
AggregateSensorUpdatePolicyParams contains all the parameters to send to the API endpoint

	for the aggregate sensor update policy operation.

	Typically these are written to a http.Request.
*/
type AggregateSensorUpdatePolicyParams struct {

	// Body.
	Body []*models.MsaAggregateQueryRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the aggregate sensor update policy params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AggregateSensorUpdatePolicyParams) WithDefaults() *AggregateSensorUpdatePolicyParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the aggregate sensor update policy params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AggregateSensorUpdatePolicyParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the aggregate sensor update policy params
func (o *AggregateSensorUpdatePolicyParams) WithTimeout(timeout time.Duration) *AggregateSensorUpdatePolicyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the aggregate sensor update policy params
func (o *AggregateSensorUpdatePolicyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the aggregate sensor update policy params
func (o *AggregateSensorUpdatePolicyParams) WithContext(ctx context.Context) *AggregateSensorUpdatePolicyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the aggregate sensor update policy params
func (o *AggregateSensorUpdatePolicyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the aggregate sensor update policy params
func (o *AggregateSensorUpdatePolicyParams) WithHTTPClient(client *http.Client) *AggregateSensorUpdatePolicyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the aggregate sensor update policy params
func (o *AggregateSensorUpdatePolicyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the aggregate sensor update policy params
func (o *AggregateSensorUpdatePolicyParams) WithBody(body []*models.MsaAggregateQueryRequest) *AggregateSensorUpdatePolicyParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the aggregate sensor update policy params
func (o *AggregateSensorUpdatePolicyParams) SetBody(body []*models.MsaAggregateQueryRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *AggregateSensorUpdatePolicyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
