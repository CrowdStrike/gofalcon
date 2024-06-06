// Code generated by go-swagger; DO NOT EDIT.

package message_center

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

// NewAggregateCasesParams creates a new AggregateCasesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAggregateCasesParams() *AggregateCasesParams {
	return &AggregateCasesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAggregateCasesParamsWithTimeout creates a new AggregateCasesParams object
// with the ability to set a timeout on a request.
func NewAggregateCasesParamsWithTimeout(timeout time.Duration) *AggregateCasesParams {
	return &AggregateCasesParams{
		timeout: timeout,
	}
}

// NewAggregateCasesParamsWithContext creates a new AggregateCasesParams object
// with the ability to set a context for a request.
func NewAggregateCasesParamsWithContext(ctx context.Context) *AggregateCasesParams {
	return &AggregateCasesParams{
		Context: ctx,
	}
}

// NewAggregateCasesParamsWithHTTPClient creates a new AggregateCasesParams object
// with the ability to set a custom HTTPClient for a request.
func NewAggregateCasesParamsWithHTTPClient(client *http.Client) *AggregateCasesParams {
	return &AggregateCasesParams{
		HTTPClient: client,
	}
}

/*
AggregateCasesParams contains all the parameters to send to the API endpoint

	for the aggregate cases operation.

	Typically these are written to a http.Request.
*/
type AggregateCasesParams struct {

	// Body.
	Body []*models.MsaAggregateQueryRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the aggregate cases params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AggregateCasesParams) WithDefaults() *AggregateCasesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the aggregate cases params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AggregateCasesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the aggregate cases params
func (o *AggregateCasesParams) WithTimeout(timeout time.Duration) *AggregateCasesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the aggregate cases params
func (o *AggregateCasesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the aggregate cases params
func (o *AggregateCasesParams) WithContext(ctx context.Context) *AggregateCasesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the aggregate cases params
func (o *AggregateCasesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the aggregate cases params
func (o *AggregateCasesParams) WithHTTPClient(client *http.Client) *AggregateCasesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the aggregate cases params
func (o *AggregateCasesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the aggregate cases params
func (o *AggregateCasesParams) WithBody(body []*models.MsaAggregateQueryRequest) *AggregateCasesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the aggregate cases params
func (o *AggregateCasesParams) SetBody(body []*models.MsaAggregateQueryRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *AggregateCasesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
