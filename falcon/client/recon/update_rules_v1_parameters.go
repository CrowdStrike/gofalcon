// Code generated by go-swagger; DO NOT EDIT.

package recon

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

// NewUpdateRulesV1Params creates a new UpdateRulesV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateRulesV1Params() *UpdateRulesV1Params {
	return &UpdateRulesV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateRulesV1ParamsWithTimeout creates a new UpdateRulesV1Params object
// with the ability to set a timeout on a request.
func NewUpdateRulesV1ParamsWithTimeout(timeout time.Duration) *UpdateRulesV1Params {
	return &UpdateRulesV1Params{
		timeout: timeout,
	}
}

// NewUpdateRulesV1ParamsWithContext creates a new UpdateRulesV1Params object
// with the ability to set a context for a request.
func NewUpdateRulesV1ParamsWithContext(ctx context.Context) *UpdateRulesV1Params {
	return &UpdateRulesV1Params{
		Context: ctx,
	}
}

// NewUpdateRulesV1ParamsWithHTTPClient creates a new UpdateRulesV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateRulesV1ParamsWithHTTPClient(client *http.Client) *UpdateRulesV1Params {
	return &UpdateRulesV1Params{
		HTTPClient: client,
	}
}

/*
UpdateRulesV1Params contains all the parameters to send to the API endpoint

	for the update rules v1 operation.

	Typically these are written to a http.Request.
*/
type UpdateRulesV1Params struct {

	// Body.
	Body []*models.DomainUpdateRuleRequestV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update rules v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateRulesV1Params) WithDefaults() *UpdateRulesV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update rules v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateRulesV1Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update rules v1 params
func (o *UpdateRulesV1Params) WithTimeout(timeout time.Duration) *UpdateRulesV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update rules v1 params
func (o *UpdateRulesV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update rules v1 params
func (o *UpdateRulesV1Params) WithContext(ctx context.Context) *UpdateRulesV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update rules v1 params
func (o *UpdateRulesV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update rules v1 params
func (o *UpdateRulesV1Params) WithHTTPClient(client *http.Client) *UpdateRulesV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update rules v1 params
func (o *UpdateRulesV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the update rules v1 params
func (o *UpdateRulesV1Params) WithBody(body []*models.DomainUpdateRuleRequestV1) *UpdateRulesV1Params {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the update rules v1 params
func (o *UpdateRulesV1Params) SetBody(body []*models.DomainUpdateRuleRequestV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateRulesV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
