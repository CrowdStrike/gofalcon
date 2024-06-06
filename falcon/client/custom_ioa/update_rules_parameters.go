// Code generated by go-swagger; DO NOT EDIT.

package custom_ioa

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

// NewUpdateRulesParams creates a new UpdateRulesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateRulesParams() *UpdateRulesParams {
	return &UpdateRulesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateRulesParamsWithTimeout creates a new UpdateRulesParams object
// with the ability to set a timeout on a request.
func NewUpdateRulesParamsWithTimeout(timeout time.Duration) *UpdateRulesParams {
	return &UpdateRulesParams{
		timeout: timeout,
	}
}

// NewUpdateRulesParamsWithContext creates a new UpdateRulesParams object
// with the ability to set a context for a request.
func NewUpdateRulesParamsWithContext(ctx context.Context) *UpdateRulesParams {
	return &UpdateRulesParams{
		Context: ctx,
	}
}

// NewUpdateRulesParamsWithHTTPClient creates a new UpdateRulesParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateRulesParamsWithHTTPClient(client *http.Client) *UpdateRulesParams {
	return &UpdateRulesParams{
		HTTPClient: client,
	}
}

/*
UpdateRulesParams contains all the parameters to send to the API endpoint

	for the update rules operation.

	Typically these are written to a http.Request.
*/
type UpdateRulesParams struct {

	// Body.
	Body *models.APIRuleUpdatesRequestV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update rules params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateRulesParams) WithDefaults() *UpdateRulesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update rules params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateRulesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update rules params
func (o *UpdateRulesParams) WithTimeout(timeout time.Duration) *UpdateRulesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update rules params
func (o *UpdateRulesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update rules params
func (o *UpdateRulesParams) WithContext(ctx context.Context) *UpdateRulesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update rules params
func (o *UpdateRulesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update rules params
func (o *UpdateRulesParams) WithHTTPClient(client *http.Client) *UpdateRulesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update rules params
func (o *UpdateRulesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the update rules params
func (o *UpdateRulesParams) WithBody(body *models.APIRuleUpdatesRequestV1) *UpdateRulesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the update rules params
func (o *UpdateRulesParams) SetBody(body *models.APIRuleUpdatesRequestV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateRulesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
