// Code generated by go-swagger; DO NOT EDIT.

package sensor_update_policies

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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// NewCreateSensorUpdatePoliciesParams creates a new CreateSensorUpdatePoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateSensorUpdatePoliciesParams() *CreateSensorUpdatePoliciesParams {
	return &CreateSensorUpdatePoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateSensorUpdatePoliciesParamsWithTimeout creates a new CreateSensorUpdatePoliciesParams object
// with the ability to set a timeout on a request.
func NewCreateSensorUpdatePoliciesParamsWithTimeout(timeout time.Duration) *CreateSensorUpdatePoliciesParams {
	return &CreateSensorUpdatePoliciesParams{
		timeout: timeout,
	}
}

// NewCreateSensorUpdatePoliciesParamsWithContext creates a new CreateSensorUpdatePoliciesParams object
// with the ability to set a context for a request.
func NewCreateSensorUpdatePoliciesParamsWithContext(ctx context.Context) *CreateSensorUpdatePoliciesParams {
	return &CreateSensorUpdatePoliciesParams{
		Context: ctx,
	}
}

// NewCreateSensorUpdatePoliciesParamsWithHTTPClient creates a new CreateSensorUpdatePoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateSensorUpdatePoliciesParamsWithHTTPClient(client *http.Client) *CreateSensorUpdatePoliciesParams {
	return &CreateSensorUpdatePoliciesParams{
		HTTPClient: client,
	}
}

/* CreateSensorUpdatePoliciesParams contains all the parameters to send to the API endpoint
   for the create sensor update policies operation.

   Typically these are written to a http.Request.
*/
type CreateSensorUpdatePoliciesParams struct {

	// Body.
	Body *models.SensorUpdateCreatePoliciesReqV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create sensor update policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateSensorUpdatePoliciesParams) WithDefaults() *CreateSensorUpdatePoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create sensor update policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateSensorUpdatePoliciesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create sensor update policies params
func (o *CreateSensorUpdatePoliciesParams) WithTimeout(timeout time.Duration) *CreateSensorUpdatePoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create sensor update policies params
func (o *CreateSensorUpdatePoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create sensor update policies params
func (o *CreateSensorUpdatePoliciesParams) WithContext(ctx context.Context) *CreateSensorUpdatePoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create sensor update policies params
func (o *CreateSensorUpdatePoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create sensor update policies params
func (o *CreateSensorUpdatePoliciesParams) WithHTTPClient(client *http.Client) *CreateSensorUpdatePoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create sensor update policies params
func (o *CreateSensorUpdatePoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create sensor update policies params
func (o *CreateSensorUpdatePoliciesParams) WithBody(body *models.SensorUpdateCreatePoliciesReqV1) *CreateSensorUpdatePoliciesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create sensor update policies params
func (o *CreateSensorUpdatePoliciesParams) SetBody(body *models.SensorUpdateCreatePoliciesReqV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateSensorUpdatePoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
