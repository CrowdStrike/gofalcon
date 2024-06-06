// Code generated by go-swagger; DO NOT EDIT.

package device_control_policies

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

// NewCreateDeviceControlPoliciesParams creates a new CreateDeviceControlPoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateDeviceControlPoliciesParams() *CreateDeviceControlPoliciesParams {
	return &CreateDeviceControlPoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateDeviceControlPoliciesParamsWithTimeout creates a new CreateDeviceControlPoliciesParams object
// with the ability to set a timeout on a request.
func NewCreateDeviceControlPoliciesParamsWithTimeout(timeout time.Duration) *CreateDeviceControlPoliciesParams {
	return &CreateDeviceControlPoliciesParams{
		timeout: timeout,
	}
}

// NewCreateDeviceControlPoliciesParamsWithContext creates a new CreateDeviceControlPoliciesParams object
// with the ability to set a context for a request.
func NewCreateDeviceControlPoliciesParamsWithContext(ctx context.Context) *CreateDeviceControlPoliciesParams {
	return &CreateDeviceControlPoliciesParams{
		Context: ctx,
	}
}

// NewCreateDeviceControlPoliciesParamsWithHTTPClient creates a new CreateDeviceControlPoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateDeviceControlPoliciesParamsWithHTTPClient(client *http.Client) *CreateDeviceControlPoliciesParams {
	return &CreateDeviceControlPoliciesParams{
		HTTPClient: client,
	}
}

/*
CreateDeviceControlPoliciesParams contains all the parameters to send to the API endpoint

	for the create device control policies operation.

	Typically these are written to a http.Request.
*/
type CreateDeviceControlPoliciesParams struct {

	// Body.
	Body *models.DeviceControlCreatePoliciesV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create device control policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateDeviceControlPoliciesParams) WithDefaults() *CreateDeviceControlPoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create device control policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateDeviceControlPoliciesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create device control policies params
func (o *CreateDeviceControlPoliciesParams) WithTimeout(timeout time.Duration) *CreateDeviceControlPoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create device control policies params
func (o *CreateDeviceControlPoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create device control policies params
func (o *CreateDeviceControlPoliciesParams) WithContext(ctx context.Context) *CreateDeviceControlPoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create device control policies params
func (o *CreateDeviceControlPoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create device control policies params
func (o *CreateDeviceControlPoliciesParams) WithHTTPClient(client *http.Client) *CreateDeviceControlPoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create device control policies params
func (o *CreateDeviceControlPoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create device control policies params
func (o *CreateDeviceControlPoliciesParams) WithBody(body *models.DeviceControlCreatePoliciesV1) *CreateDeviceControlPoliciesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create device control policies params
func (o *CreateDeviceControlPoliciesParams) SetBody(body *models.DeviceControlCreatePoliciesV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateDeviceControlPoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
