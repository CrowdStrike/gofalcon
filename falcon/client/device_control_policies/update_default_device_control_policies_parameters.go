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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// NewUpdateDefaultDeviceControlPoliciesParams creates a new UpdateDefaultDeviceControlPoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateDefaultDeviceControlPoliciesParams() *UpdateDefaultDeviceControlPoliciesParams {
	return &UpdateDefaultDeviceControlPoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateDefaultDeviceControlPoliciesParamsWithTimeout creates a new UpdateDefaultDeviceControlPoliciesParams object
// with the ability to set a timeout on a request.
func NewUpdateDefaultDeviceControlPoliciesParamsWithTimeout(timeout time.Duration) *UpdateDefaultDeviceControlPoliciesParams {
	return &UpdateDefaultDeviceControlPoliciesParams{
		timeout: timeout,
	}
}

// NewUpdateDefaultDeviceControlPoliciesParamsWithContext creates a new UpdateDefaultDeviceControlPoliciesParams object
// with the ability to set a context for a request.
func NewUpdateDefaultDeviceControlPoliciesParamsWithContext(ctx context.Context) *UpdateDefaultDeviceControlPoliciesParams {
	return &UpdateDefaultDeviceControlPoliciesParams{
		Context: ctx,
	}
}

// NewUpdateDefaultDeviceControlPoliciesParamsWithHTTPClient creates a new UpdateDefaultDeviceControlPoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateDefaultDeviceControlPoliciesParamsWithHTTPClient(client *http.Client) *UpdateDefaultDeviceControlPoliciesParams {
	return &UpdateDefaultDeviceControlPoliciesParams{
		HTTPClient: client,
	}
}

/* UpdateDefaultDeviceControlPoliciesParams contains all the parameters to send to the API endpoint
   for the update default device control policies operation.

   Typically these are written to a http.Request.
*/
type UpdateDefaultDeviceControlPoliciesParams struct {

	// Body.
	Body *models.DeviceControlReqUpdateDefaultDCPolicyV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update default device control policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateDefaultDeviceControlPoliciesParams) WithDefaults() *UpdateDefaultDeviceControlPoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update default device control policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateDefaultDeviceControlPoliciesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update default device control policies params
func (o *UpdateDefaultDeviceControlPoliciesParams) WithTimeout(timeout time.Duration) *UpdateDefaultDeviceControlPoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update default device control policies params
func (o *UpdateDefaultDeviceControlPoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update default device control policies params
func (o *UpdateDefaultDeviceControlPoliciesParams) WithContext(ctx context.Context) *UpdateDefaultDeviceControlPoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update default device control policies params
func (o *UpdateDefaultDeviceControlPoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update default device control policies params
func (o *UpdateDefaultDeviceControlPoliciesParams) WithHTTPClient(client *http.Client) *UpdateDefaultDeviceControlPoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update default device control policies params
func (o *UpdateDefaultDeviceControlPoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the update default device control policies params
func (o *UpdateDefaultDeviceControlPoliciesParams) WithBody(body *models.DeviceControlReqUpdateDefaultDCPolicyV1) *UpdateDefaultDeviceControlPoliciesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the update default device control policies params
func (o *UpdateDefaultDeviceControlPoliciesParams) SetBody(body *models.DeviceControlReqUpdateDefaultDCPolicyV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateDefaultDeviceControlPoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
