// Code generated by go-swagger; DO NOT EDIT.

package iocs

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

// NewDevicesCountParams creates a new DevicesCountParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDevicesCountParams() *DevicesCountParams {
	return &DevicesCountParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDevicesCountParamsWithTimeout creates a new DevicesCountParams object
// with the ability to set a timeout on a request.
func NewDevicesCountParamsWithTimeout(timeout time.Duration) *DevicesCountParams {
	return &DevicesCountParams{
		timeout: timeout,
	}
}

// NewDevicesCountParamsWithContext creates a new DevicesCountParams object
// with the ability to set a context for a request.
func NewDevicesCountParamsWithContext(ctx context.Context) *DevicesCountParams {
	return &DevicesCountParams{
		Context: ctx,
	}
}

// NewDevicesCountParamsWithHTTPClient creates a new DevicesCountParams object
// with the ability to set a custom HTTPClient for a request.
func NewDevicesCountParamsWithHTTPClient(client *http.Client) *DevicesCountParams {
	return &DevicesCountParams{
		HTTPClient: client,
	}
}

/* DevicesCountParams contains all the parameters to send to the API endpoint
   for the devices count operation.

   Typically these are written to a http.Request.
*/
type DevicesCountParams struct {

	/* Type.


	The type of the indicator. Valid types include:

	sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.

	md5: A hex-encoded md5 hash string. Length - min 32, max: 32.

	domain: A domain name. Length - min: 1, max: 200.

	ipv4: An IPv4 address. Must be a valid IP address.

	ipv6: An IPv6 address. Must be a valid IP address.

	*/
	Type string

	/* Value.

	   The string representation of the indicator
	*/
	Value string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the devices count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DevicesCountParams) WithDefaults() *DevicesCountParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the devices count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DevicesCountParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the devices count params
func (o *DevicesCountParams) WithTimeout(timeout time.Duration) *DevicesCountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the devices count params
func (o *DevicesCountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the devices count params
func (o *DevicesCountParams) WithContext(ctx context.Context) *DevicesCountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the devices count params
func (o *DevicesCountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the devices count params
func (o *DevicesCountParams) WithHTTPClient(client *http.Client) *DevicesCountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the devices count params
func (o *DevicesCountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithType adds the typeVar to the devices count params
func (o *DevicesCountParams) WithType(typeVar string) *DevicesCountParams {
	o.SetType(typeVar)
	return o
}

// SetType adds the type to the devices count params
func (o *DevicesCountParams) SetType(typeVar string) {
	o.Type = typeVar
}

// WithValue adds the value to the devices count params
func (o *DevicesCountParams) WithValue(value string) *DevicesCountParams {
	o.SetValue(value)
	return o
}

// SetValue adds the value to the devices count params
func (o *DevicesCountParams) SetValue(value string) {
	o.Value = value
}

// WriteToRequest writes these params to a swagger request
func (o *DevicesCountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param type
	qrType := o.Type
	qType := qrType
	if qType != "" {

		if err := r.SetQueryParam("type", qType); err != nil {
			return err
		}
	}

	// query param value
	qrValue := o.Value
	qValue := qrValue
	if qValue != "" {

		if err := r.SetQueryParam("value", qValue); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
