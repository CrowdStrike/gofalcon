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

// NewDevicesRanOnParams creates a new DevicesRanOnParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDevicesRanOnParams() *DevicesRanOnParams {
	return &DevicesRanOnParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDevicesRanOnParamsWithTimeout creates a new DevicesRanOnParams object
// with the ability to set a timeout on a request.
func NewDevicesRanOnParamsWithTimeout(timeout time.Duration) *DevicesRanOnParams {
	return &DevicesRanOnParams{
		timeout: timeout,
	}
}

// NewDevicesRanOnParamsWithContext creates a new DevicesRanOnParams object
// with the ability to set a context for a request.
func NewDevicesRanOnParamsWithContext(ctx context.Context) *DevicesRanOnParams {
	return &DevicesRanOnParams{
		Context: ctx,
	}
}

// NewDevicesRanOnParamsWithHTTPClient creates a new DevicesRanOnParams object
// with the ability to set a custom HTTPClient for a request.
func NewDevicesRanOnParamsWithHTTPClient(client *http.Client) *DevicesRanOnParams {
	return &DevicesRanOnParams{
		HTTPClient: client,
	}
}

/* DevicesRanOnParams contains all the parameters to send to the API endpoint
   for the devices ran on operation.

   Typically these are written to a http.Request.
*/
type DevicesRanOnParams struct {

	/* Limit.

	   The first process to return, where 0 is the latest offset. Use with the offset parameter to manage pagination of results.
	*/
	Limit *string

	/* Offset.

	   The first process to return, where 0 is the latest offset. Use with the limit parameter to manage pagination of results.
	*/
	Offset *string

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

// WithDefaults hydrates default values in the devices ran on params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DevicesRanOnParams) WithDefaults() *DevicesRanOnParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the devices ran on params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DevicesRanOnParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the devices ran on params
func (o *DevicesRanOnParams) WithTimeout(timeout time.Duration) *DevicesRanOnParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the devices ran on params
func (o *DevicesRanOnParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the devices ran on params
func (o *DevicesRanOnParams) WithContext(ctx context.Context) *DevicesRanOnParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the devices ran on params
func (o *DevicesRanOnParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the devices ran on params
func (o *DevicesRanOnParams) WithHTTPClient(client *http.Client) *DevicesRanOnParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the devices ran on params
func (o *DevicesRanOnParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLimit adds the limit to the devices ran on params
func (o *DevicesRanOnParams) WithLimit(limit *string) *DevicesRanOnParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the devices ran on params
func (o *DevicesRanOnParams) SetLimit(limit *string) {
	o.Limit = limit
}

// WithOffset adds the offset to the devices ran on params
func (o *DevicesRanOnParams) WithOffset(offset *string) *DevicesRanOnParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the devices ran on params
func (o *DevicesRanOnParams) SetOffset(offset *string) {
	o.Offset = offset
}

// WithType adds the typeVar to the devices ran on params
func (o *DevicesRanOnParams) WithType(typeVar string) *DevicesRanOnParams {
	o.SetType(typeVar)
	return o
}

// SetType adds the type to the devices ran on params
func (o *DevicesRanOnParams) SetType(typeVar string) {
	o.Type = typeVar
}

// WithValue adds the value to the devices ran on params
func (o *DevicesRanOnParams) WithValue(value string) *DevicesRanOnParams {
	o.SetValue(value)
	return o
}

// SetValue adds the value to the devices ran on params
func (o *DevicesRanOnParams) SetValue(value string) {
	o.Value = value
}

// WriteToRequest writes these params to a swagger request
func (o *DevicesRanOnParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Limit != nil {

		// query param limit
		var qrLimit string

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := qrLimit
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Offset != nil {

		// query param offset
		var qrOffset string

		if o.Offset != nil {
			qrOffset = *o.Offset
		}
		qOffset := qrOffset
		if qOffset != "" {

			if err := r.SetQueryParam("offset", qOffset); err != nil {
				return err
			}
		}
	}

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
