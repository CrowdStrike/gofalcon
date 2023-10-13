// Code generated by go-swagger; DO NOT EDIT.

package ioc

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

// NewIndicatorGetProcessesRanOnV1Params creates a new IndicatorGetProcessesRanOnV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIndicatorGetProcessesRanOnV1Params() *IndicatorGetProcessesRanOnV1Params {
	return &IndicatorGetProcessesRanOnV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewIndicatorGetProcessesRanOnV1ParamsWithTimeout creates a new IndicatorGetProcessesRanOnV1Params object
// with the ability to set a timeout on a request.
func NewIndicatorGetProcessesRanOnV1ParamsWithTimeout(timeout time.Duration) *IndicatorGetProcessesRanOnV1Params {
	return &IndicatorGetProcessesRanOnV1Params{
		timeout: timeout,
	}
}

// NewIndicatorGetProcessesRanOnV1ParamsWithContext creates a new IndicatorGetProcessesRanOnV1Params object
// with the ability to set a context for a request.
func NewIndicatorGetProcessesRanOnV1ParamsWithContext(ctx context.Context) *IndicatorGetProcessesRanOnV1Params {
	return &IndicatorGetProcessesRanOnV1Params{
		Context: ctx,
	}
}

// NewIndicatorGetProcessesRanOnV1ParamsWithHTTPClient creates a new IndicatorGetProcessesRanOnV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewIndicatorGetProcessesRanOnV1ParamsWithHTTPClient(client *http.Client) *IndicatorGetProcessesRanOnV1Params {
	return &IndicatorGetProcessesRanOnV1Params{
		HTTPClient: client,
	}
}

/* IndicatorGetProcessesRanOnV1Params contains all the parameters to send to the API endpoint
   for the indicator get processes ran on v1 operation.

   Typically these are written to a http.Request.
*/
type IndicatorGetProcessesRanOnV1Params struct {

	/* DeviceID.

	   Specify a host's ID to return only processes from that host. Get a host's ID from GET /devices/queries/devices/v1, the Falcon console, or the Streaming API.
	*/
	DeviceID string

	/* Limit.

	   The maximum number of results to return. Use with the offset parameter to manage pagination of results.
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

// WithDefaults hydrates default values in the indicator get processes ran on v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IndicatorGetProcessesRanOnV1Params) WithDefaults() *IndicatorGetProcessesRanOnV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the indicator get processes ran on v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IndicatorGetProcessesRanOnV1Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) WithTimeout(timeout time.Duration) *IndicatorGetProcessesRanOnV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) WithContext(ctx context.Context) *IndicatorGetProcessesRanOnV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) WithHTTPClient(client *http.Client) *IndicatorGetProcessesRanOnV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithDeviceID adds the deviceID to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) WithDeviceID(deviceID string) *IndicatorGetProcessesRanOnV1Params {
	o.SetDeviceID(deviceID)
	return o
}

// SetDeviceID adds the deviceId to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) SetDeviceID(deviceID string) {
	o.DeviceID = deviceID
}

// WithLimit adds the limit to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) WithLimit(limit *string) *IndicatorGetProcessesRanOnV1Params {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) SetLimit(limit *string) {
	o.Limit = limit
}

// WithOffset adds the offset to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) WithOffset(offset *string) *IndicatorGetProcessesRanOnV1Params {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) SetOffset(offset *string) {
	o.Offset = offset
}

// WithType adds the typeVar to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) WithType(typeVar string) *IndicatorGetProcessesRanOnV1Params {
	o.SetType(typeVar)
	return o
}

// SetType adds the type to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) SetType(typeVar string) {
	o.Type = typeVar
}

// WithValue adds the value to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) WithValue(value string) *IndicatorGetProcessesRanOnV1Params {
	o.SetValue(value)
	return o
}

// SetValue adds the value to the indicator get processes ran on v1 params
func (o *IndicatorGetProcessesRanOnV1Params) SetValue(value string) {
	o.Value = value
}

// WriteToRequest writes these params to a swagger request
func (o *IndicatorGetProcessesRanOnV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param device_id
	qrDeviceID := o.DeviceID
	qDeviceID := qrDeviceID
	if qDeviceID != "" {

		if err := r.SetQueryParam("device_id", qDeviceID); err != nil {
			return err
		}
	}

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
