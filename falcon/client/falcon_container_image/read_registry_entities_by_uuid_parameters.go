// Code generated by go-swagger; DO NOT EDIT.

package falcon_container_image

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

// NewReadRegistryEntitiesByUUIDParams creates a new ReadRegistryEntitiesByUUIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewReadRegistryEntitiesByUUIDParams() *ReadRegistryEntitiesByUUIDParams {
	return &ReadRegistryEntitiesByUUIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewReadRegistryEntitiesByUUIDParamsWithTimeout creates a new ReadRegistryEntitiesByUUIDParams object
// with the ability to set a timeout on a request.
func NewReadRegistryEntitiesByUUIDParamsWithTimeout(timeout time.Duration) *ReadRegistryEntitiesByUUIDParams {
	return &ReadRegistryEntitiesByUUIDParams{
		timeout: timeout,
	}
}

// NewReadRegistryEntitiesByUUIDParamsWithContext creates a new ReadRegistryEntitiesByUUIDParams object
// with the ability to set a context for a request.
func NewReadRegistryEntitiesByUUIDParamsWithContext(ctx context.Context) *ReadRegistryEntitiesByUUIDParams {
	return &ReadRegistryEntitiesByUUIDParams{
		Context: ctx,
	}
}

// NewReadRegistryEntitiesByUUIDParamsWithHTTPClient creates a new ReadRegistryEntitiesByUUIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewReadRegistryEntitiesByUUIDParamsWithHTTPClient(client *http.Client) *ReadRegistryEntitiesByUUIDParams {
	return &ReadRegistryEntitiesByUUIDParams{
		HTTPClient: client,
	}
}

/* ReadRegistryEntitiesByUUIDParams contains all the parameters to send to the API endpoint
   for the read registry entities by UUID operation.

   Typically these are written to a http.Request.
*/
type ReadRegistryEntitiesByUUIDParams struct {

	/* Ids.

	   Registry entity UUID
	*/
	Ids string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the read registry entities by UUID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadRegistryEntitiesByUUIDParams) WithDefaults() *ReadRegistryEntitiesByUUIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the read registry entities by UUID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadRegistryEntitiesByUUIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the read registry entities by UUID params
func (o *ReadRegistryEntitiesByUUIDParams) WithTimeout(timeout time.Duration) *ReadRegistryEntitiesByUUIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the read registry entities by UUID params
func (o *ReadRegistryEntitiesByUUIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the read registry entities by UUID params
func (o *ReadRegistryEntitiesByUUIDParams) WithContext(ctx context.Context) *ReadRegistryEntitiesByUUIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the read registry entities by UUID params
func (o *ReadRegistryEntitiesByUUIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the read registry entities by UUID params
func (o *ReadRegistryEntitiesByUUIDParams) WithHTTPClient(client *http.Client) *ReadRegistryEntitiesByUUIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the read registry entities by UUID params
func (o *ReadRegistryEntitiesByUUIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the read registry entities by UUID params
func (o *ReadRegistryEntitiesByUUIDParams) WithIds(ids string) *ReadRegistryEntitiesByUUIDParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the read registry entities by UUID params
func (o *ReadRegistryEntitiesByUUIDParams) SetIds(ids string) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *ReadRegistryEntitiesByUUIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param ids
	qrIds := o.Ids
	qIds := qrIds
	if qIds != "" {

		if err := r.SetQueryParam("ids", qIds); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
