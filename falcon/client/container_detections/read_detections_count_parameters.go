// Code generated by go-swagger; DO NOT EDIT.

package container_detections

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

// NewReadDetectionsCountParams creates a new ReadDetectionsCountParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewReadDetectionsCountParams() *ReadDetectionsCountParams {
	return &ReadDetectionsCountParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewReadDetectionsCountParamsWithTimeout creates a new ReadDetectionsCountParams object
// with the ability to set a timeout on a request.
func NewReadDetectionsCountParamsWithTimeout(timeout time.Duration) *ReadDetectionsCountParams {
	return &ReadDetectionsCountParams{
		timeout: timeout,
	}
}

// NewReadDetectionsCountParamsWithContext creates a new ReadDetectionsCountParams object
// with the ability to set a context for a request.
func NewReadDetectionsCountParamsWithContext(ctx context.Context) *ReadDetectionsCountParams {
	return &ReadDetectionsCountParams{
		Context: ctx,
	}
}

// NewReadDetectionsCountParamsWithHTTPClient creates a new ReadDetectionsCountParams object
// with the ability to set a custom HTTPClient for a request.
func NewReadDetectionsCountParamsWithHTTPClient(client *http.Client) *ReadDetectionsCountParams {
	return &ReadDetectionsCountParams{
		HTTPClient: client,
	}
}

/*
ReadDetectionsCountParams contains all the parameters to send to the API endpoint

	for the read detections count operation.

	Typically these are written to a http.Request.
*/
type ReadDetectionsCountParams struct {

	/* Filter.

	     Filter images detections using a query in Falcon Query Language (FQL). Supported filter fields:
	- `cid`
	- `detection_type`
	- `image_registry`
	- `image_repository`
	- `image_tag`
	*/
	Filter *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the read detections count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadDetectionsCountParams) WithDefaults() *ReadDetectionsCountParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the read detections count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadDetectionsCountParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the read detections count params
func (o *ReadDetectionsCountParams) WithTimeout(timeout time.Duration) *ReadDetectionsCountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the read detections count params
func (o *ReadDetectionsCountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the read detections count params
func (o *ReadDetectionsCountParams) WithContext(ctx context.Context) *ReadDetectionsCountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the read detections count params
func (o *ReadDetectionsCountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the read detections count params
func (o *ReadDetectionsCountParams) WithHTTPClient(client *http.Client) *ReadDetectionsCountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the read detections count params
func (o *ReadDetectionsCountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the read detections count params
func (o *ReadDetectionsCountParams) WithFilter(filter *string) *ReadDetectionsCountParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the read detections count params
func (o *ReadDetectionsCountParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WriteToRequest writes these params to a swagger request
func (o *ReadDetectionsCountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Filter != nil {

		// query param filter
		var qrFilter string

		if o.Filter != nil {
			qrFilter = *o.Filter
		}
		qFilter := qrFilter
		if qFilter != "" {

			if err := r.SetQueryParam("filter", qFilter); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
