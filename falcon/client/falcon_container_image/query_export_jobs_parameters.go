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

// NewQueryExportJobsParams creates a new QueryExportJobsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryExportJobsParams() *QueryExportJobsParams {
	return &QueryExportJobsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryExportJobsParamsWithTimeout creates a new QueryExportJobsParams object
// with the ability to set a timeout on a request.
func NewQueryExportJobsParamsWithTimeout(timeout time.Duration) *QueryExportJobsParams {
	return &QueryExportJobsParams{
		timeout: timeout,
	}
}

// NewQueryExportJobsParamsWithContext creates a new QueryExportJobsParams object
// with the ability to set a context for a request.
func NewQueryExportJobsParamsWithContext(ctx context.Context) *QueryExportJobsParams {
	return &QueryExportJobsParams{
		Context: ctx,
	}
}

// NewQueryExportJobsParamsWithHTTPClient creates a new QueryExportJobsParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryExportJobsParamsWithHTTPClient(client *http.Client) *QueryExportJobsParams {
	return &QueryExportJobsParams{
		HTTPClient: client,
	}
}

/*
QueryExportJobsParams contains all the parameters to send to the API endpoint

	for the query export jobs operation.

	Typically these are written to a http.Request.
*/
type QueryExportJobsParams struct {

	/* Filter.

	     FQL query specifying the filter parameters. Only the last 100 jobs are returned. Supported filters:
	- `resource`: (string)
	- `status`: (string)
	*/
	Filter *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query export jobs params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryExportJobsParams) WithDefaults() *QueryExportJobsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query export jobs params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryExportJobsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query export jobs params
func (o *QueryExportJobsParams) WithTimeout(timeout time.Duration) *QueryExportJobsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query export jobs params
func (o *QueryExportJobsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query export jobs params
func (o *QueryExportJobsParams) WithContext(ctx context.Context) *QueryExportJobsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query export jobs params
func (o *QueryExportJobsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query export jobs params
func (o *QueryExportJobsParams) WithHTTPClient(client *http.Client) *QueryExportJobsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query export jobs params
func (o *QueryExportJobsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query export jobs params
func (o *QueryExportJobsParams) WithFilter(filter *string) *QueryExportJobsParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query export jobs params
func (o *QueryExportJobsParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WriteToRequest writes these params to a swagger request
func (o *QueryExportJobsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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