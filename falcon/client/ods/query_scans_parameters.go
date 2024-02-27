// Code generated by go-swagger; DO NOT EDIT.

package ods

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
	"github.com/go-openapi/swag"
)

// NewQueryScansParams creates a new QueryScansParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryScansParams() *QueryScansParams {
	return &QueryScansParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryScansParamsWithTimeout creates a new QueryScansParams object
// with the ability to set a timeout on a request.
func NewQueryScansParamsWithTimeout(timeout time.Duration) *QueryScansParams {
	return &QueryScansParams{
		timeout: timeout,
	}
}

// NewQueryScansParamsWithContext creates a new QueryScansParams object
// with the ability to set a context for a request.
func NewQueryScansParamsWithContext(ctx context.Context) *QueryScansParams {
	return &QueryScansParams{
		Context: ctx,
	}
}

// NewQueryScansParamsWithHTTPClient creates a new QueryScansParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryScansParamsWithHTTPClient(client *http.Client) *QueryScansParams {
	return &QueryScansParams{
		HTTPClient: client,
	}
}

/*
QueryScansParams contains all the parameters to send to the API endpoint

	for the query scans operation.

	Typically these are written to a http.Request.
*/
type QueryScansParams struct {

	/* Filter.

	   A FQL compatible query string. Terms: [id profile_id description.keyword initiated_from filecount.scanned filecount.malicious filecount.quarantined filecount.skipped affected_hosts_count status severity scan_started_on scan_completed_on created_on created_by last_updated targeted_host_count missing_host_count]
	*/
	Filter string

	/* Limit.

	   The max number of resources to return

	   Default: 500
	*/
	Limit *int64

	/* Offset.

	   Index of the starting resource
	*/
	Offset *int64

	/* Sort.

	   The property to sort on, followed by a |, followed by the sort direction, either "asc" or "desc"

	   Default: "created_on|desc"
	*/
	Sort string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query scans params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryScansParams) WithDefaults() *QueryScansParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query scans params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryScansParams) SetDefaults() {
	var (
		limitDefault = int64(500)

		offsetDefault = int64(0)

		sortDefault = string("created_on|desc")
	)

	val := QueryScansParams{
		Limit:  &limitDefault,
		Offset: &offsetDefault,
		Sort:   sortDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the query scans params
func (o *QueryScansParams) WithTimeout(timeout time.Duration) *QueryScansParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query scans params
func (o *QueryScansParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query scans params
func (o *QueryScansParams) WithContext(ctx context.Context) *QueryScansParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query scans params
func (o *QueryScansParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query scans params
func (o *QueryScansParams) WithHTTPClient(client *http.Client) *QueryScansParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query scans params
func (o *QueryScansParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query scans params
func (o *QueryScansParams) WithFilter(filter string) *QueryScansParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query scans params
func (o *QueryScansParams) SetFilter(filter string) {
	o.Filter = filter
}

// WithLimit adds the limit to the query scans params
func (o *QueryScansParams) WithLimit(limit *int64) *QueryScansParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query scans params
func (o *QueryScansParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query scans params
func (o *QueryScansParams) WithOffset(offset *int64) *QueryScansParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query scans params
func (o *QueryScansParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the query scans params
func (o *QueryScansParams) WithSort(sort string) *QueryScansParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query scans params
func (o *QueryScansParams) SetSort(sort string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QueryScansParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param filter
	qrFilter := o.Filter
	qFilter := qrFilter

	if err := r.SetQueryParam("filter", qFilter); err != nil {
		return err
	}

	if o.Limit != nil {

		// query param limit
		var qrLimit int64

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Offset != nil {

		// query param offset
		var qrOffset int64

		if o.Offset != nil {
			qrOffset = *o.Offset
		}
		qOffset := swag.FormatInt64(qrOffset)
		if qOffset != "" {

			if err := r.SetQueryParam("offset", qOffset); err != nil {
				return err
			}
		}
	}

	// query param sort
	qrSort := o.Sort
	qSort := qrSort

	if err := r.SetQueryParam("sort", qSort); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
