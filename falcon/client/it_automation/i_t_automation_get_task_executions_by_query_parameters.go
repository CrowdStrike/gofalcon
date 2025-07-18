// Code generated by go-swagger; DO NOT EDIT.

package it_automation

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

// NewITAutomationGetTaskExecutionsByQueryParams creates a new ITAutomationGetTaskExecutionsByQueryParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewITAutomationGetTaskExecutionsByQueryParams() *ITAutomationGetTaskExecutionsByQueryParams {
	return &ITAutomationGetTaskExecutionsByQueryParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewITAutomationGetTaskExecutionsByQueryParamsWithTimeout creates a new ITAutomationGetTaskExecutionsByQueryParams object
// with the ability to set a timeout on a request.
func NewITAutomationGetTaskExecutionsByQueryParamsWithTimeout(timeout time.Duration) *ITAutomationGetTaskExecutionsByQueryParams {
	return &ITAutomationGetTaskExecutionsByQueryParams{
		timeout: timeout,
	}
}

// NewITAutomationGetTaskExecutionsByQueryParamsWithContext creates a new ITAutomationGetTaskExecutionsByQueryParams object
// with the ability to set a context for a request.
func NewITAutomationGetTaskExecutionsByQueryParamsWithContext(ctx context.Context) *ITAutomationGetTaskExecutionsByQueryParams {
	return &ITAutomationGetTaskExecutionsByQueryParams{
		Context: ctx,
	}
}

// NewITAutomationGetTaskExecutionsByQueryParamsWithHTTPClient creates a new ITAutomationGetTaskExecutionsByQueryParams object
// with the ability to set a custom HTTPClient for a request.
func NewITAutomationGetTaskExecutionsByQueryParamsWithHTTPClient(client *http.Client) *ITAutomationGetTaskExecutionsByQueryParams {
	return &ITAutomationGetTaskExecutionsByQueryParams{
		HTTPClient: client,
	}
}

/*
ITAutomationGetTaskExecutionsByQueryParams contains all the parameters to send to the API endpoint

	for the i t automation get task executions by query operation.

	Typically these are written to a http.Request.
*/
type ITAutomationGetTaskExecutionsByQueryParams struct {

	/* Filter.

	   The filter expression that should be used to limit the results. Allowed filter fields: [end_time, run_by, run_type, start_time, status, task_id, task_name, task_type] Example: example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'
	*/
	Filter *string

	/* Limit.

	   The maximum records to return. Example: 50

	   Default: 100
	*/
	Limit *int64

	/* Offset.

	   Starting index for record retrieval. Example: 100
	*/
	Offset *int64

	/* Sort.

	   The sort expression that should be used to sort the results. Allowed sort fields: [end_time, run_by, run_type, start_time, status, task_id, task_name, task_type]. Sort either `asc` (ascending) or `desc` (descending). Example: example_field|asc
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the i t automation get task executions by query params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ITAutomationGetTaskExecutionsByQueryParams) WithDefaults() *ITAutomationGetTaskExecutionsByQueryParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the i t automation get task executions by query params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ITAutomationGetTaskExecutionsByQueryParams) SetDefaults() {
	var (
		limitDefault = int64(100)

		offsetDefault = int64(0)
	)

	val := ITAutomationGetTaskExecutionsByQueryParams{
		Limit:  &limitDefault,
		Offset: &offsetDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) WithTimeout(timeout time.Duration) *ITAutomationGetTaskExecutionsByQueryParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) WithContext(ctx context.Context) *ITAutomationGetTaskExecutionsByQueryParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) WithHTTPClient(client *http.Client) *ITAutomationGetTaskExecutionsByQueryParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) WithFilter(filter *string) *ITAutomationGetTaskExecutionsByQueryParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) WithLimit(limit *int64) *ITAutomationGetTaskExecutionsByQueryParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) WithOffset(offset *int64) *ITAutomationGetTaskExecutionsByQueryParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) WithSort(sort *string) *ITAutomationGetTaskExecutionsByQueryParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the i t automation get task executions by query params
func (o *ITAutomationGetTaskExecutionsByQueryParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *ITAutomationGetTaskExecutionsByQueryParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if o.Sort != nil {

		// query param sort
		var qrSort string

		if o.Sort != nil {
			qrSort = *o.Sort
		}
		qSort := qrSort
		if qSort != "" {

			if err := r.SetQueryParam("sort", qSort); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
