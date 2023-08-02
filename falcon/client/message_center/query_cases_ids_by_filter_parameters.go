// Code generated by go-swagger; DO NOT EDIT.

package message_center

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

// NewQueryCasesIdsByFilterParams creates a new QueryCasesIdsByFilterParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryCasesIdsByFilterParams() *QueryCasesIdsByFilterParams {
	return &QueryCasesIdsByFilterParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryCasesIdsByFilterParamsWithTimeout creates a new QueryCasesIdsByFilterParams object
// with the ability to set a timeout on a request.
func NewQueryCasesIdsByFilterParamsWithTimeout(timeout time.Duration) *QueryCasesIdsByFilterParams {
	return &QueryCasesIdsByFilterParams{
		timeout: timeout,
	}
}

// NewQueryCasesIdsByFilterParamsWithContext creates a new QueryCasesIdsByFilterParams object
// with the ability to set a context for a request.
func NewQueryCasesIdsByFilterParamsWithContext(ctx context.Context) *QueryCasesIdsByFilterParams {
	return &QueryCasesIdsByFilterParams{
		Context: ctx,
	}
}

// NewQueryCasesIdsByFilterParamsWithHTTPClient creates a new QueryCasesIdsByFilterParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryCasesIdsByFilterParamsWithHTTPClient(client *http.Client) *QueryCasesIdsByFilterParams {
	return &QueryCasesIdsByFilterParams{
		HTTPClient: client,
	}
}

/*
QueryCasesIdsByFilterParams contains all the parameters to send to the API endpoint

	for the query cases ids by filter operation.

	Typically these are written to a http.Request.
*/
type QueryCasesIdsByFilterParams struct {

	/* Filter.

	     Optional filter and sort criteria in the form of an FQL query. Allowed filters are:

	_all
	activity.body
	case.aids
	case.assigner.display_name
	case.assigner.first_name
	case.assigner.last_name
	case.assigner.uid
	case.assigner.uuid
	case.body
	case.created_time
	case.detections.id
	case.hosts
	case.id
	case.incidents.id
	case.ip_addresses
	case.key
	case.last_modified_time
	case.status
	case.title
	case.type
	*/
	Filter *string

	/* Limit.

	   The maximum records to return. [1-500]
	*/
	Limit *int64

	/* Offset.

	   Starting index of overall result set from which to return ids.
	*/
	Offset *string

	/* Sort.

	   The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc".
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query cases ids by filter params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryCasesIdsByFilterParams) WithDefaults() *QueryCasesIdsByFilterParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query cases ids by filter params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryCasesIdsByFilterParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) WithTimeout(timeout time.Duration) *QueryCasesIdsByFilterParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) WithContext(ctx context.Context) *QueryCasesIdsByFilterParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) WithHTTPClient(client *http.Client) *QueryCasesIdsByFilterParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) WithFilter(filter *string) *QueryCasesIdsByFilterParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) WithLimit(limit *int64) *QueryCasesIdsByFilterParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) WithOffset(offset *string) *QueryCasesIdsByFilterParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) SetOffset(offset *string) {
	o.Offset = offset
}

// WithSort adds the sort to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) WithSort(sort *string) *QueryCasesIdsByFilterParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query cases ids by filter params
func (o *QueryCasesIdsByFilterParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QueryCasesIdsByFilterParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
