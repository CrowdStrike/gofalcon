// Code generated by go-swagger; DO NOT EDIT.

package user_management

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

// NewQueryUserV1Params creates a new QueryUserV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryUserV1Params() *QueryUserV1Params {
	return &QueryUserV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryUserV1ParamsWithTimeout creates a new QueryUserV1Params object
// with the ability to set a timeout on a request.
func NewQueryUserV1ParamsWithTimeout(timeout time.Duration) *QueryUserV1Params {
	return &QueryUserV1Params{
		timeout: timeout,
	}
}

// NewQueryUserV1ParamsWithContext creates a new QueryUserV1Params object
// with the ability to set a context for a request.
func NewQueryUserV1ParamsWithContext(ctx context.Context) *QueryUserV1Params {
	return &QueryUserV1Params{
		Context: ctx,
	}
}

// NewQueryUserV1ParamsWithHTTPClient creates a new QueryUserV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewQueryUserV1ParamsWithHTTPClient(client *http.Client) *QueryUserV1Params {
	return &QueryUserV1Params{
		HTTPClient: client,
	}
}

/*
QueryUserV1Params contains all the parameters to send to the API endpoint

	for the query user v1 operation.

	Typically these are written to a http.Request.
*/
type QueryUserV1Params struct {

	/* Filter.

	   Filter using a query in Falcon Query Language (FQL). Supported filters: assigned_cids, cid, direct_assigned_cids, factors, first_name, has_temporary_roles, last_name, name, status, temporarily_assigned_cids, uid
	*/
	Filter *string

	/* Limit.

	   The maximum records to return. [1-500]

	   Default: 100
	*/
	Limit *int64

	/* Offset.

	   The offset to start retrieving records from
	*/
	Offset *int64

	/* Sort.

	   The property to sort by

	   Default: "uid|asc"
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query user v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryUserV1Params) WithDefaults() *QueryUserV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query user v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryUserV1Params) SetDefaults() {
	var (
		limitDefault = int64(100)

		offsetDefault = int64(0)

		sortDefault = string("uid|asc")
	)

	val := QueryUserV1Params{
		Limit:  &limitDefault,
		Offset: &offsetDefault,
		Sort:   &sortDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the query user v1 params
func (o *QueryUserV1Params) WithTimeout(timeout time.Duration) *QueryUserV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query user v1 params
func (o *QueryUserV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query user v1 params
func (o *QueryUserV1Params) WithContext(ctx context.Context) *QueryUserV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query user v1 params
func (o *QueryUserV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query user v1 params
func (o *QueryUserV1Params) WithHTTPClient(client *http.Client) *QueryUserV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query user v1 params
func (o *QueryUserV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query user v1 params
func (o *QueryUserV1Params) WithFilter(filter *string) *QueryUserV1Params {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query user v1 params
func (o *QueryUserV1Params) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the query user v1 params
func (o *QueryUserV1Params) WithLimit(limit *int64) *QueryUserV1Params {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query user v1 params
func (o *QueryUserV1Params) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query user v1 params
func (o *QueryUserV1Params) WithOffset(offset *int64) *QueryUserV1Params {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query user v1 params
func (o *QueryUserV1Params) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the query user v1 params
func (o *QueryUserV1Params) WithSort(sort *string) *QueryUserV1Params {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query user v1 params
func (o *QueryUserV1Params) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QueryUserV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
