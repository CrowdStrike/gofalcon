// Code generated by go-swagger; DO NOT EDIT.

package cloud_connect_aws

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

// NewQueryAWSAccountsParams creates a new QueryAWSAccountsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryAWSAccountsParams() *QueryAWSAccountsParams {
	return &QueryAWSAccountsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryAWSAccountsParamsWithTimeout creates a new QueryAWSAccountsParams object
// with the ability to set a timeout on a request.
func NewQueryAWSAccountsParamsWithTimeout(timeout time.Duration) *QueryAWSAccountsParams {
	return &QueryAWSAccountsParams{
		timeout: timeout,
	}
}

// NewQueryAWSAccountsParamsWithContext creates a new QueryAWSAccountsParams object
// with the ability to set a context for a request.
func NewQueryAWSAccountsParamsWithContext(ctx context.Context) *QueryAWSAccountsParams {
	return &QueryAWSAccountsParams{
		Context: ctx,
	}
}

// NewQueryAWSAccountsParamsWithHTTPClient creates a new QueryAWSAccountsParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryAWSAccountsParamsWithHTTPClient(client *http.Client) *QueryAWSAccountsParams {
	return &QueryAWSAccountsParams{
		HTTPClient: client,
	}
}

/*
QueryAWSAccountsParams contains all the parameters to send to the API endpoint

	for the query a w s accounts operation.

	Typically these are written to a http.Request.
*/
type QueryAWSAccountsParams struct {

	/* Filter.

	   The filter expression that should be used to limit the results
	*/
	Filter *string

	/* Limit.

	   The maximum records to return. [1-1000]. Defaults to 100.

	   Default: 100
	*/
	Limit *int64

	/* Offset.

	   The offset to start retrieving records from
	*/
	Offset *int64

	/* Sort.

	   The property to sort by (e.g. alias.desc or state.asc)
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query a w s accounts params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryAWSAccountsParams) WithDefaults() *QueryAWSAccountsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query a w s accounts params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryAWSAccountsParams) SetDefaults() {
	var (
		limitDefault = int64(100)
	)

	val := QueryAWSAccountsParams{
		Limit: &limitDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the query a w s accounts params
func (o *QueryAWSAccountsParams) WithTimeout(timeout time.Duration) *QueryAWSAccountsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query a w s accounts params
func (o *QueryAWSAccountsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query a w s accounts params
func (o *QueryAWSAccountsParams) WithContext(ctx context.Context) *QueryAWSAccountsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query a w s accounts params
func (o *QueryAWSAccountsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query a w s accounts params
func (o *QueryAWSAccountsParams) WithHTTPClient(client *http.Client) *QueryAWSAccountsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query a w s accounts params
func (o *QueryAWSAccountsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query a w s accounts params
func (o *QueryAWSAccountsParams) WithFilter(filter *string) *QueryAWSAccountsParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query a w s accounts params
func (o *QueryAWSAccountsParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the query a w s accounts params
func (o *QueryAWSAccountsParams) WithLimit(limit *int64) *QueryAWSAccountsParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query a w s accounts params
func (o *QueryAWSAccountsParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query a w s accounts params
func (o *QueryAWSAccountsParams) WithOffset(offset *int64) *QueryAWSAccountsParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query a w s accounts params
func (o *QueryAWSAccountsParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the query a w s accounts params
func (o *QueryAWSAccountsParams) WithSort(sort *string) *QueryAWSAccountsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query a w s accounts params
func (o *QueryAWSAccountsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QueryAWSAccountsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
