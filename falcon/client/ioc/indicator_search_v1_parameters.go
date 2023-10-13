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
	"github.com/go-openapi/swag"
)

// NewIndicatorSearchV1Params creates a new IndicatorSearchV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIndicatorSearchV1Params() *IndicatorSearchV1Params {
	return &IndicatorSearchV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewIndicatorSearchV1ParamsWithTimeout creates a new IndicatorSearchV1Params object
// with the ability to set a timeout on a request.
func NewIndicatorSearchV1ParamsWithTimeout(timeout time.Duration) *IndicatorSearchV1Params {
	return &IndicatorSearchV1Params{
		timeout: timeout,
	}
}

// NewIndicatorSearchV1ParamsWithContext creates a new IndicatorSearchV1Params object
// with the ability to set a context for a request.
func NewIndicatorSearchV1ParamsWithContext(ctx context.Context) *IndicatorSearchV1Params {
	return &IndicatorSearchV1Params{
		Context: ctx,
	}
}

// NewIndicatorSearchV1ParamsWithHTTPClient creates a new IndicatorSearchV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewIndicatorSearchV1ParamsWithHTTPClient(client *http.Client) *IndicatorSearchV1Params {
	return &IndicatorSearchV1Params{
		HTTPClient: client,
	}
}

/* IndicatorSearchV1Params contains all the parameters to send to the API endpoint
   for the indicator search v1 operation.

   Typically these are written to a http.Request.
*/
type IndicatorSearchV1Params struct {

	/* After.

	   A pagination token used with the `limit` parameter to manage pagination of results. On your first request, don't provide an 'after' token. On subsequent requests, provide the 'after' token from the previous response to continue from that place in the results. To access more than 10k indicators, use the 'after' parameter instead of 'offset'.
	*/
	After *string

	/* Filter.

	   The filter expression that should be used to limit the results.
	*/
	Filter *string

	/* FromParent.

	   The filter for returning either only indicators for the request customer or its MSSP parents
	*/
	FromParent *bool

	/* Limit.

	   The maximum records to return.
	*/
	Limit *int64

	/* Offset.

	   The offset to start retrieving records from. Offset and After params are mutually exclusive. If none provided then scrolling will be used by default. To access more than 10k iocs, use the 'after' parameter instead of 'offset'.
	*/
	Offset *int64

	/* Sort.

	   The sort expression that should be used to sort the results.
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the indicator search v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IndicatorSearchV1Params) WithDefaults() *IndicatorSearchV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the indicator search v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IndicatorSearchV1Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the indicator search v1 params
func (o *IndicatorSearchV1Params) WithTimeout(timeout time.Duration) *IndicatorSearchV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the indicator search v1 params
func (o *IndicatorSearchV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the indicator search v1 params
func (o *IndicatorSearchV1Params) WithContext(ctx context.Context) *IndicatorSearchV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the indicator search v1 params
func (o *IndicatorSearchV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the indicator search v1 params
func (o *IndicatorSearchV1Params) WithHTTPClient(client *http.Client) *IndicatorSearchV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the indicator search v1 params
func (o *IndicatorSearchV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAfter adds the after to the indicator search v1 params
func (o *IndicatorSearchV1Params) WithAfter(after *string) *IndicatorSearchV1Params {
	o.SetAfter(after)
	return o
}

// SetAfter adds the after to the indicator search v1 params
func (o *IndicatorSearchV1Params) SetAfter(after *string) {
	o.After = after
}

// WithFilter adds the filter to the indicator search v1 params
func (o *IndicatorSearchV1Params) WithFilter(filter *string) *IndicatorSearchV1Params {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the indicator search v1 params
func (o *IndicatorSearchV1Params) SetFilter(filter *string) {
	o.Filter = filter
}

// WithFromParent adds the fromParent to the indicator search v1 params
func (o *IndicatorSearchV1Params) WithFromParent(fromParent *bool) *IndicatorSearchV1Params {
	o.SetFromParent(fromParent)
	return o
}

// SetFromParent adds the fromParent to the indicator search v1 params
func (o *IndicatorSearchV1Params) SetFromParent(fromParent *bool) {
	o.FromParent = fromParent
}

// WithLimit adds the limit to the indicator search v1 params
func (o *IndicatorSearchV1Params) WithLimit(limit *int64) *IndicatorSearchV1Params {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the indicator search v1 params
func (o *IndicatorSearchV1Params) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the indicator search v1 params
func (o *IndicatorSearchV1Params) WithOffset(offset *int64) *IndicatorSearchV1Params {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the indicator search v1 params
func (o *IndicatorSearchV1Params) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the indicator search v1 params
func (o *IndicatorSearchV1Params) WithSort(sort *string) *IndicatorSearchV1Params {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the indicator search v1 params
func (o *IndicatorSearchV1Params) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *IndicatorSearchV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.After != nil {

		// query param after
		var qrAfter string

		if o.After != nil {
			qrAfter = *o.After
		}
		qAfter := qrAfter
		if qAfter != "" {

			if err := r.SetQueryParam("after", qAfter); err != nil {
				return err
			}
		}
	}

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

	if o.FromParent != nil {

		// query param from_parent
		var qrFromParent bool

		if o.FromParent != nil {
			qrFromParent = *o.FromParent
		}
		qFromParent := swag.FormatBool(qrFromParent)
		if qFromParent != "" {

			if err := r.SetQueryParam("from_parent", qFromParent); err != nil {
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
