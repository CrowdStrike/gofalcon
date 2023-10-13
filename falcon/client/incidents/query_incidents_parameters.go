// Code generated by go-swagger; DO NOT EDIT.

package incidents

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

// NewQueryIncidentsParams creates a new QueryIncidentsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryIncidentsParams() *QueryIncidentsParams {
	return &QueryIncidentsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryIncidentsParamsWithTimeout creates a new QueryIncidentsParams object
// with the ability to set a timeout on a request.
func NewQueryIncidentsParamsWithTimeout(timeout time.Duration) *QueryIncidentsParams {
	return &QueryIncidentsParams{
		timeout: timeout,
	}
}

// NewQueryIncidentsParamsWithContext creates a new QueryIncidentsParams object
// with the ability to set a context for a request.
func NewQueryIncidentsParamsWithContext(ctx context.Context) *QueryIncidentsParams {
	return &QueryIncidentsParams{
		Context: ctx,
	}
}

// NewQueryIncidentsParamsWithHTTPClient creates a new QueryIncidentsParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryIncidentsParamsWithHTTPClient(client *http.Client) *QueryIncidentsParams {
	return &QueryIncidentsParams{
		HTTPClient: client,
	}
}

/* QueryIncidentsParams contains all the parameters to send to the API endpoint
   for the query incidents operation.

   Typically these are written to a http.Request.
*/
type QueryIncidentsParams struct {

	/* Filter.

	   Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide).
	*/
	Filter *string

	/* Limit.

	   The maximum records to return. [1-500]
	*/
	Limit *int64

	/* Offset.

	   Starting index of overall result set from which to return ids.
	*/
	Offset *int64

	/* Sort.

	   The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc".
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query incidents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryIncidentsParams) WithDefaults() *QueryIncidentsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query incidents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryIncidentsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query incidents params
func (o *QueryIncidentsParams) WithTimeout(timeout time.Duration) *QueryIncidentsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query incidents params
func (o *QueryIncidentsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query incidents params
func (o *QueryIncidentsParams) WithContext(ctx context.Context) *QueryIncidentsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query incidents params
func (o *QueryIncidentsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query incidents params
func (o *QueryIncidentsParams) WithHTTPClient(client *http.Client) *QueryIncidentsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query incidents params
func (o *QueryIncidentsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query incidents params
func (o *QueryIncidentsParams) WithFilter(filter *string) *QueryIncidentsParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query incidents params
func (o *QueryIncidentsParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the query incidents params
func (o *QueryIncidentsParams) WithLimit(limit *int64) *QueryIncidentsParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query incidents params
func (o *QueryIncidentsParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query incidents params
func (o *QueryIncidentsParams) WithOffset(offset *int64) *QueryIncidentsParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query incidents params
func (o *QueryIncidentsParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the query incidents params
func (o *QueryIncidentsParams) WithSort(sort *string) *QueryIncidentsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query incidents params
func (o *QueryIncidentsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QueryIncidentsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
