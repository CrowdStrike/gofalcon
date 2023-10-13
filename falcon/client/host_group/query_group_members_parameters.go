// Code generated by go-swagger; DO NOT EDIT.

package host_group

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

// NewQueryGroupMembersParams creates a new QueryGroupMembersParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryGroupMembersParams() *QueryGroupMembersParams {
	return &QueryGroupMembersParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryGroupMembersParamsWithTimeout creates a new QueryGroupMembersParams object
// with the ability to set a timeout on a request.
func NewQueryGroupMembersParamsWithTimeout(timeout time.Duration) *QueryGroupMembersParams {
	return &QueryGroupMembersParams{
		timeout: timeout,
	}
}

// NewQueryGroupMembersParamsWithContext creates a new QueryGroupMembersParams object
// with the ability to set a context for a request.
func NewQueryGroupMembersParamsWithContext(ctx context.Context) *QueryGroupMembersParams {
	return &QueryGroupMembersParams{
		Context: ctx,
	}
}

// NewQueryGroupMembersParamsWithHTTPClient creates a new QueryGroupMembersParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryGroupMembersParamsWithHTTPClient(client *http.Client) *QueryGroupMembersParams {
	return &QueryGroupMembersParams{
		HTTPClient: client,
	}
}

/* QueryGroupMembersParams contains all the parameters to send to the API endpoint
   for the query group members operation.

   Typically these are written to a http.Request.
*/
type QueryGroupMembersParams struct {

	/* Filter.

	   The filter expression that should be used to limit the results
	*/
	Filter *string

	/* ID.

	   The ID of the Host Group to search for members of
	*/
	ID *string

	/* Limit.

	   The maximum records to return. [1-5000]
	*/
	Limit *int64

	/* Offset.

	   The offset to start retrieving records from
	*/
	Offset *int64

	/* Sort.

	   The property to sort by
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query group members params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryGroupMembersParams) WithDefaults() *QueryGroupMembersParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query group members params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryGroupMembersParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query group members params
func (o *QueryGroupMembersParams) WithTimeout(timeout time.Duration) *QueryGroupMembersParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query group members params
func (o *QueryGroupMembersParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query group members params
func (o *QueryGroupMembersParams) WithContext(ctx context.Context) *QueryGroupMembersParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query group members params
func (o *QueryGroupMembersParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query group members params
func (o *QueryGroupMembersParams) WithHTTPClient(client *http.Client) *QueryGroupMembersParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query group members params
func (o *QueryGroupMembersParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query group members params
func (o *QueryGroupMembersParams) WithFilter(filter *string) *QueryGroupMembersParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query group members params
func (o *QueryGroupMembersParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithID adds the id to the query group members params
func (o *QueryGroupMembersParams) WithID(id *string) *QueryGroupMembersParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the query group members params
func (o *QueryGroupMembersParams) SetID(id *string) {
	o.ID = id
}

// WithLimit adds the limit to the query group members params
func (o *QueryGroupMembersParams) WithLimit(limit *int64) *QueryGroupMembersParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query group members params
func (o *QueryGroupMembersParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query group members params
func (o *QueryGroupMembersParams) WithOffset(offset *int64) *QueryGroupMembersParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query group members params
func (o *QueryGroupMembersParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the query group members params
func (o *QueryGroupMembersParams) WithSort(sort *string) *QueryGroupMembersParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query group members params
func (o *QueryGroupMembersParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QueryGroupMembersParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if o.ID != nil {

		// query param id
		var qrID string

		if o.ID != nil {
			qrID = *o.ID
		}
		qID := qrID
		if qID != "" {

			if err := r.SetQueryParam("id", qID); err != nil {
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
