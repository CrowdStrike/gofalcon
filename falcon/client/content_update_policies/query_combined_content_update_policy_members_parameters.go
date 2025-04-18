// Code generated by go-swagger; DO NOT EDIT.

package content_update_policies

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

// NewQueryCombinedContentUpdatePolicyMembersParams creates a new QueryCombinedContentUpdatePolicyMembersParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryCombinedContentUpdatePolicyMembersParams() *QueryCombinedContentUpdatePolicyMembersParams {
	return &QueryCombinedContentUpdatePolicyMembersParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryCombinedContentUpdatePolicyMembersParamsWithTimeout creates a new QueryCombinedContentUpdatePolicyMembersParams object
// with the ability to set a timeout on a request.
func NewQueryCombinedContentUpdatePolicyMembersParamsWithTimeout(timeout time.Duration) *QueryCombinedContentUpdatePolicyMembersParams {
	return &QueryCombinedContentUpdatePolicyMembersParams{
		timeout: timeout,
	}
}

// NewQueryCombinedContentUpdatePolicyMembersParamsWithContext creates a new QueryCombinedContentUpdatePolicyMembersParams object
// with the ability to set a context for a request.
func NewQueryCombinedContentUpdatePolicyMembersParamsWithContext(ctx context.Context) *QueryCombinedContentUpdatePolicyMembersParams {
	return &QueryCombinedContentUpdatePolicyMembersParams{
		Context: ctx,
	}
}

// NewQueryCombinedContentUpdatePolicyMembersParamsWithHTTPClient creates a new QueryCombinedContentUpdatePolicyMembersParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryCombinedContentUpdatePolicyMembersParamsWithHTTPClient(client *http.Client) *QueryCombinedContentUpdatePolicyMembersParams {
	return &QueryCombinedContentUpdatePolicyMembersParams{
		HTTPClient: client,
	}
}

/*
QueryCombinedContentUpdatePolicyMembersParams contains all the parameters to send to the API endpoint

	for the query combined content update policy members operation.

	Typically these are written to a http.Request.
*/
type QueryCombinedContentUpdatePolicyMembersParams struct {

	/* Filter.

	   The filter expression that should be used to limit the results
	*/
	Filter *string

	/* ID.

	   The ID of the Content Update Policy to search for members of
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

// WithDefaults hydrates default values in the query combined content update policy members params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryCombinedContentUpdatePolicyMembersParams) WithDefaults() *QueryCombinedContentUpdatePolicyMembersParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query combined content update policy members params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryCombinedContentUpdatePolicyMembersParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) WithTimeout(timeout time.Duration) *QueryCombinedContentUpdatePolicyMembersParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) WithContext(ctx context.Context) *QueryCombinedContentUpdatePolicyMembersParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) WithHTTPClient(client *http.Client) *QueryCombinedContentUpdatePolicyMembersParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) WithFilter(filter *string) *QueryCombinedContentUpdatePolicyMembersParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithID adds the id to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) WithID(id *string) *QueryCombinedContentUpdatePolicyMembersParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) SetID(id *string) {
	o.ID = id
}

// WithLimit adds the limit to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) WithLimit(limit *int64) *QueryCombinedContentUpdatePolicyMembersParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) WithOffset(offset *int64) *QueryCombinedContentUpdatePolicyMembersParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) WithSort(sort *string) *QueryCombinedContentUpdatePolicyMembersParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query combined content update policy members params
func (o *QueryCombinedContentUpdatePolicyMembersParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QueryCombinedContentUpdatePolicyMembersParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
