// Code generated by go-swagger; DO NOT EDIT.

package mssp

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

// NewQueryUserGroupsParams creates a new QueryUserGroupsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryUserGroupsParams() *QueryUserGroupsParams {
	return &QueryUserGroupsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryUserGroupsParamsWithTimeout creates a new QueryUserGroupsParams object
// with the ability to set a timeout on a request.
func NewQueryUserGroupsParamsWithTimeout(timeout time.Duration) *QueryUserGroupsParams {
	return &QueryUserGroupsParams{
		timeout: timeout,
	}
}

// NewQueryUserGroupsParamsWithContext creates a new QueryUserGroupsParams object
// with the ability to set a context for a request.
func NewQueryUserGroupsParamsWithContext(ctx context.Context) *QueryUserGroupsParams {
	return &QueryUserGroupsParams{
		Context: ctx,
	}
}

// NewQueryUserGroupsParamsWithHTTPClient creates a new QueryUserGroupsParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryUserGroupsParamsWithHTTPClient(client *http.Client) *QueryUserGroupsParams {
	return &QueryUserGroupsParams{
		HTTPClient: client,
	}
}

/* QueryUserGroupsParams contains all the parameters to send to the API endpoint
   for the query user groups operation.

   Typically these are written to a http.Request.
*/
type QueryUserGroupsParams struct {

	/* Limit.

	   Maximum number of results to return

	   Default: 10
	*/
	Limit *int64

	/* Name.

	   Name to lookup groups for
	*/
	Name *string

	/* Offset.

	   Starting index of overall result set from which to return ids
	*/
	Offset *int64

	/* Sort.

	   The sort expression used to sort the results

	   Default: "name|asc"
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query user groups params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryUserGroupsParams) WithDefaults() *QueryUserGroupsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query user groups params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryUserGroupsParams) SetDefaults() {
	var (
		limitDefault = int64(10)

		offsetDefault = int64(0)

		sortDefault = string("name|asc")
	)

	val := QueryUserGroupsParams{
		Limit:  &limitDefault,
		Offset: &offsetDefault,
		Sort:   &sortDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the query user groups params
func (o *QueryUserGroupsParams) WithTimeout(timeout time.Duration) *QueryUserGroupsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query user groups params
func (o *QueryUserGroupsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query user groups params
func (o *QueryUserGroupsParams) WithContext(ctx context.Context) *QueryUserGroupsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query user groups params
func (o *QueryUserGroupsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query user groups params
func (o *QueryUserGroupsParams) WithHTTPClient(client *http.Client) *QueryUserGroupsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query user groups params
func (o *QueryUserGroupsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLimit adds the limit to the query user groups params
func (o *QueryUserGroupsParams) WithLimit(limit *int64) *QueryUserGroupsParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query user groups params
func (o *QueryUserGroupsParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithName adds the name to the query user groups params
func (o *QueryUserGroupsParams) WithName(name *string) *QueryUserGroupsParams {
	o.SetName(name)
	return o
}

// SetName adds the name to the query user groups params
func (o *QueryUserGroupsParams) SetName(name *string) {
	o.Name = name
}

// WithOffset adds the offset to the query user groups params
func (o *QueryUserGroupsParams) WithOffset(offset *int64) *QueryUserGroupsParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query user groups params
func (o *QueryUserGroupsParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the query user groups params
func (o *QueryUserGroupsParams) WithSort(sort *string) *QueryUserGroupsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query user groups params
func (o *QueryUserGroupsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QueryUserGroupsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

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

	if o.Name != nil {

		// query param name
		var qrName string

		if o.Name != nil {
			qrName = *o.Name
		}
		qName := qrName
		if qName != "" {

			if err := r.SetQueryParam("name", qName); err != nil {
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
