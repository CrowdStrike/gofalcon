// Code generated by go-swagger; DO NOT EDIT.

package host_migration

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

// NewGetHostMigrationIDsV1Params creates a new GetHostMigrationIDsV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetHostMigrationIDsV1Params() *GetHostMigrationIDsV1Params {
	return &GetHostMigrationIDsV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetHostMigrationIDsV1ParamsWithTimeout creates a new GetHostMigrationIDsV1Params object
// with the ability to set a timeout on a request.
func NewGetHostMigrationIDsV1ParamsWithTimeout(timeout time.Duration) *GetHostMigrationIDsV1Params {
	return &GetHostMigrationIDsV1Params{
		timeout: timeout,
	}
}

// NewGetHostMigrationIDsV1ParamsWithContext creates a new GetHostMigrationIDsV1Params object
// with the ability to set a context for a request.
func NewGetHostMigrationIDsV1ParamsWithContext(ctx context.Context) *GetHostMigrationIDsV1Params {
	return &GetHostMigrationIDsV1Params{
		Context: ctx,
	}
}

// NewGetHostMigrationIDsV1ParamsWithHTTPClient creates a new GetHostMigrationIDsV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewGetHostMigrationIDsV1ParamsWithHTTPClient(client *http.Client) *GetHostMigrationIDsV1Params {
	return &GetHostMigrationIDsV1Params{
		HTTPClient: client,
	}
}

/*
GetHostMigrationIDsV1Params contains all the parameters to send to the API endpoint

	for the get host migration i ds v1 operation.

	Typically these are written to a http.Request.
*/
type GetHostMigrationIDsV1Params struct {

	/* Filter.

	   The filter expression that should be used to limit the results. Valid fields: host_migration_id, groups, hostgroups, hostname, status, migration_id, created_time, static_host_groups, target_cid, source_cid, id
	*/
	Filter *string

	/* ID.

	   The migration job to query
	*/
	ID string

	/* Limit.

	   The maximum records to return. [1-10000]
	*/
	Limit *int64

	/* Offset.

	   The offset to start retrieving records from
	*/
	Offset *int64

	/* Sort.

	   The property to sort by.
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get host migration i ds v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetHostMigrationIDsV1Params) WithDefaults() *GetHostMigrationIDsV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get host migration i ds v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetHostMigrationIDsV1Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) WithTimeout(timeout time.Duration) *GetHostMigrationIDsV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) WithContext(ctx context.Context) *GetHostMigrationIDsV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) WithHTTPClient(client *http.Client) *GetHostMigrationIDsV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) WithFilter(filter *string) *GetHostMigrationIDsV1Params {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) SetFilter(filter *string) {
	o.Filter = filter
}

// WithID adds the id to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) WithID(id string) *GetHostMigrationIDsV1Params {
	o.SetID(id)
	return o
}

// SetID adds the id to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) SetID(id string) {
	o.ID = id
}

// WithLimit adds the limit to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) WithLimit(limit *int64) *GetHostMigrationIDsV1Params {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) WithOffset(offset *int64) *GetHostMigrationIDsV1Params {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) WithSort(sort *string) *GetHostMigrationIDsV1Params {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get host migration i ds v1 params
func (o *GetHostMigrationIDsV1Params) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *GetHostMigrationIDsV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// query param id
	qrID := o.ID
	qID := qrID
	if qID != "" {

		if err := r.SetQueryParam("id", qID); err != nil {
			return err
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
