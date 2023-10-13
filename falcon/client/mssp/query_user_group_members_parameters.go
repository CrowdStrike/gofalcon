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

// NewQueryUserGroupMembersParams creates a new QueryUserGroupMembersParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryUserGroupMembersParams() *QueryUserGroupMembersParams {
	return &QueryUserGroupMembersParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryUserGroupMembersParamsWithTimeout creates a new QueryUserGroupMembersParams object
// with the ability to set a timeout on a request.
func NewQueryUserGroupMembersParamsWithTimeout(timeout time.Duration) *QueryUserGroupMembersParams {
	return &QueryUserGroupMembersParams{
		timeout: timeout,
	}
}

// NewQueryUserGroupMembersParamsWithContext creates a new QueryUserGroupMembersParams object
// with the ability to set a context for a request.
func NewQueryUserGroupMembersParamsWithContext(ctx context.Context) *QueryUserGroupMembersParams {
	return &QueryUserGroupMembersParams{
		Context: ctx,
	}
}

// NewQueryUserGroupMembersParamsWithHTTPClient creates a new QueryUserGroupMembersParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryUserGroupMembersParamsWithHTTPClient(client *http.Client) *QueryUserGroupMembersParams {
	return &QueryUserGroupMembersParams{
		HTTPClient: client,
	}
}

/* QueryUserGroupMembersParams contains all the parameters to send to the API endpoint
   for the query user group members operation.

   Typically these are written to a http.Request.
*/
type QueryUserGroupMembersParams struct {

	/* Limit.

	   Number of ids to return

	   Default: 10
	*/
	Limit *int64

	/* Offset.

	   Starting index of overall result set from which to return ids
	*/
	Offset *int64

	/* Sort.

	   The sort expression used to sort the results

	   Default: "last_modified_timestamp|desc"
	*/
	Sort *string

	/* UserUUID.

	   User UUID to lookup associated user group ID
	*/
	UserUUID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query user group members params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryUserGroupMembersParams) WithDefaults() *QueryUserGroupMembersParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query user group members params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryUserGroupMembersParams) SetDefaults() {
	var (
		limitDefault = int64(10)

		offsetDefault = int64(0)

		sortDefault = string("last_modified_timestamp|desc")
	)

	val := QueryUserGroupMembersParams{
		Limit:  &limitDefault,
		Offset: &offsetDefault,
		Sort:   &sortDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the query user group members params
func (o *QueryUserGroupMembersParams) WithTimeout(timeout time.Duration) *QueryUserGroupMembersParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query user group members params
func (o *QueryUserGroupMembersParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query user group members params
func (o *QueryUserGroupMembersParams) WithContext(ctx context.Context) *QueryUserGroupMembersParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query user group members params
func (o *QueryUserGroupMembersParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query user group members params
func (o *QueryUserGroupMembersParams) WithHTTPClient(client *http.Client) *QueryUserGroupMembersParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query user group members params
func (o *QueryUserGroupMembersParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLimit adds the limit to the query user group members params
func (o *QueryUserGroupMembersParams) WithLimit(limit *int64) *QueryUserGroupMembersParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query user group members params
func (o *QueryUserGroupMembersParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query user group members params
func (o *QueryUserGroupMembersParams) WithOffset(offset *int64) *QueryUserGroupMembersParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query user group members params
func (o *QueryUserGroupMembersParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the query user group members params
func (o *QueryUserGroupMembersParams) WithSort(sort *string) *QueryUserGroupMembersParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query user group members params
func (o *QueryUserGroupMembersParams) SetSort(sort *string) {
	o.Sort = sort
}

// WithUserUUID adds the userUUID to the query user group members params
func (o *QueryUserGroupMembersParams) WithUserUUID(userUUID string) *QueryUserGroupMembersParams {
	o.SetUserUUID(userUUID)
	return o
}

// SetUserUUID adds the userUuid to the query user group members params
func (o *QueryUserGroupMembersParams) SetUserUUID(userUUID string) {
	o.UserUUID = userUUID
}

// WriteToRequest writes these params to a swagger request
func (o *QueryUserGroupMembersParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// query param user_uuid
	qrUserUUID := o.UserUUID
	qUserUUID := qrUserUUID
	if qUserUUID != "" {

		if err := r.SetQueryParam("user_uuid", qUserUUID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
