// Code generated by go-swagger; DO NOT EDIT.

package custom_ioa

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

// NewQueryRulesMixin0Params creates a new QueryRulesMixin0Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryRulesMixin0Params() *QueryRulesMixin0Params {
	return &QueryRulesMixin0Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryRulesMixin0ParamsWithTimeout creates a new QueryRulesMixin0Params object
// with the ability to set a timeout on a request.
func NewQueryRulesMixin0ParamsWithTimeout(timeout time.Duration) *QueryRulesMixin0Params {
	return &QueryRulesMixin0Params{
		timeout: timeout,
	}
}

// NewQueryRulesMixin0ParamsWithContext creates a new QueryRulesMixin0Params object
// with the ability to set a context for a request.
func NewQueryRulesMixin0ParamsWithContext(ctx context.Context) *QueryRulesMixin0Params {
	return &QueryRulesMixin0Params{
		Context: ctx,
	}
}

// NewQueryRulesMixin0ParamsWithHTTPClient creates a new QueryRulesMixin0Params object
// with the ability to set a custom HTTPClient for a request.
func NewQueryRulesMixin0ParamsWithHTTPClient(client *http.Client) *QueryRulesMixin0Params {
	return &QueryRulesMixin0Params{
		HTTPClient: client,
	}
}

/*
QueryRulesMixin0Params contains all the parameters to send to the API endpoint

	for the query rules mixin0 operation.

	Typically these are written to a http.Request.
*/
type QueryRulesMixin0Params struct {

	/* Filter.

	   FQL query specifying the filter parameters. Filter term criteria: [enabled platform name description rules.action_label rules.name rules.description rules.pattern_severity rules.ruletype_name rules.enabled]. Filter range criteria: created_on, modified_on; use any common date format, such as '2010-05-15T14:55:21.892315096Z'.
	*/
	Filter *string

	/* Limit.

	   Number of IDs to return
	*/
	Limit *int64

	/* Offset.

	   Starting index of overall result set from which to return IDs
	*/
	Offset *string

	/* Q.

	   Match query criteria, which includes all the filter string fields
	*/
	Q *string

	/* Sort.

	   Possible order by fields: {rules.current_version.description, rules.current_version.action_label, rules.current_version.modified_on, rules.created_on, rules.current_version.name, rules.created_by, rules.current_version.pattern_severity, rules.current_version.modified_by, rules.ruletype_name, rules.enabled}
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query rules mixin0 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryRulesMixin0Params) WithDefaults() *QueryRulesMixin0Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query rules mixin0 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryRulesMixin0Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query rules mixin0 params
func (o *QueryRulesMixin0Params) WithTimeout(timeout time.Duration) *QueryRulesMixin0Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query rules mixin0 params
func (o *QueryRulesMixin0Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query rules mixin0 params
func (o *QueryRulesMixin0Params) WithContext(ctx context.Context) *QueryRulesMixin0Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query rules mixin0 params
func (o *QueryRulesMixin0Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query rules mixin0 params
func (o *QueryRulesMixin0Params) WithHTTPClient(client *http.Client) *QueryRulesMixin0Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query rules mixin0 params
func (o *QueryRulesMixin0Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query rules mixin0 params
func (o *QueryRulesMixin0Params) WithFilter(filter *string) *QueryRulesMixin0Params {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query rules mixin0 params
func (o *QueryRulesMixin0Params) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the query rules mixin0 params
func (o *QueryRulesMixin0Params) WithLimit(limit *int64) *QueryRulesMixin0Params {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query rules mixin0 params
func (o *QueryRulesMixin0Params) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query rules mixin0 params
func (o *QueryRulesMixin0Params) WithOffset(offset *string) *QueryRulesMixin0Params {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query rules mixin0 params
func (o *QueryRulesMixin0Params) SetOffset(offset *string) {
	o.Offset = offset
}

// WithQ adds the q to the query rules mixin0 params
func (o *QueryRulesMixin0Params) WithQ(q *string) *QueryRulesMixin0Params {
	o.SetQ(q)
	return o
}

// SetQ adds the q to the query rules mixin0 params
func (o *QueryRulesMixin0Params) SetQ(q *string) {
	o.Q = q
}

// WithSort adds the sort to the query rules mixin0 params
func (o *QueryRulesMixin0Params) WithSort(sort *string) *QueryRulesMixin0Params {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query rules mixin0 params
func (o *QueryRulesMixin0Params) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QueryRulesMixin0Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if o.Q != nil {

		// query param q
		var qrQ string

		if o.Q != nil {
			qrQ = *o.Q
		}
		qQ := qrQ
		if qQ != "" {

			if err := r.SetQueryParam("q", qQ); err != nil {
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
