// Code generated by go-swagger; DO NOT EDIT.

package quick_scan_pro

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

// NewQueryScanResultsParams creates a new QueryScanResultsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryScanResultsParams() *QueryScanResultsParams {
	return &QueryScanResultsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryScanResultsParamsWithTimeout creates a new QueryScanResultsParams object
// with the ability to set a timeout on a request.
func NewQueryScanResultsParamsWithTimeout(timeout time.Duration) *QueryScanResultsParams {
	return &QueryScanResultsParams{
		timeout: timeout,
	}
}

// NewQueryScanResultsParamsWithContext creates a new QueryScanResultsParams object
// with the ability to set a context for a request.
func NewQueryScanResultsParamsWithContext(ctx context.Context) *QueryScanResultsParams {
	return &QueryScanResultsParams{
		Context: ctx,
	}
}

// NewQueryScanResultsParamsWithHTTPClient creates a new QueryScanResultsParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryScanResultsParamsWithHTTPClient(client *http.Client) *QueryScanResultsParams {
	return &QueryScanResultsParams{
		HTTPClient: client,
	}
}

/*
QueryScanResultsParams contains all the parameters to send to the API endpoint

	for the query scan results operation.

	Typically these are written to a http.Request.
*/
type QueryScanResultsParams struct {

	/* Filter.

	     Empty value means to not filter on anything
	Available filter fields that supports match (~): _all, mitre_attacks.description
	Available filter fields that supports exact match: cid,sha256,id,status,type,entity,executor,verdict,verdict_reason,verdict_source,artifacts.file_artifacts.sha256,artifacts.file_artifacts.filename,artifacts.file_artifacts.verdict,artifacts.file_artifacts.verdict_reasons,artifacts.url_artifacts.url,artifacts.url_artifacts.verdict,artifacts.url_artifacts.verdict_reasons,mitre_attacks.attack_id,mitre_attacks.attack_id_wiki,mitre_attacks.tactic,mitre_attacks.technique,mitre_attacks.capec_id,mitre_attacks.parent.attack_id,mitre_attacks.parent.attack_id_wiki,mitre_attacks.parent.technique
	Available filter fields that supports wildcard (*): mitre_attacks.description
	Available filter fields that supports range comparisons (>, <, >=, <=): created_timestamp, updated_timestamp
	All filter fields and operations supports negation (!).
	_all field is used to search between all fields.
	*/
	Filter string

	/* Limit.

	   Maximum number of IDs to return. Max: 5000.

	   Default: 50
	*/
	Limit *int64

	/* Offset.

	   The offset to start retrieving ids from.
	*/
	Offset *int64

	/* Sort.

	   Sort order: `asc` or `desc`. Sort supported fields `created_timestamp`
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query scan results params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryScanResultsParams) WithDefaults() *QueryScanResultsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query scan results params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryScanResultsParams) SetDefaults() {
	var (
		limitDefault = int64(50)
	)

	val := QueryScanResultsParams{
		Limit: &limitDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the query scan results params
func (o *QueryScanResultsParams) WithTimeout(timeout time.Duration) *QueryScanResultsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query scan results params
func (o *QueryScanResultsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query scan results params
func (o *QueryScanResultsParams) WithContext(ctx context.Context) *QueryScanResultsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query scan results params
func (o *QueryScanResultsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query scan results params
func (o *QueryScanResultsParams) WithHTTPClient(client *http.Client) *QueryScanResultsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query scan results params
func (o *QueryScanResultsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query scan results params
func (o *QueryScanResultsParams) WithFilter(filter string) *QueryScanResultsParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query scan results params
func (o *QueryScanResultsParams) SetFilter(filter string) {
	o.Filter = filter
}

// WithLimit adds the limit to the query scan results params
func (o *QueryScanResultsParams) WithLimit(limit *int64) *QueryScanResultsParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query scan results params
func (o *QueryScanResultsParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query scan results params
func (o *QueryScanResultsParams) WithOffset(offset *int64) *QueryScanResultsParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query scan results params
func (o *QueryScanResultsParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the query scan results params
func (o *QueryScanResultsParams) WithSort(sort *string) *QueryScanResultsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query scan results params
func (o *QueryScanResultsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QueryScanResultsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param filter
	qrFilter := o.Filter
	qFilter := qrFilter
	if qFilter != "" {

		if err := r.SetQueryParam("filter", qFilter); err != nil {
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
