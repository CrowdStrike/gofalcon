// Code generated by go-swagger; DO NOT EDIT.

package serverless_vulnerabilities

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

// NewGetCombinedVulnerabilitiesSARIFParams creates a new GetCombinedVulnerabilitiesSARIFParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetCombinedVulnerabilitiesSARIFParams() *GetCombinedVulnerabilitiesSARIFParams {
	return &GetCombinedVulnerabilitiesSARIFParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetCombinedVulnerabilitiesSARIFParamsWithTimeout creates a new GetCombinedVulnerabilitiesSARIFParams object
// with the ability to set a timeout on a request.
func NewGetCombinedVulnerabilitiesSARIFParamsWithTimeout(timeout time.Duration) *GetCombinedVulnerabilitiesSARIFParams {
	return &GetCombinedVulnerabilitiesSARIFParams{
		timeout: timeout,
	}
}

// NewGetCombinedVulnerabilitiesSARIFParamsWithContext creates a new GetCombinedVulnerabilitiesSARIFParams object
// with the ability to set a context for a request.
func NewGetCombinedVulnerabilitiesSARIFParamsWithContext(ctx context.Context) *GetCombinedVulnerabilitiesSARIFParams {
	return &GetCombinedVulnerabilitiesSARIFParams{
		Context: ctx,
	}
}

// NewGetCombinedVulnerabilitiesSARIFParamsWithHTTPClient creates a new GetCombinedVulnerabilitiesSARIFParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetCombinedVulnerabilitiesSARIFParamsWithHTTPClient(client *http.Client) *GetCombinedVulnerabilitiesSARIFParams {
	return &GetCombinedVulnerabilitiesSARIFParams{
		HTTPClient: client,
	}
}

/*
GetCombinedVulnerabilitiesSARIFParams contains all the parameters to send to the API endpoint

	for the get combined vulnerabilities s a r i f operation.

	Typically these are written to a http.Request.
*/
type GetCombinedVulnerabilitiesSARIFParams struct {

	/* Filter.

	   Filter lambda vulnerabilities using a query in Falcon Query Language (FQL).Supported filters:  application_name,application_name_version,cid,cloud_account_id,cloud_account_name,cloud_provider,cve_id,cvss_base_score,exprt_rating,first_seen_timestamp,function_name,function_resource_id,is_supported,is_valid_asset_id,layer,region,runtime,severity,timestamp,type
	*/
	Filter *string

	/* Limit.

	   The upper-bound on the number of records to retrieve.
	*/
	Limit *int64

	/* Offset.

	   The offset from where to begin.
	*/
	Offset *int64

	/* Sort.

	   The fields to sort the records on. Supported columns:  [application_name application_name_version cid cloud_account_id cloud_account_name cloud_provider cve_id cvss_base_score exprt_rating first_seen_timestamp function_resource_id is_supported layer region runtime severity timestamp type]
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get combined vulnerabilities s a r i f params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCombinedVulnerabilitiesSARIFParams) WithDefaults() *GetCombinedVulnerabilitiesSARIFParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get combined vulnerabilities s a r i f params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCombinedVulnerabilitiesSARIFParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) WithTimeout(timeout time.Duration) *GetCombinedVulnerabilitiesSARIFParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) WithContext(ctx context.Context) *GetCombinedVulnerabilitiesSARIFParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) WithHTTPClient(client *http.Client) *GetCombinedVulnerabilitiesSARIFParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) WithFilter(filter *string) *GetCombinedVulnerabilitiesSARIFParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) WithLimit(limit *int64) *GetCombinedVulnerabilitiesSARIFParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) WithOffset(offset *int64) *GetCombinedVulnerabilitiesSARIFParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) WithSort(sort *string) *GetCombinedVulnerabilitiesSARIFParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get combined vulnerabilities s a r i f params
func (o *GetCombinedVulnerabilitiesSARIFParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *GetCombinedVulnerabilitiesSARIFParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
