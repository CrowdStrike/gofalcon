// Code generated by go-swagger; DO NOT EDIT.

package cloud_security_assets

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

// NewCloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams creates a new CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams() *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	return &CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParamsWithTimeout creates a new CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams object
// with the ability to set a timeout on a request.
func NewCloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParamsWithTimeout(timeout time.Duration) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	return &CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams{
		timeout: timeout,
	}
}

// NewCloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParamsWithContext creates a new CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams object
// with the ability to set a context for a request.
func NewCloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParamsWithContext(ctx context.Context) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	return &CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams{
		Context: ctx,
	}
}

// NewCloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParamsWithHTTPClient creates a new CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewCloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParamsWithHTTPClient(client *http.Client) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	return &CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams{
		HTTPClient: client,
	}
}

/*
CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams contains all the parameters to send to the API endpoint

	for the cloud security assets combined compliance by account region and resource type get operation.

	Typically these are written to a http.Request.
*/
type CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams struct {

	/* After.

	   token-based pagination. use for paginating through an entire result set. Use only one of 'offset' and 'after' parameters for paginating
	*/
	After *string

	/* Filter.

	     FQL string to filter on asset contents. Filterable fields include:
	- `account_id`
	- `account_name`
	- `assessment_id`
	- `business_impact`
	- `cloud_group`
	- `cloud_label`
	- `cloud_label_id`
	- `cloud_provider`
	- `cloud_scope`
	- `compliant`
	- `control.benchmark.name`
	- `control.benchmark.version`
	- `control.framework`
	- `control.name`
	- `control.type`
	- `control.version`
	- `environment`
	- `last_evaluated`
	- `region`
	- `resource_provider`
	- `resource_type`
	- `resource_type_name`
	- `service`
	- `service_category`
	- `severities`
	*/
	Filter *string

	/* IncludeFailingIomSeverityCounts.

	   Include counts of failing IOMs by severity level
	*/
	IncludeFailingIomSeverityCounts *bool

	/* Limit.

	   The maximum number of items to return. When not specified or 0, 20 is used. When larger than 10000, 10000 is used.

	   Default: 20
	*/
	Limit *int64

	/* Offset.

	   Offset returned controls. Use only one of 'offset' and 'after' parameter for paginating. 'offset' can only be used on offsets < 10,000. For paginating through the entire result set, use 'after' parameter
	*/
	Offset *int64

	/* Sort.

	     Sort expression in format: field|direction (e.g., last_evaluated|desc). Allowed sort fields:
	- `account_id`
	- `account_name`
	- `assessment_id`
	- `cloud_provider`
	- `control.benchmark.name`
	- `control.benchmark.version`
	- `control.framework`
	- `control.name`
	- `control.type`
	- `control.version`
	- `last_evaluated`
	- `region`
	- `resource_counts.compliant`
	- `resource_counts.non_compliant`
	- `resource_counts.total`
	- `resource_provider`
	- `resource_type`
	- `resource_type_name`
	- `service`
	- `service_category`
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the cloud security assets combined compliance by account region and resource type get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WithDefaults() *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the cloud security assets combined compliance by account region and resource type get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) SetDefaults() {
	var (
		includeFailingIomSeverityCountsDefault = bool(false)

		limitDefault = int64(20)
	)

	val := CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams{
		IncludeFailingIomSeverityCounts: &includeFailingIomSeverityCountsDefault,
		Limit:                           &limitDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WithTimeout(timeout time.Duration) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WithContext(ctx context.Context) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WithHTTPClient(client *http.Client) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAfter adds the after to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WithAfter(after *string) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	o.SetAfter(after)
	return o
}

// SetAfter adds the after to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) SetAfter(after *string) {
	o.After = after
}

// WithFilter adds the filter to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WithFilter(filter *string) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithIncludeFailingIomSeverityCounts adds the includeFailingIomSeverityCounts to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WithIncludeFailingIomSeverityCounts(includeFailingIomSeverityCounts *bool) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	o.SetIncludeFailingIomSeverityCounts(includeFailingIomSeverityCounts)
	return o
}

// SetIncludeFailingIomSeverityCounts adds the includeFailingIomSeverityCounts to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) SetIncludeFailingIomSeverityCounts(includeFailingIomSeverityCounts *bool) {
	o.IncludeFailingIomSeverityCounts = includeFailingIomSeverityCounts
}

// WithLimit adds the limit to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WithLimit(limit *int64) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WithOffset(offset *int64) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WithSort(sort *string) *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the cloud security assets combined compliance by account region and resource type get params
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *CloudSecurityAssetsCombinedComplianceByAccountRegionAndResourceTypeGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if o.IncludeFailingIomSeverityCounts != nil {

		// query param include_failing_iom_severity_counts
		var qrIncludeFailingIomSeverityCounts bool

		if o.IncludeFailingIomSeverityCounts != nil {
			qrIncludeFailingIomSeverityCounts = *o.IncludeFailingIomSeverityCounts
		}
		qIncludeFailingIomSeverityCounts := swag.FormatBool(qrIncludeFailingIomSeverityCounts)
		if qIncludeFailingIomSeverityCounts != "" {

			if err := r.SetQueryParam("include_failing_iom_severity_counts", qIncludeFailingIomSeverityCounts); err != nil {
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
