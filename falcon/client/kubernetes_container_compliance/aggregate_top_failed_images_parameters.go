// Code generated by go-swagger; DO NOT EDIT.

package kubernetes_container_compliance

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

// NewAggregateTopFailedImagesParams creates a new AggregateTopFailedImagesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAggregateTopFailedImagesParams() *AggregateTopFailedImagesParams {
	return &AggregateTopFailedImagesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAggregateTopFailedImagesParamsWithTimeout creates a new AggregateTopFailedImagesParams object
// with the ability to set a timeout on a request.
func NewAggregateTopFailedImagesParamsWithTimeout(timeout time.Duration) *AggregateTopFailedImagesParams {
	return &AggregateTopFailedImagesParams{
		timeout: timeout,
	}
}

// NewAggregateTopFailedImagesParamsWithContext creates a new AggregateTopFailedImagesParams object
// with the ability to set a context for a request.
func NewAggregateTopFailedImagesParamsWithContext(ctx context.Context) *AggregateTopFailedImagesParams {
	return &AggregateTopFailedImagesParams{
		Context: ctx,
	}
}

// NewAggregateTopFailedImagesParamsWithHTTPClient creates a new AggregateTopFailedImagesParams object
// with the ability to set a custom HTTPClient for a request.
func NewAggregateTopFailedImagesParamsWithHTTPClient(client *http.Client) *AggregateTopFailedImagesParams {
	return &AggregateTopFailedImagesParams{
		HTTPClient: client,
	}
}

/*
AggregateTopFailedImagesParams contains all the parameters to send to the API endpoint

	for the aggregate top failed images operation.

	Typically these are written to a http.Request.
*/
type AggregateTopFailedImagesParams struct {

	/* Filter.

	   FQL filter expression used to limit the results. Filter fields include: cid, cloud_info.cloud_account_id, cloud_info.cloud_provider, cloud_info.cloud_region, cloud_info.cluster_id, cloud_info.cluster_name, cloud_info.cluster_type, compliance_finding.asset_type, compliance_finding.framework_name, compliance_finding.framework_name_version, compliance_finding.framework_version, compliance_finding.severity
	*/
	Filter *string

	/* Limit.

	   The maximum number of records to return. (1-100) Default is 10.
	*/
	Limit *int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the aggregate top failed images params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AggregateTopFailedImagesParams) WithDefaults() *AggregateTopFailedImagesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the aggregate top failed images params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AggregateTopFailedImagesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the aggregate top failed images params
func (o *AggregateTopFailedImagesParams) WithTimeout(timeout time.Duration) *AggregateTopFailedImagesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the aggregate top failed images params
func (o *AggregateTopFailedImagesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the aggregate top failed images params
func (o *AggregateTopFailedImagesParams) WithContext(ctx context.Context) *AggregateTopFailedImagesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the aggregate top failed images params
func (o *AggregateTopFailedImagesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the aggregate top failed images params
func (o *AggregateTopFailedImagesParams) WithHTTPClient(client *http.Client) *AggregateTopFailedImagesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the aggregate top failed images params
func (o *AggregateTopFailedImagesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the aggregate top failed images params
func (o *AggregateTopFailedImagesParams) WithFilter(filter *string) *AggregateTopFailedImagesParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the aggregate top failed images params
func (o *AggregateTopFailedImagesParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the aggregate top failed images params
func (o *AggregateTopFailedImagesParams) WithLimit(limit *int64) *AggregateTopFailedImagesParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the aggregate top failed images params
func (o *AggregateTopFailedImagesParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WriteToRequest writes these params to a swagger request
func (o *AggregateTopFailedImagesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
