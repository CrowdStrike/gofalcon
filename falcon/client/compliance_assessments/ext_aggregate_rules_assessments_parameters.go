// Code generated by go-swagger; DO NOT EDIT.

package compliance_assessments

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
)

// NewExtAggregateRulesAssessmentsParams creates a new ExtAggregateRulesAssessmentsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewExtAggregateRulesAssessmentsParams() *ExtAggregateRulesAssessmentsParams {
	return &ExtAggregateRulesAssessmentsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewExtAggregateRulesAssessmentsParamsWithTimeout creates a new ExtAggregateRulesAssessmentsParams object
// with the ability to set a timeout on a request.
func NewExtAggregateRulesAssessmentsParamsWithTimeout(timeout time.Duration) *ExtAggregateRulesAssessmentsParams {
	return &ExtAggregateRulesAssessmentsParams{
		timeout: timeout,
	}
}

// NewExtAggregateRulesAssessmentsParamsWithContext creates a new ExtAggregateRulesAssessmentsParams object
// with the ability to set a context for a request.
func NewExtAggregateRulesAssessmentsParamsWithContext(ctx context.Context) *ExtAggregateRulesAssessmentsParams {
	return &ExtAggregateRulesAssessmentsParams{
		Context: ctx,
	}
}

// NewExtAggregateRulesAssessmentsParamsWithHTTPClient creates a new ExtAggregateRulesAssessmentsParams object
// with the ability to set a custom HTTPClient for a request.
func NewExtAggregateRulesAssessmentsParamsWithHTTPClient(client *http.Client) *ExtAggregateRulesAssessmentsParams {
	return &ExtAggregateRulesAssessmentsParams{
		HTTPClient: client,
	}
}

/*
ExtAggregateRulesAssessmentsParams contains all the parameters to send to the API endpoint

	for the ext aggregate rules assessments operation.

	Typically these are written to a http.Request.
*/
type ExtAggregateRulesAssessmentsParams struct {

	/* Filter.

	     Filter results using a query in Falcon Query Language (FQL). Supported Filters:
	cloud_info.cloud_provider: Cloud provider
	image_repository: Image repository
	cloud_info.cloud_region: Cloud region
	cloud_info.cloud_account_id: Cloud account ID
	compliance_finding.severity: Compliance finding severity; available values: 4, 3, 2, 1 (4: critical, 3: high, 2: medium, 1:low)
	image_tag: Image tag
	cloud_info.cluster_name: Kubernetes cluster name
	image_id: Image ID
	image_registry: Image registry
	compliance_finding.name: Compliance finding Name
	compliance_finding.framework: Compliance finding framework (available values: CIS)
	cid: Customer ID
	compliance_finding.id: Compliance finding ID
	image_digest: Image digest (sha256 digest)

	*/
	Filter *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ext aggregate rules assessments params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExtAggregateRulesAssessmentsParams) WithDefaults() *ExtAggregateRulesAssessmentsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ext aggregate rules assessments params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExtAggregateRulesAssessmentsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the ext aggregate rules assessments params
func (o *ExtAggregateRulesAssessmentsParams) WithTimeout(timeout time.Duration) *ExtAggregateRulesAssessmentsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ext aggregate rules assessments params
func (o *ExtAggregateRulesAssessmentsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ext aggregate rules assessments params
func (o *ExtAggregateRulesAssessmentsParams) WithContext(ctx context.Context) *ExtAggregateRulesAssessmentsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ext aggregate rules assessments params
func (o *ExtAggregateRulesAssessmentsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ext aggregate rules assessments params
func (o *ExtAggregateRulesAssessmentsParams) WithHTTPClient(client *http.Client) *ExtAggregateRulesAssessmentsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ext aggregate rules assessments params
func (o *ExtAggregateRulesAssessmentsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the ext aggregate rules assessments params
func (o *ExtAggregateRulesAssessmentsParams) WithFilter(filter *string) *ExtAggregateRulesAssessmentsParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the ext aggregate rules assessments params
func (o *ExtAggregateRulesAssessmentsParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WriteToRequest writes these params to a swagger request
func (o *ExtAggregateRulesAssessmentsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
