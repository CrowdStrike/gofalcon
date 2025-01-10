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

// NewExtAggregateFailedRulesByClustersParams creates a new ExtAggregateFailedRulesByClustersParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewExtAggregateFailedRulesByClustersParams() *ExtAggregateFailedRulesByClustersParams {
	return &ExtAggregateFailedRulesByClustersParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewExtAggregateFailedRulesByClustersParamsWithTimeout creates a new ExtAggregateFailedRulesByClustersParams object
// with the ability to set a timeout on a request.
func NewExtAggregateFailedRulesByClustersParamsWithTimeout(timeout time.Duration) *ExtAggregateFailedRulesByClustersParams {
	return &ExtAggregateFailedRulesByClustersParams{
		timeout: timeout,
	}
}

// NewExtAggregateFailedRulesByClustersParamsWithContext creates a new ExtAggregateFailedRulesByClustersParams object
// with the ability to set a context for a request.
func NewExtAggregateFailedRulesByClustersParamsWithContext(ctx context.Context) *ExtAggregateFailedRulesByClustersParams {
	return &ExtAggregateFailedRulesByClustersParams{
		Context: ctx,
	}
}

// NewExtAggregateFailedRulesByClustersParamsWithHTTPClient creates a new ExtAggregateFailedRulesByClustersParams object
// with the ability to set a custom HTTPClient for a request.
func NewExtAggregateFailedRulesByClustersParamsWithHTTPClient(client *http.Client) *ExtAggregateFailedRulesByClustersParams {
	return &ExtAggregateFailedRulesByClustersParams{
		HTTPClient: client,
	}
}

/*
ExtAggregateFailedRulesByClustersParams contains all the parameters to send to the API endpoint

	for the ext aggregate failed rules by clusters operation.

	Typically these are written to a http.Request.
*/
type ExtAggregateFailedRulesByClustersParams struct {

	/* Filter.

	     Filter results using a query in Falcon Query Language (FQL). Supported Filters:
	cloud_info.cloud_account_id: Cloud account ID
	image_digest: Image digest (sha256 digest)
	cloud_info.cloud_region: Cloud region
	cid: Customer ID
	image_registry: Image registry
	cloud_info.cloud_provider: Cloud provider
	compliance_finding.id: Compliance finding ID
	compliance_finding.framework: Compliance finding framework (available values: CIS)
	asset_type: asset type (container, image)
	compliance_finding.name: Compliance finding Name
	cloud_info.cluster_name: Kubernetes cluster name
	image_tag: Image tag
	image_id: Image ID
	image_repository: Image repository
	compliance_finding.severity: Compliance finding severity; available values: 4, 3, 2, 1 (4: critical, 3: high, 2: medium, 1:low)

	*/
	Filter *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ext aggregate failed rules by clusters params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExtAggregateFailedRulesByClustersParams) WithDefaults() *ExtAggregateFailedRulesByClustersParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ext aggregate failed rules by clusters params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExtAggregateFailedRulesByClustersParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the ext aggregate failed rules by clusters params
func (o *ExtAggregateFailedRulesByClustersParams) WithTimeout(timeout time.Duration) *ExtAggregateFailedRulesByClustersParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ext aggregate failed rules by clusters params
func (o *ExtAggregateFailedRulesByClustersParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ext aggregate failed rules by clusters params
func (o *ExtAggregateFailedRulesByClustersParams) WithContext(ctx context.Context) *ExtAggregateFailedRulesByClustersParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ext aggregate failed rules by clusters params
func (o *ExtAggregateFailedRulesByClustersParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ext aggregate failed rules by clusters params
func (o *ExtAggregateFailedRulesByClustersParams) WithHTTPClient(client *http.Client) *ExtAggregateFailedRulesByClustersParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ext aggregate failed rules by clusters params
func (o *ExtAggregateFailedRulesByClustersParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the ext aggregate failed rules by clusters params
func (o *ExtAggregateFailedRulesByClustersParams) WithFilter(filter *string) *ExtAggregateFailedRulesByClustersParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the ext aggregate failed rules by clusters params
func (o *ExtAggregateFailedRulesByClustersParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WriteToRequest writes these params to a swagger request
func (o *ExtAggregateFailedRulesByClustersParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
