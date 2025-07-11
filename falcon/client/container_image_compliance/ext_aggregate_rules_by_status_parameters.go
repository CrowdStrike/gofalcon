// Code generated by go-swagger; DO NOT EDIT.

package container_image_compliance

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

// NewExtAggregateRulesByStatusParams creates a new ExtAggregateRulesByStatusParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewExtAggregateRulesByStatusParams() *ExtAggregateRulesByStatusParams {
	return &ExtAggregateRulesByStatusParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewExtAggregateRulesByStatusParamsWithTimeout creates a new ExtAggregateRulesByStatusParams object
// with the ability to set a timeout on a request.
func NewExtAggregateRulesByStatusParamsWithTimeout(timeout time.Duration) *ExtAggregateRulesByStatusParams {
	return &ExtAggregateRulesByStatusParams{
		timeout: timeout,
	}
}

// NewExtAggregateRulesByStatusParamsWithContext creates a new ExtAggregateRulesByStatusParams object
// with the ability to set a context for a request.
func NewExtAggregateRulesByStatusParamsWithContext(ctx context.Context) *ExtAggregateRulesByStatusParams {
	return &ExtAggregateRulesByStatusParams{
		Context: ctx,
	}
}

// NewExtAggregateRulesByStatusParamsWithHTTPClient creates a new ExtAggregateRulesByStatusParams object
// with the ability to set a custom HTTPClient for a request.
func NewExtAggregateRulesByStatusParamsWithHTTPClient(client *http.Client) *ExtAggregateRulesByStatusParams {
	return &ExtAggregateRulesByStatusParams{
		HTTPClient: client,
	}
}

/*
ExtAggregateRulesByStatusParams contains all the parameters to send to the API endpoint

	for the ext aggregate rules by status operation.

	Typically these are written to a http.Request.
*/
type ExtAggregateRulesByStatusParams struct {

	/* Filter.

	     Filter results using a query in Falcon Query Language (FQL). Supported Filters:
	image_registry: Image registry
	image_repository: Image repository
	image_tag: Image tag
	cloud_info.cloud_provider: Cloud provider
	compliance_finding.id: Compliance finding ID
	image_id: Image ID
	cid: Customer ID
	compliance_finding.framework: Compliance finding framework (available values: CIS)
	compliance_finding.severity: Compliance finding severity; available values: 4, 3, 2, 1 (4: critical, 3: high, 2: medium, 1:low)
	container_id: Container ID
	cloud_info.cloud_account_id: Cloud account ID
	compliance_finding.name: Compliance finding Name
	cloud_info.cloud_region: Cloud region
	cloud_info.cluster_name: Kubernetes cluster name
	image_digest: Image digest (sha256 digest)
	container_name: Container name
	asset_type: asset type (container, image)

	*/
	Filter *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ext aggregate rules by status params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExtAggregateRulesByStatusParams) WithDefaults() *ExtAggregateRulesByStatusParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ext aggregate rules by status params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExtAggregateRulesByStatusParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the ext aggregate rules by status params
func (o *ExtAggregateRulesByStatusParams) WithTimeout(timeout time.Duration) *ExtAggregateRulesByStatusParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ext aggregate rules by status params
func (o *ExtAggregateRulesByStatusParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ext aggregate rules by status params
func (o *ExtAggregateRulesByStatusParams) WithContext(ctx context.Context) *ExtAggregateRulesByStatusParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ext aggregate rules by status params
func (o *ExtAggregateRulesByStatusParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ext aggregate rules by status params
func (o *ExtAggregateRulesByStatusParams) WithHTTPClient(client *http.Client) *ExtAggregateRulesByStatusParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ext aggregate rules by status params
func (o *ExtAggregateRulesByStatusParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the ext aggregate rules by status params
func (o *ExtAggregateRulesByStatusParams) WithFilter(filter *string) *ExtAggregateRulesByStatusParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the ext aggregate rules by status params
func (o *ExtAggregateRulesByStatusParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WriteToRequest writes these params to a swagger request
func (o *ExtAggregateRulesByStatusParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
