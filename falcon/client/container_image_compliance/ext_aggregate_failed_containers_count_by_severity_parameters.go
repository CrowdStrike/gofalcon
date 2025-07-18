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

// NewExtAggregateFailedContainersCountBySeverityParams creates a new ExtAggregateFailedContainersCountBySeverityParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewExtAggregateFailedContainersCountBySeverityParams() *ExtAggregateFailedContainersCountBySeverityParams {
	return &ExtAggregateFailedContainersCountBySeverityParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewExtAggregateFailedContainersCountBySeverityParamsWithTimeout creates a new ExtAggregateFailedContainersCountBySeverityParams object
// with the ability to set a timeout on a request.
func NewExtAggregateFailedContainersCountBySeverityParamsWithTimeout(timeout time.Duration) *ExtAggregateFailedContainersCountBySeverityParams {
	return &ExtAggregateFailedContainersCountBySeverityParams{
		timeout: timeout,
	}
}

// NewExtAggregateFailedContainersCountBySeverityParamsWithContext creates a new ExtAggregateFailedContainersCountBySeverityParams object
// with the ability to set a context for a request.
func NewExtAggregateFailedContainersCountBySeverityParamsWithContext(ctx context.Context) *ExtAggregateFailedContainersCountBySeverityParams {
	return &ExtAggregateFailedContainersCountBySeverityParams{
		Context: ctx,
	}
}

// NewExtAggregateFailedContainersCountBySeverityParamsWithHTTPClient creates a new ExtAggregateFailedContainersCountBySeverityParams object
// with the ability to set a custom HTTPClient for a request.
func NewExtAggregateFailedContainersCountBySeverityParamsWithHTTPClient(client *http.Client) *ExtAggregateFailedContainersCountBySeverityParams {
	return &ExtAggregateFailedContainersCountBySeverityParams{
		HTTPClient: client,
	}
}

/*
ExtAggregateFailedContainersCountBySeverityParams contains all the parameters to send to the API endpoint

	for the ext aggregate failed containers count by severity operation.

	Typically these are written to a http.Request.
*/
type ExtAggregateFailedContainersCountBySeverityParams struct {

	/* Filter.

	     Filter results using a query in Falcon Query Language (FQL). Supported Filters:
	cloud_info.cloud_provider: Cloud provider
	compliance_finding.id: Compliance finding ID
	cloud_info.cloud_region: Cloud region
	image_registry: Image registry
	image_digest: Image digest (sha256 digest)
	cloud_info.cluster_name: Kubernetes cluster name
	compliance_finding.severity: Compliance finding severity; available values: 4, 3, 2, 1 (4: critical, 3: high, 2: medium, 1:low)
	compliance_finding.name: Compliance finding Name
	cloud_info.cloud_account_id: Cloud account ID
	image_id: Image ID
	image_repository: Image repository
	image_tag: Image tag
	compliance_finding.framework: Compliance finding framework (available values: CIS)
	cloud_info.namespace: Kubernetes namespace
	cid: Customer ID

	*/
	Filter *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ext aggregate failed containers count by severity params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExtAggregateFailedContainersCountBySeverityParams) WithDefaults() *ExtAggregateFailedContainersCountBySeverityParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ext aggregate failed containers count by severity params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExtAggregateFailedContainersCountBySeverityParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the ext aggregate failed containers count by severity params
func (o *ExtAggregateFailedContainersCountBySeverityParams) WithTimeout(timeout time.Duration) *ExtAggregateFailedContainersCountBySeverityParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ext aggregate failed containers count by severity params
func (o *ExtAggregateFailedContainersCountBySeverityParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ext aggregate failed containers count by severity params
func (o *ExtAggregateFailedContainersCountBySeverityParams) WithContext(ctx context.Context) *ExtAggregateFailedContainersCountBySeverityParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ext aggregate failed containers count by severity params
func (o *ExtAggregateFailedContainersCountBySeverityParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ext aggregate failed containers count by severity params
func (o *ExtAggregateFailedContainersCountBySeverityParams) WithHTTPClient(client *http.Client) *ExtAggregateFailedContainersCountBySeverityParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ext aggregate failed containers count by severity params
func (o *ExtAggregateFailedContainersCountBySeverityParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the ext aggregate failed containers count by severity params
func (o *ExtAggregateFailedContainersCountBySeverityParams) WithFilter(filter *string) *ExtAggregateFailedContainersCountBySeverityParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the ext aggregate failed containers count by severity params
func (o *ExtAggregateFailedContainersCountBySeverityParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WriteToRequest writes these params to a swagger request
func (o *ExtAggregateFailedContainersCountBySeverityParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
