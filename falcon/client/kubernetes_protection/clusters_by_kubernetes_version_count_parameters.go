// Code generated by go-swagger; DO NOT EDIT.

package kubernetes_protection

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

// NewClustersByKubernetesVersionCountParams creates a new ClustersByKubernetesVersionCountParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewClustersByKubernetesVersionCountParams() *ClustersByKubernetesVersionCountParams {
	return &ClustersByKubernetesVersionCountParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewClustersByKubernetesVersionCountParamsWithTimeout creates a new ClustersByKubernetesVersionCountParams object
// with the ability to set a timeout on a request.
func NewClustersByKubernetesVersionCountParamsWithTimeout(timeout time.Duration) *ClustersByKubernetesVersionCountParams {
	return &ClustersByKubernetesVersionCountParams{
		timeout: timeout,
	}
}

// NewClustersByKubernetesVersionCountParamsWithContext creates a new ClustersByKubernetesVersionCountParams object
// with the ability to set a context for a request.
func NewClustersByKubernetesVersionCountParamsWithContext(ctx context.Context) *ClustersByKubernetesVersionCountParams {
	return &ClustersByKubernetesVersionCountParams{
		Context: ctx,
	}
}

// NewClustersByKubernetesVersionCountParamsWithHTTPClient creates a new ClustersByKubernetesVersionCountParams object
// with the ability to set a custom HTTPClient for a request.
func NewClustersByKubernetesVersionCountParamsWithHTTPClient(client *http.Client) *ClustersByKubernetesVersionCountParams {
	return &ClustersByKubernetesVersionCountParams{
		HTTPClient: client,
	}
}

/*
ClustersByKubernetesVersionCountParams contains all the parameters to send to the API endpoint

	for the clusters by kubernetes version count operation.

	Typically these are written to a http.Request.
*/
type ClustersByKubernetesVersionCountParams struct {

	/* Filter.

	   Retrieve count of Kubernetes clusters that match a query in Falcon Query Language (FQL). Supported filters:  access,agent_status,agent_type,cid,cloud_account_id,cloud_name,cloud_region,cluster_id,cluster_name,cluster_status,container_count,iar_coverage,kubernetes_version,last_seen,management_status,node_count,pod_count,tags
	*/
	Filter *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the clusters by kubernetes version count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ClustersByKubernetesVersionCountParams) WithDefaults() *ClustersByKubernetesVersionCountParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the clusters by kubernetes version count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ClustersByKubernetesVersionCountParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the clusters by kubernetes version count params
func (o *ClustersByKubernetesVersionCountParams) WithTimeout(timeout time.Duration) *ClustersByKubernetesVersionCountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the clusters by kubernetes version count params
func (o *ClustersByKubernetesVersionCountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the clusters by kubernetes version count params
func (o *ClustersByKubernetesVersionCountParams) WithContext(ctx context.Context) *ClustersByKubernetesVersionCountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the clusters by kubernetes version count params
func (o *ClustersByKubernetesVersionCountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the clusters by kubernetes version count params
func (o *ClustersByKubernetesVersionCountParams) WithHTTPClient(client *http.Client) *ClustersByKubernetesVersionCountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the clusters by kubernetes version count params
func (o *ClustersByKubernetesVersionCountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the clusters by kubernetes version count params
func (o *ClustersByKubernetesVersionCountParams) WithFilter(filter *string) *ClustersByKubernetesVersionCountParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the clusters by kubernetes version count params
func (o *ClustersByKubernetesVersionCountParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WriteToRequest writes these params to a swagger request
func (o *ClustersByKubernetesVersionCountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
