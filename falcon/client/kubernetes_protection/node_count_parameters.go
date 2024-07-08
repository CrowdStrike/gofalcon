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

// NewNodeCountParams creates a new NodeCountParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewNodeCountParams() *NodeCountParams {
	return &NodeCountParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewNodeCountParamsWithTimeout creates a new NodeCountParams object
// with the ability to set a timeout on a request.
func NewNodeCountParamsWithTimeout(timeout time.Duration) *NodeCountParams {
	return &NodeCountParams{
		timeout: timeout,
	}
}

// NewNodeCountParamsWithContext creates a new NodeCountParams object
// with the ability to set a context for a request.
func NewNodeCountParamsWithContext(ctx context.Context) *NodeCountParams {
	return &NodeCountParams{
		Context: ctx,
	}
}

// NewNodeCountParamsWithHTTPClient creates a new NodeCountParams object
// with the ability to set a custom HTTPClient for a request.
func NewNodeCountParamsWithHTTPClient(client *http.Client) *NodeCountParams {
	return &NodeCountParams{
		HTTPClient: client,
	}
}

/*
NodeCountParams contains all the parameters to send to the API endpoint

	for the node count operation.

	Typically these are written to a http.Request.
*/
type NodeCountParams struct {

	/* Filter.

	   Retrieve count of Kubernetes nodes that match a query in Falcon Query Language (FQL). Supported filters:  agent_type,aid,annotations_list,cid,cloud_account_id,cloud_name,cloud_region,cluster_id,cluster_name,container_count,container_runtime_version,first_seen,image_digest,ipv4,last_seen,linux_sensor_coverage,node_name,pod_count,resource_status
	*/
	Filter *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the node count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *NodeCountParams) WithDefaults() *NodeCountParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the node count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *NodeCountParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the node count params
func (o *NodeCountParams) WithTimeout(timeout time.Duration) *NodeCountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the node count params
func (o *NodeCountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the node count params
func (o *NodeCountParams) WithContext(ctx context.Context) *NodeCountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the node count params
func (o *NodeCountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the node count params
func (o *NodeCountParams) WithHTTPClient(client *http.Client) *NodeCountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the node count params
func (o *NodeCountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the node count params
func (o *NodeCountParams) WithFilter(filter *string) *NodeCountParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the node count params
func (o *NodeCountParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WriteToRequest writes these params to a swagger request
func (o *NodeCountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
