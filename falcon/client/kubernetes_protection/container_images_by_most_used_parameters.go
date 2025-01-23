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

// NewContainerImagesByMostUsedParams creates a new ContainerImagesByMostUsedParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewContainerImagesByMostUsedParams() *ContainerImagesByMostUsedParams {
	return &ContainerImagesByMostUsedParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewContainerImagesByMostUsedParamsWithTimeout creates a new ContainerImagesByMostUsedParams object
// with the ability to set a timeout on a request.
func NewContainerImagesByMostUsedParamsWithTimeout(timeout time.Duration) *ContainerImagesByMostUsedParams {
	return &ContainerImagesByMostUsedParams{
		timeout: timeout,
	}
}

// NewContainerImagesByMostUsedParamsWithContext creates a new ContainerImagesByMostUsedParams object
// with the ability to set a context for a request.
func NewContainerImagesByMostUsedParamsWithContext(ctx context.Context) *ContainerImagesByMostUsedParams {
	return &ContainerImagesByMostUsedParams{
		Context: ctx,
	}
}

// NewContainerImagesByMostUsedParamsWithHTTPClient creates a new ContainerImagesByMostUsedParams object
// with the ability to set a custom HTTPClient for a request.
func NewContainerImagesByMostUsedParamsWithHTTPClient(client *http.Client) *ContainerImagesByMostUsedParams {
	return &ContainerImagesByMostUsedParams{
		HTTPClient: client,
	}
}

/*
ContainerImagesByMostUsedParams contains all the parameters to send to the API endpoint

	for the container images by most used operation.

	Typically these are written to a http.Request.
*/
type ContainerImagesByMostUsedParams struct {

	/* Filter.

	     Retrieve count of Kubernetes containers that match a query in Falcon Query Language (FQL). Supported filter fields:
	- `agent_id`
	- `agent_type`
	- `allow_privilege_escalation`
	- `cid`
	- `cloud_account_id`
	- `cloud_instance_id`
	- `cloud_name`
	- `cloud_region`
	- `cloud_service`
	- `cluster_id`
	- `cluster_name`
	- `container_id`
	- `container_image_id`
	- `container_name`
	- `cve_id`
	- `detection_name`
	- `first_seen`
	- `image_detection_count`
	- `image_digest`
	- `image_has_been_assessed`
	- `image_id`
	- `image_registry`
	- `image_repository`
	- `image_tag`
	- `image_vulnerability_count`
	- `insecure_mount_source`
	- `insecure_mount_type`
	- `insecure_propagation_mode`
	- `interactive_mode`
	- `ipv4`
	- `ipv6`
	- `kac_agent_id`
	- `labels`
	- `last_seen`
	- `namespace`
	- `node_name`
	- `node_uid`
	- `package_name_version`
	- `pod_id`
	- `pod_name`
	- `port`
	- `privileged`
	- `root_write_access`
	- `run_as_root_group`
	- `run_as_root_user`
	- `running_status`
	*/
	Filter *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the container images by most used params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ContainerImagesByMostUsedParams) WithDefaults() *ContainerImagesByMostUsedParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the container images by most used params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ContainerImagesByMostUsedParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the container images by most used params
func (o *ContainerImagesByMostUsedParams) WithTimeout(timeout time.Duration) *ContainerImagesByMostUsedParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the container images by most used params
func (o *ContainerImagesByMostUsedParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the container images by most used params
func (o *ContainerImagesByMostUsedParams) WithContext(ctx context.Context) *ContainerImagesByMostUsedParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the container images by most used params
func (o *ContainerImagesByMostUsedParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the container images by most used params
func (o *ContainerImagesByMostUsedParams) WithHTTPClient(client *http.Client) *ContainerImagesByMostUsedParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the container images by most used params
func (o *ContainerImagesByMostUsedParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the container images by most used params
func (o *ContainerImagesByMostUsedParams) WithFilter(filter *string) *ContainerImagesByMostUsedParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the container images by most used params
func (o *ContainerImagesByMostUsedParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WriteToRequest writes these params to a swagger request
func (o *ContainerImagesByMostUsedParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
