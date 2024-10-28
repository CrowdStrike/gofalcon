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
	"github.com/go-openapi/swag"
)

// NewPodCombinedParams creates a new PodCombinedParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPodCombinedParams() *PodCombinedParams {
	return &PodCombinedParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPodCombinedParamsWithTimeout creates a new PodCombinedParams object
// with the ability to set a timeout on a request.
func NewPodCombinedParamsWithTimeout(timeout time.Duration) *PodCombinedParams {
	return &PodCombinedParams{
		timeout: timeout,
	}
}

// NewPodCombinedParamsWithContext creates a new PodCombinedParams object
// with the ability to set a context for a request.
func NewPodCombinedParamsWithContext(ctx context.Context) *PodCombinedParams {
	return &PodCombinedParams{
		Context: ctx,
	}
}

// NewPodCombinedParamsWithHTTPClient creates a new PodCombinedParams object
// with the ability to set a custom HTTPClient for a request.
func NewPodCombinedParamsWithHTTPClient(client *http.Client) *PodCombinedParams {
	return &PodCombinedParams{
		HTTPClient: client,
	}
}

/*
PodCombinedParams contains all the parameters to send to the API endpoint

	for the pod combined operation.

	Typically these are written to a http.Request.
*/
type PodCombinedParams struct {

	/* Filter.

	   Search Kubernetes pods using a query in Falcon Query Language (FQL). Supported filters:  agent_id,agent_type,allow_privilege_escalation,annotations_list,cid,cloud_account_id,cloud_name,cloud_region,cloud_service,cluster_id,cluster_name,container_count,first_seen,ipv4,ipv6,kac_agent_id,labels,last_seen,namespace,node_name,node_uid,owner_id,owner_type,pod_external_id,pod_id,pod_name,port,privileged,resource_status,root_write_access,run_as_root_group,run_as_root_user
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

	   Field to sort results by
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the pod combined params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PodCombinedParams) WithDefaults() *PodCombinedParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the pod combined params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PodCombinedParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the pod combined params
func (o *PodCombinedParams) WithTimeout(timeout time.Duration) *PodCombinedParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the pod combined params
func (o *PodCombinedParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the pod combined params
func (o *PodCombinedParams) WithContext(ctx context.Context) *PodCombinedParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the pod combined params
func (o *PodCombinedParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the pod combined params
func (o *PodCombinedParams) WithHTTPClient(client *http.Client) *PodCombinedParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the pod combined params
func (o *PodCombinedParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the pod combined params
func (o *PodCombinedParams) WithFilter(filter *string) *PodCombinedParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the pod combined params
func (o *PodCombinedParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the pod combined params
func (o *PodCombinedParams) WithLimit(limit *int64) *PodCombinedParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the pod combined params
func (o *PodCombinedParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the pod combined params
func (o *PodCombinedParams) WithOffset(offset *int64) *PodCombinedParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the pod combined params
func (o *PodCombinedParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the pod combined params
func (o *PodCombinedParams) WithSort(sort *string) *PodCombinedParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the pod combined params
func (o *PodCombinedParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *PodCombinedParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
