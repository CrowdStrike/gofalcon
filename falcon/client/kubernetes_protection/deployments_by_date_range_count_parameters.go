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

// NewDeploymentsByDateRangeCountParams creates a new DeploymentsByDateRangeCountParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeploymentsByDateRangeCountParams() *DeploymentsByDateRangeCountParams {
	return &DeploymentsByDateRangeCountParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeploymentsByDateRangeCountParamsWithTimeout creates a new DeploymentsByDateRangeCountParams object
// with the ability to set a timeout on a request.
func NewDeploymentsByDateRangeCountParamsWithTimeout(timeout time.Duration) *DeploymentsByDateRangeCountParams {
	return &DeploymentsByDateRangeCountParams{
		timeout: timeout,
	}
}

// NewDeploymentsByDateRangeCountParamsWithContext creates a new DeploymentsByDateRangeCountParams object
// with the ability to set a context for a request.
func NewDeploymentsByDateRangeCountParamsWithContext(ctx context.Context) *DeploymentsByDateRangeCountParams {
	return &DeploymentsByDateRangeCountParams{
		Context: ctx,
	}
}

// NewDeploymentsByDateRangeCountParamsWithHTTPClient creates a new DeploymentsByDateRangeCountParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeploymentsByDateRangeCountParamsWithHTTPClient(client *http.Client) *DeploymentsByDateRangeCountParams {
	return &DeploymentsByDateRangeCountParams{
		HTTPClient: client,
	}
}

/*
DeploymentsByDateRangeCountParams contains all the parameters to send to the API endpoint

	for the deployments by date range count operation.

	Typically these are written to a http.Request.
*/
type DeploymentsByDateRangeCountParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the deployments by date range count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeploymentsByDateRangeCountParams) WithDefaults() *DeploymentsByDateRangeCountParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the deployments by date range count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeploymentsByDateRangeCountParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the deployments by date range count params
func (o *DeploymentsByDateRangeCountParams) WithTimeout(timeout time.Duration) *DeploymentsByDateRangeCountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the deployments by date range count params
func (o *DeploymentsByDateRangeCountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the deployments by date range count params
func (o *DeploymentsByDateRangeCountParams) WithContext(ctx context.Context) *DeploymentsByDateRangeCountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the deployments by date range count params
func (o *DeploymentsByDateRangeCountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the deployments by date range count params
func (o *DeploymentsByDateRangeCountParams) WithHTTPClient(client *http.Client) *DeploymentsByDateRangeCountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the deployments by date range count params
func (o *DeploymentsByDateRangeCountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *DeploymentsByDateRangeCountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
