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

// NewFindContainersCountAffectedByZeroDayVulnerabilitiesParams creates a new FindContainersCountAffectedByZeroDayVulnerabilitiesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewFindContainersCountAffectedByZeroDayVulnerabilitiesParams() *FindContainersCountAffectedByZeroDayVulnerabilitiesParams {
	return &FindContainersCountAffectedByZeroDayVulnerabilitiesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewFindContainersCountAffectedByZeroDayVulnerabilitiesParamsWithTimeout creates a new FindContainersCountAffectedByZeroDayVulnerabilitiesParams object
// with the ability to set a timeout on a request.
func NewFindContainersCountAffectedByZeroDayVulnerabilitiesParamsWithTimeout(timeout time.Duration) *FindContainersCountAffectedByZeroDayVulnerabilitiesParams {
	return &FindContainersCountAffectedByZeroDayVulnerabilitiesParams{
		timeout: timeout,
	}
}

// NewFindContainersCountAffectedByZeroDayVulnerabilitiesParamsWithContext creates a new FindContainersCountAffectedByZeroDayVulnerabilitiesParams object
// with the ability to set a context for a request.
func NewFindContainersCountAffectedByZeroDayVulnerabilitiesParamsWithContext(ctx context.Context) *FindContainersCountAffectedByZeroDayVulnerabilitiesParams {
	return &FindContainersCountAffectedByZeroDayVulnerabilitiesParams{
		Context: ctx,
	}
}

// NewFindContainersCountAffectedByZeroDayVulnerabilitiesParamsWithHTTPClient creates a new FindContainersCountAffectedByZeroDayVulnerabilitiesParams object
// with the ability to set a custom HTTPClient for a request.
func NewFindContainersCountAffectedByZeroDayVulnerabilitiesParamsWithHTTPClient(client *http.Client) *FindContainersCountAffectedByZeroDayVulnerabilitiesParams {
	return &FindContainersCountAffectedByZeroDayVulnerabilitiesParams{
		HTTPClient: client,
	}
}

/*
FindContainersCountAffectedByZeroDayVulnerabilitiesParams contains all the parameters to send to the API endpoint

	for the find containers count affected by zero day vulnerabilities operation.

	Typically these are written to a http.Request.
*/
type FindContainersCountAffectedByZeroDayVulnerabilitiesParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the find containers count affected by zero day vulnerabilities params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *FindContainersCountAffectedByZeroDayVulnerabilitiesParams) WithDefaults() *FindContainersCountAffectedByZeroDayVulnerabilitiesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the find containers count affected by zero day vulnerabilities params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *FindContainersCountAffectedByZeroDayVulnerabilitiesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the find containers count affected by zero day vulnerabilities params
func (o *FindContainersCountAffectedByZeroDayVulnerabilitiesParams) WithTimeout(timeout time.Duration) *FindContainersCountAffectedByZeroDayVulnerabilitiesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the find containers count affected by zero day vulnerabilities params
func (o *FindContainersCountAffectedByZeroDayVulnerabilitiesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the find containers count affected by zero day vulnerabilities params
func (o *FindContainersCountAffectedByZeroDayVulnerabilitiesParams) WithContext(ctx context.Context) *FindContainersCountAffectedByZeroDayVulnerabilitiesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the find containers count affected by zero day vulnerabilities params
func (o *FindContainersCountAffectedByZeroDayVulnerabilitiesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the find containers count affected by zero day vulnerabilities params
func (o *FindContainersCountAffectedByZeroDayVulnerabilitiesParams) WithHTTPClient(client *http.Client) *FindContainersCountAffectedByZeroDayVulnerabilitiesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the find containers count affected by zero day vulnerabilities params
func (o *FindContainersCountAffectedByZeroDayVulnerabilitiesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *FindContainersCountAffectedByZeroDayVulnerabilitiesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
