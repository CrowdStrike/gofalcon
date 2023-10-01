// Code generated by go-swagger; DO NOT EDIT.

package filevantage

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

// NewQueryScheduledExclusionsParams creates a new QueryScheduledExclusionsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryScheduledExclusionsParams() *QueryScheduledExclusionsParams {
	return &QueryScheduledExclusionsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryScheduledExclusionsParamsWithTimeout creates a new QueryScheduledExclusionsParams object
// with the ability to set a timeout on a request.
func NewQueryScheduledExclusionsParamsWithTimeout(timeout time.Duration) *QueryScheduledExclusionsParams {
	return &QueryScheduledExclusionsParams{
		timeout: timeout,
	}
}

// NewQueryScheduledExclusionsParamsWithContext creates a new QueryScheduledExclusionsParams object
// with the ability to set a context for a request.
func NewQueryScheduledExclusionsParamsWithContext(ctx context.Context) *QueryScheduledExclusionsParams {
	return &QueryScheduledExclusionsParams{
		Context: ctx,
	}
}

// NewQueryScheduledExclusionsParamsWithHTTPClient creates a new QueryScheduledExclusionsParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryScheduledExclusionsParamsWithHTTPClient(client *http.Client) *QueryScheduledExclusionsParams {
	return &QueryScheduledExclusionsParams{
		HTTPClient: client,
	}
}

/*
QueryScheduledExclusionsParams contains all the parameters to send to the API endpoint

	for the query scheduled exclusions operation.

	Typically these are written to a http.Request.
*/
type QueryScheduledExclusionsParams struct {

	/* PolicyID.

	   The id of the policy from which to retrieve the scheduled exclusion ids.
	*/
	PolicyID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query scheduled exclusions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryScheduledExclusionsParams) WithDefaults() *QueryScheduledExclusionsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query scheduled exclusions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryScheduledExclusionsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query scheduled exclusions params
func (o *QueryScheduledExclusionsParams) WithTimeout(timeout time.Duration) *QueryScheduledExclusionsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query scheduled exclusions params
func (o *QueryScheduledExclusionsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query scheduled exclusions params
func (o *QueryScheduledExclusionsParams) WithContext(ctx context.Context) *QueryScheduledExclusionsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query scheduled exclusions params
func (o *QueryScheduledExclusionsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query scheduled exclusions params
func (o *QueryScheduledExclusionsParams) WithHTTPClient(client *http.Client) *QueryScheduledExclusionsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query scheduled exclusions params
func (o *QueryScheduledExclusionsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithPolicyID adds the policyID to the query scheduled exclusions params
func (o *QueryScheduledExclusionsParams) WithPolicyID(policyID string) *QueryScheduledExclusionsParams {
	o.SetPolicyID(policyID)
	return o
}

// SetPolicyID adds the policyId to the query scheduled exclusions params
func (o *QueryScheduledExclusionsParams) SetPolicyID(policyID string) {
	o.PolicyID = policyID
}

// WriteToRequest writes these params to a swagger request
func (o *QueryScheduledExclusionsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param policy_id
	qrPolicyID := o.PolicyID
	qPolicyID := qrPolicyID
	if qPolicyID != "" {

		if err := r.SetQueryParam("policy_id", qPolicyID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}