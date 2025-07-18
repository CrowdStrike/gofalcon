// Code generated by go-swagger; DO NOT EDIT.

package identity_protection

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

// NewAPIPreemptProxyDeletePolicyRulesParams creates a new APIPreemptProxyDeletePolicyRulesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAPIPreemptProxyDeletePolicyRulesParams() *APIPreemptProxyDeletePolicyRulesParams {
	return &APIPreemptProxyDeletePolicyRulesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAPIPreemptProxyDeletePolicyRulesParamsWithTimeout creates a new APIPreemptProxyDeletePolicyRulesParams object
// with the ability to set a timeout on a request.
func NewAPIPreemptProxyDeletePolicyRulesParamsWithTimeout(timeout time.Duration) *APIPreemptProxyDeletePolicyRulesParams {
	return &APIPreemptProxyDeletePolicyRulesParams{
		timeout: timeout,
	}
}

// NewAPIPreemptProxyDeletePolicyRulesParamsWithContext creates a new APIPreemptProxyDeletePolicyRulesParams object
// with the ability to set a context for a request.
func NewAPIPreemptProxyDeletePolicyRulesParamsWithContext(ctx context.Context) *APIPreemptProxyDeletePolicyRulesParams {
	return &APIPreemptProxyDeletePolicyRulesParams{
		Context: ctx,
	}
}

// NewAPIPreemptProxyDeletePolicyRulesParamsWithHTTPClient creates a new APIPreemptProxyDeletePolicyRulesParams object
// with the ability to set a custom HTTPClient for a request.
func NewAPIPreemptProxyDeletePolicyRulesParamsWithHTTPClient(client *http.Client) *APIPreemptProxyDeletePolicyRulesParams {
	return &APIPreemptProxyDeletePolicyRulesParams{
		HTTPClient: client,
	}
}

/*
APIPreemptProxyDeletePolicyRulesParams contains all the parameters to send to the API endpoint

	for the api preempt proxy delete policy rules operation.

	Typically these are written to a http.Request.
*/
type APIPreemptProxyDeletePolicyRulesParams struct {

	/* Authorization.

	   Authorization Header
	*/
	Authorization string

	/* Ids.

	   Rule IDs
	*/
	Ids []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the api preempt proxy delete policy rules params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *APIPreemptProxyDeletePolicyRulesParams) WithDefaults() *APIPreemptProxyDeletePolicyRulesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the api preempt proxy delete policy rules params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *APIPreemptProxyDeletePolicyRulesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the api preempt proxy delete policy rules params
func (o *APIPreemptProxyDeletePolicyRulesParams) WithTimeout(timeout time.Duration) *APIPreemptProxyDeletePolicyRulesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the api preempt proxy delete policy rules params
func (o *APIPreemptProxyDeletePolicyRulesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the api preempt proxy delete policy rules params
func (o *APIPreemptProxyDeletePolicyRulesParams) WithContext(ctx context.Context) *APIPreemptProxyDeletePolicyRulesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the api preempt proxy delete policy rules params
func (o *APIPreemptProxyDeletePolicyRulesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the api preempt proxy delete policy rules params
func (o *APIPreemptProxyDeletePolicyRulesParams) WithHTTPClient(client *http.Client) *APIPreemptProxyDeletePolicyRulesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the api preempt proxy delete policy rules params
func (o *APIPreemptProxyDeletePolicyRulesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the api preempt proxy delete policy rules params
func (o *APIPreemptProxyDeletePolicyRulesParams) WithAuthorization(authorization string) *APIPreemptProxyDeletePolicyRulesParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the api preempt proxy delete policy rules params
func (o *APIPreemptProxyDeletePolicyRulesParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithIds adds the ids to the api preempt proxy delete policy rules params
func (o *APIPreemptProxyDeletePolicyRulesParams) WithIds(ids []string) *APIPreemptProxyDeletePolicyRulesParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the api preempt proxy delete policy rules params
func (o *APIPreemptProxyDeletePolicyRulesParams) SetIds(ids []string) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *APIPreemptProxyDeletePolicyRulesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
	}

	if o.Ids != nil {

		// binding items for ids
		joinedIds := o.bindParamIds(reg)

		// query array param ids
		if err := r.SetQueryParam("ids", joinedIds...); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamAPIPreemptProxyDeletePolicyRules binds the parameter ids
func (o *APIPreemptProxyDeletePolicyRulesParams) bindParamIds(formats strfmt.Registry) []string {
	idsIR := o.Ids

	var idsIC []string
	for _, idsIIR := range idsIR { // explode []string

		idsIIV := idsIIR // string as string
		idsIC = append(idsIC, idsIIV)
	}

	// items.CollectionFormat: "multi"
	idsIS := swag.JoinByFormat(idsIC, "multi")

	return idsIS
}
