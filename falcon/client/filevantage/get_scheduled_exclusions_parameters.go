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
	"github.com/go-openapi/swag"
)

// NewGetScheduledExclusionsParams creates a new GetScheduledExclusionsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetScheduledExclusionsParams() *GetScheduledExclusionsParams {
	return &GetScheduledExclusionsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetScheduledExclusionsParamsWithTimeout creates a new GetScheduledExclusionsParams object
// with the ability to set a timeout on a request.
func NewGetScheduledExclusionsParamsWithTimeout(timeout time.Duration) *GetScheduledExclusionsParams {
	return &GetScheduledExclusionsParams{
		timeout: timeout,
	}
}

// NewGetScheduledExclusionsParamsWithContext creates a new GetScheduledExclusionsParams object
// with the ability to set a context for a request.
func NewGetScheduledExclusionsParamsWithContext(ctx context.Context) *GetScheduledExclusionsParams {
	return &GetScheduledExclusionsParams{
		Context: ctx,
	}
}

// NewGetScheduledExclusionsParamsWithHTTPClient creates a new GetScheduledExclusionsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetScheduledExclusionsParamsWithHTTPClient(client *http.Client) *GetScheduledExclusionsParams {
	return &GetScheduledExclusionsParams{
		HTTPClient: client,
	}
}

/*
GetScheduledExclusionsParams contains all the parameters to send to the API endpoint

	for the get scheduled exclusions operation.

	Typically these are written to a http.Request.
*/
type GetScheduledExclusionsParams struct {

	/* Ids.

	   One or more (up to 500) scheduled exclusion ids in the form of `ids=ID1&ids=ID2`.
	*/
	Ids []string

	/* PolicyID.

	   The id of the policy to retrieve the scheduled exclusion configurations.
	*/
	PolicyID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get scheduled exclusions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetScheduledExclusionsParams) WithDefaults() *GetScheduledExclusionsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get scheduled exclusions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetScheduledExclusionsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get scheduled exclusions params
func (o *GetScheduledExclusionsParams) WithTimeout(timeout time.Duration) *GetScheduledExclusionsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get scheduled exclusions params
func (o *GetScheduledExclusionsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get scheduled exclusions params
func (o *GetScheduledExclusionsParams) WithContext(ctx context.Context) *GetScheduledExclusionsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get scheduled exclusions params
func (o *GetScheduledExclusionsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get scheduled exclusions params
func (o *GetScheduledExclusionsParams) WithHTTPClient(client *http.Client) *GetScheduledExclusionsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get scheduled exclusions params
func (o *GetScheduledExclusionsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the get scheduled exclusions params
func (o *GetScheduledExclusionsParams) WithIds(ids []string) *GetScheduledExclusionsParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get scheduled exclusions params
func (o *GetScheduledExclusionsParams) SetIds(ids []string) {
	o.Ids = ids
}

// WithPolicyID adds the policyID to the get scheduled exclusions params
func (o *GetScheduledExclusionsParams) WithPolicyID(policyID string) *GetScheduledExclusionsParams {
	o.SetPolicyID(policyID)
	return o
}

// SetPolicyID adds the policyId to the get scheduled exclusions params
func (o *GetScheduledExclusionsParams) SetPolicyID(policyID string) {
	o.PolicyID = policyID
}

// WriteToRequest writes these params to a swagger request
func (o *GetScheduledExclusionsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Ids != nil {

		// binding items for ids
		joinedIds := o.bindParamIds(reg)

		// query array param ids
		if err := r.SetQueryParam("ids", joinedIds...); err != nil {
			return err
		}
	}

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

// bindParamGetScheduledExclusions binds the parameter ids
func (o *GetScheduledExclusionsParams) bindParamIds(formats strfmt.Registry) []string {
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
