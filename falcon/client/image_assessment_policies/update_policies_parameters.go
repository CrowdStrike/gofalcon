// Code generated by go-swagger; DO NOT EDIT.

package image_assessment_policies

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

	"github.com/aslape/gofalcon/falcon/models"
)

// NewUpdatePoliciesParams creates a new UpdatePoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdatePoliciesParams() *UpdatePoliciesParams {
	return &UpdatePoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdatePoliciesParamsWithTimeout creates a new UpdatePoliciesParams object
// with the ability to set a timeout on a request.
func NewUpdatePoliciesParamsWithTimeout(timeout time.Duration) *UpdatePoliciesParams {
	return &UpdatePoliciesParams{
		timeout: timeout,
	}
}

// NewUpdatePoliciesParamsWithContext creates a new UpdatePoliciesParams object
// with the ability to set a context for a request.
func NewUpdatePoliciesParamsWithContext(ctx context.Context) *UpdatePoliciesParams {
	return &UpdatePoliciesParams{
		Context: ctx,
	}
}

// NewUpdatePoliciesParamsWithHTTPClient creates a new UpdatePoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdatePoliciesParamsWithHTTPClient(client *http.Client) *UpdatePoliciesParams {
	return &UpdatePoliciesParams{
		HTTPClient: client,
	}
}

/*
UpdatePoliciesParams contains all the parameters to send to the API endpoint

	for the update policies operation.

	Typically these are written to a http.Request.
*/
type UpdatePoliciesParams struct {

	// Body.
	Body *models.ModelsPatchPolicyRequest

	/* ID.

	   Image Assessment Policy entity UUID
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdatePoliciesParams) WithDefaults() *UpdatePoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdatePoliciesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update policies params
func (o *UpdatePoliciesParams) WithTimeout(timeout time.Duration) *UpdatePoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update policies params
func (o *UpdatePoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update policies params
func (o *UpdatePoliciesParams) WithContext(ctx context.Context) *UpdatePoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update policies params
func (o *UpdatePoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update policies params
func (o *UpdatePoliciesParams) WithHTTPClient(client *http.Client) *UpdatePoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update policies params
func (o *UpdatePoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the update policies params
func (o *UpdatePoliciesParams) WithBody(body *models.ModelsPatchPolicyRequest) *UpdatePoliciesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the update policies params
func (o *UpdatePoliciesParams) SetBody(body *models.ModelsPatchPolicyRequest) {
	o.Body = body
}

// WithID adds the id to the update policies params
func (o *UpdatePoliciesParams) WithID(id string) *UpdatePoliciesParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the update policies params
func (o *UpdatePoliciesParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *UpdatePoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	// query param id
	qrID := o.ID
	qID := qrID
	if qID != "" {

		if err := r.SetQueryParam("id", qID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
