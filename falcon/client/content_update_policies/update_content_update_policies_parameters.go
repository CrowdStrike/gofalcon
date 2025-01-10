// Code generated by go-swagger; DO NOT EDIT.

package content_update_policies

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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// NewUpdateContentUpdatePoliciesParams creates a new UpdateContentUpdatePoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateContentUpdatePoliciesParams() *UpdateContentUpdatePoliciesParams {
	return &UpdateContentUpdatePoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateContentUpdatePoliciesParamsWithTimeout creates a new UpdateContentUpdatePoliciesParams object
// with the ability to set a timeout on a request.
func NewUpdateContentUpdatePoliciesParamsWithTimeout(timeout time.Duration) *UpdateContentUpdatePoliciesParams {
	return &UpdateContentUpdatePoliciesParams{
		timeout: timeout,
	}
}

// NewUpdateContentUpdatePoliciesParamsWithContext creates a new UpdateContentUpdatePoliciesParams object
// with the ability to set a context for a request.
func NewUpdateContentUpdatePoliciesParamsWithContext(ctx context.Context) *UpdateContentUpdatePoliciesParams {
	return &UpdateContentUpdatePoliciesParams{
		Context: ctx,
	}
}

// NewUpdateContentUpdatePoliciesParamsWithHTTPClient creates a new UpdateContentUpdatePoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateContentUpdatePoliciesParamsWithHTTPClient(client *http.Client) *UpdateContentUpdatePoliciesParams {
	return &UpdateContentUpdatePoliciesParams{
		HTTPClient: client,
	}
}

/*
UpdateContentUpdatePoliciesParams contains all the parameters to send to the API endpoint

	for the update content update policies operation.

	Typically these are written to a http.Request.
*/
type UpdateContentUpdatePoliciesParams struct {

	// Body.
	Body *models.ContentUpdateUpdatePoliciesReqV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update content update policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateContentUpdatePoliciesParams) WithDefaults() *UpdateContentUpdatePoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update content update policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateContentUpdatePoliciesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update content update policies params
func (o *UpdateContentUpdatePoliciesParams) WithTimeout(timeout time.Duration) *UpdateContentUpdatePoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update content update policies params
func (o *UpdateContentUpdatePoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update content update policies params
func (o *UpdateContentUpdatePoliciesParams) WithContext(ctx context.Context) *UpdateContentUpdatePoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update content update policies params
func (o *UpdateContentUpdatePoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update content update policies params
func (o *UpdateContentUpdatePoliciesParams) WithHTTPClient(client *http.Client) *UpdateContentUpdatePoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update content update policies params
func (o *UpdateContentUpdatePoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the update content update policies params
func (o *UpdateContentUpdatePoliciesParams) WithBody(body *models.ContentUpdateUpdatePoliciesReqV1) *UpdateContentUpdatePoliciesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the update content update policies params
func (o *UpdateContentUpdatePoliciesParams) SetBody(body *models.ContentUpdateUpdatePoliciesReqV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateContentUpdatePoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}