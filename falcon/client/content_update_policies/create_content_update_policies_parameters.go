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

// NewCreateContentUpdatePoliciesParams creates a new CreateContentUpdatePoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateContentUpdatePoliciesParams() *CreateContentUpdatePoliciesParams {
	return &CreateContentUpdatePoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateContentUpdatePoliciesParamsWithTimeout creates a new CreateContentUpdatePoliciesParams object
// with the ability to set a timeout on a request.
func NewCreateContentUpdatePoliciesParamsWithTimeout(timeout time.Duration) *CreateContentUpdatePoliciesParams {
	return &CreateContentUpdatePoliciesParams{
		timeout: timeout,
	}
}

// NewCreateContentUpdatePoliciesParamsWithContext creates a new CreateContentUpdatePoliciesParams object
// with the ability to set a context for a request.
func NewCreateContentUpdatePoliciesParamsWithContext(ctx context.Context) *CreateContentUpdatePoliciesParams {
	return &CreateContentUpdatePoliciesParams{
		Context: ctx,
	}
}

// NewCreateContentUpdatePoliciesParamsWithHTTPClient creates a new CreateContentUpdatePoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateContentUpdatePoliciesParamsWithHTTPClient(client *http.Client) *CreateContentUpdatePoliciesParams {
	return &CreateContentUpdatePoliciesParams{
		HTTPClient: client,
	}
}

/*
CreateContentUpdatePoliciesParams contains all the parameters to send to the API endpoint

	for the create content update policies operation.

	Typically these are written to a http.Request.
*/
type CreateContentUpdatePoliciesParams struct {

	// Body.
	Body *models.ContentUpdateCreatePoliciesReqV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create content update policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateContentUpdatePoliciesParams) WithDefaults() *CreateContentUpdatePoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create content update policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateContentUpdatePoliciesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create content update policies params
func (o *CreateContentUpdatePoliciesParams) WithTimeout(timeout time.Duration) *CreateContentUpdatePoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create content update policies params
func (o *CreateContentUpdatePoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create content update policies params
func (o *CreateContentUpdatePoliciesParams) WithContext(ctx context.Context) *CreateContentUpdatePoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create content update policies params
func (o *CreateContentUpdatePoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create content update policies params
func (o *CreateContentUpdatePoliciesParams) WithHTTPClient(client *http.Client) *CreateContentUpdatePoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create content update policies params
func (o *CreateContentUpdatePoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create content update policies params
func (o *CreateContentUpdatePoliciesParams) WithBody(body *models.ContentUpdateCreatePoliciesReqV1) *CreateContentUpdatePoliciesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create content update policies params
func (o *CreateContentUpdatePoliciesParams) SetBody(body *models.ContentUpdateCreatePoliciesReqV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateContentUpdatePoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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