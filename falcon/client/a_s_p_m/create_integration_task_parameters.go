// Code generated by go-swagger; DO NOT EDIT.

package a_s_p_m

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

// NewCreateIntegrationTaskParams creates a new CreateIntegrationTaskParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateIntegrationTaskParams() *CreateIntegrationTaskParams {
	return &CreateIntegrationTaskParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateIntegrationTaskParamsWithTimeout creates a new CreateIntegrationTaskParams object
// with the ability to set a timeout on a request.
func NewCreateIntegrationTaskParamsWithTimeout(timeout time.Duration) *CreateIntegrationTaskParams {
	return &CreateIntegrationTaskParams{
		timeout: timeout,
	}
}

// NewCreateIntegrationTaskParamsWithContext creates a new CreateIntegrationTaskParams object
// with the ability to set a context for a request.
func NewCreateIntegrationTaskParamsWithContext(ctx context.Context) *CreateIntegrationTaskParams {
	return &CreateIntegrationTaskParams{
		Context: ctx,
	}
}

// NewCreateIntegrationTaskParamsWithHTTPClient creates a new CreateIntegrationTaskParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateIntegrationTaskParamsWithHTTPClient(client *http.Client) *CreateIntegrationTaskParams {
	return &CreateIntegrationTaskParams{
		HTTPClient: client,
	}
}

/*
CreateIntegrationTaskParams contains all the parameters to send to the API endpoint

	for the create integration task operation.

	Typically these are written to a http.Request.
*/
type CreateIntegrationTaskParams struct {

	// Body.
	Body *models.TypesCreateIntegrationTaskRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create integration task params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateIntegrationTaskParams) WithDefaults() *CreateIntegrationTaskParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create integration task params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateIntegrationTaskParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create integration task params
func (o *CreateIntegrationTaskParams) WithTimeout(timeout time.Duration) *CreateIntegrationTaskParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create integration task params
func (o *CreateIntegrationTaskParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create integration task params
func (o *CreateIntegrationTaskParams) WithContext(ctx context.Context) *CreateIntegrationTaskParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create integration task params
func (o *CreateIntegrationTaskParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create integration task params
func (o *CreateIntegrationTaskParams) WithHTTPClient(client *http.Client) *CreateIntegrationTaskParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create integration task params
func (o *CreateIntegrationTaskParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create integration task params
func (o *CreateIntegrationTaskParams) WithBody(body *models.TypesCreateIntegrationTaskRequest) *CreateIntegrationTaskParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create integration task params
func (o *CreateIntegrationTaskParams) SetBody(body *models.TypesCreateIntegrationTaskRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateIntegrationTaskParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
