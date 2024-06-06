// Code generated by go-swagger; DO NOT EDIT.

package cspm_registration

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

// NewPatchCSPMAwsAccountParams creates a new PatchCSPMAwsAccountParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPatchCSPMAwsAccountParams() *PatchCSPMAwsAccountParams {
	return &PatchCSPMAwsAccountParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPatchCSPMAwsAccountParamsWithTimeout creates a new PatchCSPMAwsAccountParams object
// with the ability to set a timeout on a request.
func NewPatchCSPMAwsAccountParamsWithTimeout(timeout time.Duration) *PatchCSPMAwsAccountParams {
	return &PatchCSPMAwsAccountParams{
		timeout: timeout,
	}
}

// NewPatchCSPMAwsAccountParamsWithContext creates a new PatchCSPMAwsAccountParams object
// with the ability to set a context for a request.
func NewPatchCSPMAwsAccountParamsWithContext(ctx context.Context) *PatchCSPMAwsAccountParams {
	return &PatchCSPMAwsAccountParams{
		Context: ctx,
	}
}

// NewPatchCSPMAwsAccountParamsWithHTTPClient creates a new PatchCSPMAwsAccountParams object
// with the ability to set a custom HTTPClient for a request.
func NewPatchCSPMAwsAccountParamsWithHTTPClient(client *http.Client) *PatchCSPMAwsAccountParams {
	return &PatchCSPMAwsAccountParams{
		HTTPClient: client,
	}
}

/*
PatchCSPMAwsAccountParams contains all the parameters to send to the API endpoint

	for the patch c s p m aws account operation.

	Typically these are written to a http.Request.
*/
type PatchCSPMAwsAccountParams struct {

	// Body.
	Body *models.RegistrationAWSAccountPatchRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the patch c s p m aws account params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchCSPMAwsAccountParams) WithDefaults() *PatchCSPMAwsAccountParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the patch c s p m aws account params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchCSPMAwsAccountParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the patch c s p m aws account params
func (o *PatchCSPMAwsAccountParams) WithTimeout(timeout time.Duration) *PatchCSPMAwsAccountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch c s p m aws account params
func (o *PatchCSPMAwsAccountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch c s p m aws account params
func (o *PatchCSPMAwsAccountParams) WithContext(ctx context.Context) *PatchCSPMAwsAccountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch c s p m aws account params
func (o *PatchCSPMAwsAccountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch c s p m aws account params
func (o *PatchCSPMAwsAccountParams) WithHTTPClient(client *http.Client) *PatchCSPMAwsAccountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch c s p m aws account params
func (o *PatchCSPMAwsAccountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the patch c s p m aws account params
func (o *PatchCSPMAwsAccountParams) WithBody(body *models.RegistrationAWSAccountPatchRequest) *PatchCSPMAwsAccountParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch c s p m aws account params
func (o *PatchCSPMAwsAccountParams) SetBody(body *models.RegistrationAWSAccountPatchRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PatchCSPMAwsAccountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
