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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// NewValidateCSPMGCPServiceAccountExtParams creates a new ValidateCSPMGCPServiceAccountExtParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewValidateCSPMGCPServiceAccountExtParams() *ValidateCSPMGCPServiceAccountExtParams {
	return &ValidateCSPMGCPServiceAccountExtParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewValidateCSPMGCPServiceAccountExtParamsWithTimeout creates a new ValidateCSPMGCPServiceAccountExtParams object
// with the ability to set a timeout on a request.
func NewValidateCSPMGCPServiceAccountExtParamsWithTimeout(timeout time.Duration) *ValidateCSPMGCPServiceAccountExtParams {
	return &ValidateCSPMGCPServiceAccountExtParams{
		timeout: timeout,
	}
}

// NewValidateCSPMGCPServiceAccountExtParamsWithContext creates a new ValidateCSPMGCPServiceAccountExtParams object
// with the ability to set a context for a request.
func NewValidateCSPMGCPServiceAccountExtParamsWithContext(ctx context.Context) *ValidateCSPMGCPServiceAccountExtParams {
	return &ValidateCSPMGCPServiceAccountExtParams{
		Context: ctx,
	}
}

// NewValidateCSPMGCPServiceAccountExtParamsWithHTTPClient creates a new ValidateCSPMGCPServiceAccountExtParams object
// with the ability to set a custom HTTPClient for a request.
func NewValidateCSPMGCPServiceAccountExtParamsWithHTTPClient(client *http.Client) *ValidateCSPMGCPServiceAccountExtParams {
	return &ValidateCSPMGCPServiceAccountExtParams{
		HTTPClient: client,
	}
}

/*
ValidateCSPMGCPServiceAccountExtParams contains all the parameters to send to the API endpoint

	for the validate c s p m g c p service account ext operation.

	Typically these are written to a http.Request.
*/
type ValidateCSPMGCPServiceAccountExtParams struct {

	// Body.
	Body *models.RegistrationGCPServiceAccountValidationRequestV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the validate c s p m g c p service account ext params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ValidateCSPMGCPServiceAccountExtParams) WithDefaults() *ValidateCSPMGCPServiceAccountExtParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the validate c s p m g c p service account ext params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ValidateCSPMGCPServiceAccountExtParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the validate c s p m g c p service account ext params
func (o *ValidateCSPMGCPServiceAccountExtParams) WithTimeout(timeout time.Duration) *ValidateCSPMGCPServiceAccountExtParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the validate c s p m g c p service account ext params
func (o *ValidateCSPMGCPServiceAccountExtParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the validate c s p m g c p service account ext params
func (o *ValidateCSPMGCPServiceAccountExtParams) WithContext(ctx context.Context) *ValidateCSPMGCPServiceAccountExtParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the validate c s p m g c p service account ext params
func (o *ValidateCSPMGCPServiceAccountExtParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the validate c s p m g c p service account ext params
func (o *ValidateCSPMGCPServiceAccountExtParams) WithHTTPClient(client *http.Client) *ValidateCSPMGCPServiceAccountExtParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the validate c s p m g c p service account ext params
func (o *ValidateCSPMGCPServiceAccountExtParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the validate c s p m g c p service account ext params
func (o *ValidateCSPMGCPServiceAccountExtParams) WithBody(body *models.RegistrationGCPServiceAccountValidationRequestV1) *ValidateCSPMGCPServiceAccountExtParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the validate c s p m g c p service account ext params
func (o *ValidateCSPMGCPServiceAccountExtParams) SetBody(body *models.RegistrationGCPServiceAccountValidationRequestV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ValidateCSPMGCPServiceAccountExtParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
