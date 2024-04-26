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

// NewGetCSPMGCPValidateAccountsExtParams creates a new GetCSPMGCPValidateAccountsExtParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetCSPMGCPValidateAccountsExtParams() *GetCSPMGCPValidateAccountsExtParams {
	return &GetCSPMGCPValidateAccountsExtParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetCSPMGCPValidateAccountsExtParamsWithTimeout creates a new GetCSPMGCPValidateAccountsExtParams object
// with the ability to set a timeout on a request.
func NewGetCSPMGCPValidateAccountsExtParamsWithTimeout(timeout time.Duration) *GetCSPMGCPValidateAccountsExtParams {
	return &GetCSPMGCPValidateAccountsExtParams{
		timeout: timeout,
	}
}

// NewGetCSPMGCPValidateAccountsExtParamsWithContext creates a new GetCSPMGCPValidateAccountsExtParams object
// with the ability to set a context for a request.
func NewGetCSPMGCPValidateAccountsExtParamsWithContext(ctx context.Context) *GetCSPMGCPValidateAccountsExtParams {
	return &GetCSPMGCPValidateAccountsExtParams{
		Context: ctx,
	}
}

// NewGetCSPMGCPValidateAccountsExtParamsWithHTTPClient creates a new GetCSPMGCPValidateAccountsExtParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetCSPMGCPValidateAccountsExtParamsWithHTTPClient(client *http.Client) *GetCSPMGCPValidateAccountsExtParams {
	return &GetCSPMGCPValidateAccountsExtParams{
		HTTPClient: client,
	}
}

/*
GetCSPMGCPValidateAccountsExtParams contains all the parameters to send to the API endpoint

	for the get c s p m g c p validate accounts ext operation.

	Typically these are written to a http.Request.
*/
type GetCSPMGCPValidateAccountsExtParams struct {

	// Body.
	Body *models.RegistrationGCPAccountValidationRequestV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get c s p m g c p validate accounts ext params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCSPMGCPValidateAccountsExtParams) WithDefaults() *GetCSPMGCPValidateAccountsExtParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get c s p m g c p validate accounts ext params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCSPMGCPValidateAccountsExtParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get c s p m g c p validate accounts ext params
func (o *GetCSPMGCPValidateAccountsExtParams) WithTimeout(timeout time.Duration) *GetCSPMGCPValidateAccountsExtParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get c s p m g c p validate accounts ext params
func (o *GetCSPMGCPValidateAccountsExtParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get c s p m g c p validate accounts ext params
func (o *GetCSPMGCPValidateAccountsExtParams) WithContext(ctx context.Context) *GetCSPMGCPValidateAccountsExtParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get c s p m g c p validate accounts ext params
func (o *GetCSPMGCPValidateAccountsExtParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get c s p m g c p validate accounts ext params
func (o *GetCSPMGCPValidateAccountsExtParams) WithHTTPClient(client *http.Client) *GetCSPMGCPValidateAccountsExtParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get c s p m g c p validate accounts ext params
func (o *GetCSPMGCPValidateAccountsExtParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the get c s p m g c p validate accounts ext params
func (o *GetCSPMGCPValidateAccountsExtParams) WithBody(body *models.RegistrationGCPAccountValidationRequestV1) *GetCSPMGCPValidateAccountsExtParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the get c s p m g c p validate accounts ext params
func (o *GetCSPMGCPValidateAccountsExtParams) SetBody(body *models.RegistrationGCPAccountValidationRequestV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *GetCSPMGCPValidateAccountsExtParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
