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
)

// NewGetCSPMGCPServiceAccountsExtParams creates a new GetCSPMGCPServiceAccountsExtParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetCSPMGCPServiceAccountsExtParams() *GetCSPMGCPServiceAccountsExtParams {
	return &GetCSPMGCPServiceAccountsExtParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetCSPMGCPServiceAccountsExtParamsWithTimeout creates a new GetCSPMGCPServiceAccountsExtParams object
// with the ability to set a timeout on a request.
func NewGetCSPMGCPServiceAccountsExtParamsWithTimeout(timeout time.Duration) *GetCSPMGCPServiceAccountsExtParams {
	return &GetCSPMGCPServiceAccountsExtParams{
		timeout: timeout,
	}
}

// NewGetCSPMGCPServiceAccountsExtParamsWithContext creates a new GetCSPMGCPServiceAccountsExtParams object
// with the ability to set a context for a request.
func NewGetCSPMGCPServiceAccountsExtParamsWithContext(ctx context.Context) *GetCSPMGCPServiceAccountsExtParams {
	return &GetCSPMGCPServiceAccountsExtParams{
		Context: ctx,
	}
}

// NewGetCSPMGCPServiceAccountsExtParamsWithHTTPClient creates a new GetCSPMGCPServiceAccountsExtParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetCSPMGCPServiceAccountsExtParamsWithHTTPClient(client *http.Client) *GetCSPMGCPServiceAccountsExtParams {
	return &GetCSPMGCPServiceAccountsExtParams{
		HTTPClient: client,
	}
}

/*
GetCSPMGCPServiceAccountsExtParams contains all the parameters to send to the API endpoint

	for the get c s p m g c p service accounts ext operation.

	Typically these are written to a http.Request.
*/
type GetCSPMGCPServiceAccountsExtParams struct {

	/* ID.

	   Service Account ID
	*/
	ID *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get c s p m g c p service accounts ext params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCSPMGCPServiceAccountsExtParams) WithDefaults() *GetCSPMGCPServiceAccountsExtParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get c s p m g c p service accounts ext params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCSPMGCPServiceAccountsExtParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get c s p m g c p service accounts ext params
func (o *GetCSPMGCPServiceAccountsExtParams) WithTimeout(timeout time.Duration) *GetCSPMGCPServiceAccountsExtParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get c s p m g c p service accounts ext params
func (o *GetCSPMGCPServiceAccountsExtParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get c s p m g c p service accounts ext params
func (o *GetCSPMGCPServiceAccountsExtParams) WithContext(ctx context.Context) *GetCSPMGCPServiceAccountsExtParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get c s p m g c p service accounts ext params
func (o *GetCSPMGCPServiceAccountsExtParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get c s p m g c p service accounts ext params
func (o *GetCSPMGCPServiceAccountsExtParams) WithHTTPClient(client *http.Client) *GetCSPMGCPServiceAccountsExtParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get c s p m g c p service accounts ext params
func (o *GetCSPMGCPServiceAccountsExtParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the get c s p m g c p service accounts ext params
func (o *GetCSPMGCPServiceAccountsExtParams) WithID(id *string) *GetCSPMGCPServiceAccountsExtParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get c s p m g c p service accounts ext params
func (o *GetCSPMGCPServiceAccountsExtParams) SetID(id *string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *GetCSPMGCPServiceAccountsExtParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.ID != nil {

		// query param id
		var qrID string

		if o.ID != nil {
			qrID = *o.ID
		}
		qID := qrID
		if qID != "" {

			if err := r.SetQueryParam("id", qID); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
