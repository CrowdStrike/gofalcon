// Code generated by go-swagger; DO NOT EDIT.

package quarantine

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

// NewUpdateQuarantinedDetectsByIdsParams creates a new UpdateQuarantinedDetectsByIdsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateQuarantinedDetectsByIdsParams() *UpdateQuarantinedDetectsByIdsParams {
	return &UpdateQuarantinedDetectsByIdsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateQuarantinedDetectsByIdsParamsWithTimeout creates a new UpdateQuarantinedDetectsByIdsParams object
// with the ability to set a timeout on a request.
func NewUpdateQuarantinedDetectsByIdsParamsWithTimeout(timeout time.Duration) *UpdateQuarantinedDetectsByIdsParams {
	return &UpdateQuarantinedDetectsByIdsParams{
		timeout: timeout,
	}
}

// NewUpdateQuarantinedDetectsByIdsParamsWithContext creates a new UpdateQuarantinedDetectsByIdsParams object
// with the ability to set a context for a request.
func NewUpdateQuarantinedDetectsByIdsParamsWithContext(ctx context.Context) *UpdateQuarantinedDetectsByIdsParams {
	return &UpdateQuarantinedDetectsByIdsParams{
		Context: ctx,
	}
}

// NewUpdateQuarantinedDetectsByIdsParamsWithHTTPClient creates a new UpdateQuarantinedDetectsByIdsParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateQuarantinedDetectsByIdsParamsWithHTTPClient(client *http.Client) *UpdateQuarantinedDetectsByIdsParams {
	return &UpdateQuarantinedDetectsByIdsParams{
		HTTPClient: client,
	}
}

/*
UpdateQuarantinedDetectsByIdsParams contains all the parameters to send to the API endpoint

	for the update quarantined detects by ids operation.

	Typically these are written to a http.Request.
*/
type UpdateQuarantinedDetectsByIdsParams struct {

	// Body.
	Body *models.DomainEntitiesPatchRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update quarantined detects by ids params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateQuarantinedDetectsByIdsParams) WithDefaults() *UpdateQuarantinedDetectsByIdsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update quarantined detects by ids params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateQuarantinedDetectsByIdsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update quarantined detects by ids params
func (o *UpdateQuarantinedDetectsByIdsParams) WithTimeout(timeout time.Duration) *UpdateQuarantinedDetectsByIdsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update quarantined detects by ids params
func (o *UpdateQuarantinedDetectsByIdsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update quarantined detects by ids params
func (o *UpdateQuarantinedDetectsByIdsParams) WithContext(ctx context.Context) *UpdateQuarantinedDetectsByIdsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update quarantined detects by ids params
func (o *UpdateQuarantinedDetectsByIdsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update quarantined detects by ids params
func (o *UpdateQuarantinedDetectsByIdsParams) WithHTTPClient(client *http.Client) *UpdateQuarantinedDetectsByIdsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update quarantined detects by ids params
func (o *UpdateQuarantinedDetectsByIdsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the update quarantined detects by ids params
func (o *UpdateQuarantinedDetectsByIdsParams) WithBody(body *models.DomainEntitiesPatchRequest) *UpdateQuarantinedDetectsByIdsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the update quarantined detects by ids params
func (o *UpdateQuarantinedDetectsByIdsParams) SetBody(body *models.DomainEntitiesPatchRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateQuarantinedDetectsByIdsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
