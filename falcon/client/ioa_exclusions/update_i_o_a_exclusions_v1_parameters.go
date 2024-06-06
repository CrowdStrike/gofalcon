// Code generated by go-swagger; DO NOT EDIT.

package ioa_exclusions

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

// NewUpdateIOAExclusionsV1Params creates a new UpdateIOAExclusionsV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateIOAExclusionsV1Params() *UpdateIOAExclusionsV1Params {
	return &UpdateIOAExclusionsV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateIOAExclusionsV1ParamsWithTimeout creates a new UpdateIOAExclusionsV1Params object
// with the ability to set a timeout on a request.
func NewUpdateIOAExclusionsV1ParamsWithTimeout(timeout time.Duration) *UpdateIOAExclusionsV1Params {
	return &UpdateIOAExclusionsV1Params{
		timeout: timeout,
	}
}

// NewUpdateIOAExclusionsV1ParamsWithContext creates a new UpdateIOAExclusionsV1Params object
// with the ability to set a context for a request.
func NewUpdateIOAExclusionsV1ParamsWithContext(ctx context.Context) *UpdateIOAExclusionsV1Params {
	return &UpdateIOAExclusionsV1Params{
		Context: ctx,
	}
}

// NewUpdateIOAExclusionsV1ParamsWithHTTPClient creates a new UpdateIOAExclusionsV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateIOAExclusionsV1ParamsWithHTTPClient(client *http.Client) *UpdateIOAExclusionsV1Params {
	return &UpdateIOAExclusionsV1Params{
		HTTPClient: client,
	}
}

/*
UpdateIOAExclusionsV1Params contains all the parameters to send to the API endpoint

	for the update i o a exclusions v1 operation.

	Typically these are written to a http.Request.
*/
type UpdateIOAExclusionsV1Params struct {

	// Body.
	Body *models.IoaExclusionsIoaExclusionUpdateReqV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update i o a exclusions v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateIOAExclusionsV1Params) WithDefaults() *UpdateIOAExclusionsV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update i o a exclusions v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateIOAExclusionsV1Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update i o a exclusions v1 params
func (o *UpdateIOAExclusionsV1Params) WithTimeout(timeout time.Duration) *UpdateIOAExclusionsV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update i o a exclusions v1 params
func (o *UpdateIOAExclusionsV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update i o a exclusions v1 params
func (o *UpdateIOAExclusionsV1Params) WithContext(ctx context.Context) *UpdateIOAExclusionsV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update i o a exclusions v1 params
func (o *UpdateIOAExclusionsV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update i o a exclusions v1 params
func (o *UpdateIOAExclusionsV1Params) WithHTTPClient(client *http.Client) *UpdateIOAExclusionsV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update i o a exclusions v1 params
func (o *UpdateIOAExclusionsV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the update i o a exclusions v1 params
func (o *UpdateIOAExclusionsV1Params) WithBody(body *models.IoaExclusionsIoaExclusionUpdateReqV1) *UpdateIOAExclusionsV1Params {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the update i o a exclusions v1 params
func (o *UpdateIOAExclusionsV1Params) SetBody(body *models.IoaExclusionsIoaExclusionUpdateReqV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateIOAExclusionsV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
