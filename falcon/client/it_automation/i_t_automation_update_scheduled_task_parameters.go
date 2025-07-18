// Code generated by go-swagger; DO NOT EDIT.

package it_automation

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

// NewITAutomationUpdateScheduledTaskParams creates a new ITAutomationUpdateScheduledTaskParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewITAutomationUpdateScheduledTaskParams() *ITAutomationUpdateScheduledTaskParams {
	return &ITAutomationUpdateScheduledTaskParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewITAutomationUpdateScheduledTaskParamsWithTimeout creates a new ITAutomationUpdateScheduledTaskParams object
// with the ability to set a timeout on a request.
func NewITAutomationUpdateScheduledTaskParamsWithTimeout(timeout time.Duration) *ITAutomationUpdateScheduledTaskParams {
	return &ITAutomationUpdateScheduledTaskParams{
		timeout: timeout,
	}
}

// NewITAutomationUpdateScheduledTaskParamsWithContext creates a new ITAutomationUpdateScheduledTaskParams object
// with the ability to set a context for a request.
func NewITAutomationUpdateScheduledTaskParamsWithContext(ctx context.Context) *ITAutomationUpdateScheduledTaskParams {
	return &ITAutomationUpdateScheduledTaskParams{
		Context: ctx,
	}
}

// NewITAutomationUpdateScheduledTaskParamsWithHTTPClient creates a new ITAutomationUpdateScheduledTaskParams object
// with the ability to set a custom HTTPClient for a request.
func NewITAutomationUpdateScheduledTaskParamsWithHTTPClient(client *http.Client) *ITAutomationUpdateScheduledTaskParams {
	return &ITAutomationUpdateScheduledTaskParams{
		HTTPClient: client,
	}
}

/*
ITAutomationUpdateScheduledTaskParams contains all the parameters to send to the API endpoint

	for the i t automation update scheduled task operation.

	Typically these are written to a http.Request.
*/
type ITAutomationUpdateScheduledTaskParams struct {

	// Body.
	Body *models.ItautomationUpdateScheduledTaskRequest

	/* ID.

	   The id of the scheduled task to update
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the i t automation update scheduled task params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ITAutomationUpdateScheduledTaskParams) WithDefaults() *ITAutomationUpdateScheduledTaskParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the i t automation update scheduled task params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ITAutomationUpdateScheduledTaskParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the i t automation update scheduled task params
func (o *ITAutomationUpdateScheduledTaskParams) WithTimeout(timeout time.Duration) *ITAutomationUpdateScheduledTaskParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the i t automation update scheduled task params
func (o *ITAutomationUpdateScheduledTaskParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the i t automation update scheduled task params
func (o *ITAutomationUpdateScheduledTaskParams) WithContext(ctx context.Context) *ITAutomationUpdateScheduledTaskParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the i t automation update scheduled task params
func (o *ITAutomationUpdateScheduledTaskParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the i t automation update scheduled task params
func (o *ITAutomationUpdateScheduledTaskParams) WithHTTPClient(client *http.Client) *ITAutomationUpdateScheduledTaskParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the i t automation update scheduled task params
func (o *ITAutomationUpdateScheduledTaskParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the i t automation update scheduled task params
func (o *ITAutomationUpdateScheduledTaskParams) WithBody(body *models.ItautomationUpdateScheduledTaskRequest) *ITAutomationUpdateScheduledTaskParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the i t automation update scheduled task params
func (o *ITAutomationUpdateScheduledTaskParams) SetBody(body *models.ItautomationUpdateScheduledTaskRequest) {
	o.Body = body
}

// WithID adds the id to the i t automation update scheduled task params
func (o *ITAutomationUpdateScheduledTaskParams) WithID(id string) *ITAutomationUpdateScheduledTaskParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the i t automation update scheduled task params
func (o *ITAutomationUpdateScheduledTaskParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *ITAutomationUpdateScheduledTaskParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
