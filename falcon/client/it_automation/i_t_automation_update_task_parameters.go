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

// NewITAutomationUpdateTaskParams creates a new ITAutomationUpdateTaskParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewITAutomationUpdateTaskParams() *ITAutomationUpdateTaskParams {
	return &ITAutomationUpdateTaskParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewITAutomationUpdateTaskParamsWithTimeout creates a new ITAutomationUpdateTaskParams object
// with the ability to set a timeout on a request.
func NewITAutomationUpdateTaskParamsWithTimeout(timeout time.Duration) *ITAutomationUpdateTaskParams {
	return &ITAutomationUpdateTaskParams{
		timeout: timeout,
	}
}

// NewITAutomationUpdateTaskParamsWithContext creates a new ITAutomationUpdateTaskParams object
// with the ability to set a context for a request.
func NewITAutomationUpdateTaskParamsWithContext(ctx context.Context) *ITAutomationUpdateTaskParams {
	return &ITAutomationUpdateTaskParams{
		Context: ctx,
	}
}

// NewITAutomationUpdateTaskParamsWithHTTPClient creates a new ITAutomationUpdateTaskParams object
// with the ability to set a custom HTTPClient for a request.
func NewITAutomationUpdateTaskParamsWithHTTPClient(client *http.Client) *ITAutomationUpdateTaskParams {
	return &ITAutomationUpdateTaskParams{
		HTTPClient: client,
	}
}

/*
ITAutomationUpdateTaskParams contains all the parameters to send to the API endpoint

	for the i t automation update task operation.

	Typically these are written to a http.Request.
*/
type ITAutomationUpdateTaskParams struct {

	// Body.
	Body *models.ItautomationUpdateTaskRequest

	/* ID.

	   ID of the task to update. Use ITAutomationSearchTasks to fetch IDs
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the i t automation update task params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ITAutomationUpdateTaskParams) WithDefaults() *ITAutomationUpdateTaskParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the i t automation update task params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ITAutomationUpdateTaskParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the i t automation update task params
func (o *ITAutomationUpdateTaskParams) WithTimeout(timeout time.Duration) *ITAutomationUpdateTaskParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the i t automation update task params
func (o *ITAutomationUpdateTaskParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the i t automation update task params
func (o *ITAutomationUpdateTaskParams) WithContext(ctx context.Context) *ITAutomationUpdateTaskParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the i t automation update task params
func (o *ITAutomationUpdateTaskParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the i t automation update task params
func (o *ITAutomationUpdateTaskParams) WithHTTPClient(client *http.Client) *ITAutomationUpdateTaskParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the i t automation update task params
func (o *ITAutomationUpdateTaskParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the i t automation update task params
func (o *ITAutomationUpdateTaskParams) WithBody(body *models.ItautomationUpdateTaskRequest) *ITAutomationUpdateTaskParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the i t automation update task params
func (o *ITAutomationUpdateTaskParams) SetBody(body *models.ItautomationUpdateTaskRequest) {
	o.Body = body
}

// WithID adds the id to the i t automation update task params
func (o *ITAutomationUpdateTaskParams) WithID(id string) *ITAutomationUpdateTaskParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the i t automation update task params
func (o *ITAutomationUpdateTaskParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *ITAutomationUpdateTaskParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
