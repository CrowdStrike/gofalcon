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
	"github.com/go-openapi/swag"
)

// NewITAutomationGetTaskExecutionParams creates a new ITAutomationGetTaskExecutionParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewITAutomationGetTaskExecutionParams() *ITAutomationGetTaskExecutionParams {
	return &ITAutomationGetTaskExecutionParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewITAutomationGetTaskExecutionParamsWithTimeout creates a new ITAutomationGetTaskExecutionParams object
// with the ability to set a timeout on a request.
func NewITAutomationGetTaskExecutionParamsWithTimeout(timeout time.Duration) *ITAutomationGetTaskExecutionParams {
	return &ITAutomationGetTaskExecutionParams{
		timeout: timeout,
	}
}

// NewITAutomationGetTaskExecutionParamsWithContext creates a new ITAutomationGetTaskExecutionParams object
// with the ability to set a context for a request.
func NewITAutomationGetTaskExecutionParamsWithContext(ctx context.Context) *ITAutomationGetTaskExecutionParams {
	return &ITAutomationGetTaskExecutionParams{
		Context: ctx,
	}
}

// NewITAutomationGetTaskExecutionParamsWithHTTPClient creates a new ITAutomationGetTaskExecutionParams object
// with the ability to set a custom HTTPClient for a request.
func NewITAutomationGetTaskExecutionParamsWithHTTPClient(client *http.Client) *ITAutomationGetTaskExecutionParams {
	return &ITAutomationGetTaskExecutionParams{
		HTTPClient: client,
	}
}

/*
ITAutomationGetTaskExecutionParams contains all the parameters to send to the API endpoint

	for the i t automation get task execution operation.

	Typically these are written to a http.Request.
*/
type ITAutomationGetTaskExecutionParams struct {

	/* Ids.

	   Task execution IDs to fetch. Use ITAutomationSearchTaskExecutions to get the execution id
	*/
	Ids []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the i t automation get task execution params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ITAutomationGetTaskExecutionParams) WithDefaults() *ITAutomationGetTaskExecutionParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the i t automation get task execution params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ITAutomationGetTaskExecutionParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the i t automation get task execution params
func (o *ITAutomationGetTaskExecutionParams) WithTimeout(timeout time.Duration) *ITAutomationGetTaskExecutionParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the i t automation get task execution params
func (o *ITAutomationGetTaskExecutionParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the i t automation get task execution params
func (o *ITAutomationGetTaskExecutionParams) WithContext(ctx context.Context) *ITAutomationGetTaskExecutionParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the i t automation get task execution params
func (o *ITAutomationGetTaskExecutionParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the i t automation get task execution params
func (o *ITAutomationGetTaskExecutionParams) WithHTTPClient(client *http.Client) *ITAutomationGetTaskExecutionParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the i t automation get task execution params
func (o *ITAutomationGetTaskExecutionParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the i t automation get task execution params
func (o *ITAutomationGetTaskExecutionParams) WithIds(ids []string) *ITAutomationGetTaskExecutionParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the i t automation get task execution params
func (o *ITAutomationGetTaskExecutionParams) SetIds(ids []string) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *ITAutomationGetTaskExecutionParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Ids != nil {

		// binding items for ids
		joinedIds := o.bindParamIds(reg)

		// query array param ids
		if err := r.SetQueryParam("ids", joinedIds...); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamITAutomationGetTaskExecution binds the parameter ids
func (o *ITAutomationGetTaskExecutionParams) bindParamIds(formats strfmt.Registry) []string {
	idsIR := o.Ids

	var idsIC []string
	for _, idsIIR := range idsIR { // explode []string

		idsIIV := idsIIR // string as string
		idsIC = append(idsIC, idsIIV)
	}

	// items.CollectionFormat: "multi"
	idsIS := swag.JoinByFormat(idsIC, "multi")

	return idsIS
}
