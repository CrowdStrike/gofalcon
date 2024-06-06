// Code generated by go-swagger; DO NOT EDIT.

package workflows

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

// NewExecutionActionParams creates a new ExecutionActionParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewExecutionActionParams() *ExecutionActionParams {
	return &ExecutionActionParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewExecutionActionParamsWithTimeout creates a new ExecutionActionParams object
// with the ability to set a timeout on a request.
func NewExecutionActionParamsWithTimeout(timeout time.Duration) *ExecutionActionParams {
	return &ExecutionActionParams{
		timeout: timeout,
	}
}

// NewExecutionActionParamsWithContext creates a new ExecutionActionParams object
// with the ability to set a context for a request.
func NewExecutionActionParamsWithContext(ctx context.Context) *ExecutionActionParams {
	return &ExecutionActionParams{
		Context: ctx,
	}
}

// NewExecutionActionParamsWithHTTPClient creates a new ExecutionActionParams object
// with the ability to set a custom HTTPClient for a request.
func NewExecutionActionParamsWithHTTPClient(client *http.Client) *ExecutionActionParams {
	return &ExecutionActionParams{
		HTTPClient: client,
	}
}

/*
ExecutionActionParams contains all the parameters to send to the API endpoint

	for the execution action operation.

	Typically these are written to a http.Request.
*/
type ExecutionActionParams struct {

	/* ActionName.

	     Specify one of these actions:

	- `resume`: resume/retry the workflow execution(s) specified in ids
	*/
	ActionName string

	// Body.
	Body *models.ClientActionRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the execution action params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExecutionActionParams) WithDefaults() *ExecutionActionParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the execution action params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExecutionActionParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the execution action params
func (o *ExecutionActionParams) WithTimeout(timeout time.Duration) *ExecutionActionParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the execution action params
func (o *ExecutionActionParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the execution action params
func (o *ExecutionActionParams) WithContext(ctx context.Context) *ExecutionActionParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the execution action params
func (o *ExecutionActionParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the execution action params
func (o *ExecutionActionParams) WithHTTPClient(client *http.Client) *ExecutionActionParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the execution action params
func (o *ExecutionActionParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithActionName adds the actionName to the execution action params
func (o *ExecutionActionParams) WithActionName(actionName string) *ExecutionActionParams {
	o.SetActionName(actionName)
	return o
}

// SetActionName adds the actionName to the execution action params
func (o *ExecutionActionParams) SetActionName(actionName string) {
	o.ActionName = actionName
}

// WithBody adds the body to the execution action params
func (o *ExecutionActionParams) WithBody(body *models.ClientActionRequest) *ExecutionActionParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the execution action params
func (o *ExecutionActionParams) SetBody(body *models.ClientActionRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ExecutionActionParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param action_name
	qrActionName := o.ActionName
	qActionName := qrActionName
	if qActionName != "" {

		if err := r.SetQueryParam("action_name", qActionName); err != nil {
			return err
		}
	}
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
