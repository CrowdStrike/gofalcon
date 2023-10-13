// Code generated by go-swagger; DO NOT EDIT.

package scheduled_reports

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

// NewExecuteParams creates a new ExecuteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewExecuteParams() *ExecuteParams {
	return &ExecuteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewExecuteParamsWithTimeout creates a new ExecuteParams object
// with the ability to set a timeout on a request.
func NewExecuteParamsWithTimeout(timeout time.Duration) *ExecuteParams {
	return &ExecuteParams{
		timeout: timeout,
	}
}

// NewExecuteParamsWithContext creates a new ExecuteParams object
// with the ability to set a context for a request.
func NewExecuteParamsWithContext(ctx context.Context) *ExecuteParams {
	return &ExecuteParams{
		Context: ctx,
	}
}

// NewExecuteParamsWithHTTPClient creates a new ExecuteParams object
// with the ability to set a custom HTTPClient for a request.
func NewExecuteParamsWithHTTPClient(client *http.Client) *ExecuteParams {
	return &ExecuteParams{
		HTTPClient: client,
	}
}

/* ExecuteParams contains all the parameters to send to the API endpoint
   for the execute operation.

   Typically these are written to a http.Request.
*/
type ExecuteParams struct {

	// Body.
	Body []*models.DomainReportExecutionLaunchRequestV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the execute params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExecuteParams) WithDefaults() *ExecuteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the execute params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExecuteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the execute params
func (o *ExecuteParams) WithTimeout(timeout time.Duration) *ExecuteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the execute params
func (o *ExecuteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the execute params
func (o *ExecuteParams) WithContext(ctx context.Context) *ExecuteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the execute params
func (o *ExecuteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the execute params
func (o *ExecuteParams) WithHTTPClient(client *http.Client) *ExecuteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the execute params
func (o *ExecuteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the execute params
func (o *ExecuteParams) WithBody(body []*models.DomainReportExecutionLaunchRequestV1) *ExecuteParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the execute params
func (o *ExecuteParams) SetBody(body []*models.DomainReportExecutionLaunchRequestV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ExecuteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
