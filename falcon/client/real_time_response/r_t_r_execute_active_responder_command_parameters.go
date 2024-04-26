// Code generated by go-swagger; DO NOT EDIT.

package real_time_response

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

// NewRTRExecuteActiveResponderCommandParams creates a new RTRExecuteActiveResponderCommandParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRTRExecuteActiveResponderCommandParams() *RTRExecuteActiveResponderCommandParams {
	return &RTRExecuteActiveResponderCommandParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRTRExecuteActiveResponderCommandParamsWithTimeout creates a new RTRExecuteActiveResponderCommandParams object
// with the ability to set a timeout on a request.
func NewRTRExecuteActiveResponderCommandParamsWithTimeout(timeout time.Duration) *RTRExecuteActiveResponderCommandParams {
	return &RTRExecuteActiveResponderCommandParams{
		timeout: timeout,
	}
}

// NewRTRExecuteActiveResponderCommandParamsWithContext creates a new RTRExecuteActiveResponderCommandParams object
// with the ability to set a context for a request.
func NewRTRExecuteActiveResponderCommandParamsWithContext(ctx context.Context) *RTRExecuteActiveResponderCommandParams {
	return &RTRExecuteActiveResponderCommandParams{
		Context: ctx,
	}
}

// NewRTRExecuteActiveResponderCommandParamsWithHTTPClient creates a new RTRExecuteActiveResponderCommandParams object
// with the ability to set a custom HTTPClient for a request.
func NewRTRExecuteActiveResponderCommandParamsWithHTTPClient(client *http.Client) *RTRExecuteActiveResponderCommandParams {
	return &RTRExecuteActiveResponderCommandParams{
		HTTPClient: client,
	}
}

/*
RTRExecuteActiveResponderCommandParams contains all the parameters to send to the API endpoint

	for the r t r execute active responder command operation.

	Typically these are written to a http.Request.
*/
type RTRExecuteActiveResponderCommandParams struct {

	/* Body.

	     Use this endpoint to run these [real time response commands](https://falcon.crowdstrike.com/documentation/page/b8c1738c/real-time-response-and-network-containment#k893b7c0):
	- `cat`
	- `cd`
	- `clear`
	- `cp`
	- `encrypt`
	- `env`
	- `eventlog`
	- `filehash`
	- `get`
	- `getsid`
	- `help`
	- `history`
	- `ipconfig`
	- `kill`
	- `ls`
	- `map`
	- `memdump`
	- `mkdir`
	- `mount`
	- `mv`
	- `netstat`
	- `ps`
	- `reg query`
	- `reg set`
	- `reg delete`
	- `reg load`
	- `reg unload`
	- `restart`
	- `rm`
	- `runscript`
	- `shutdown`
	- `unmap`
	- `update history`
	- `update install`
	- `update list`
	- `update query`
	- `xmemdump`
	- `zip`

	Required values.  The rest of the fields are unused.
	**`base_command`** Active-Responder command type we are going to execute, for example: `get` or `cp`.  Refer to the RTR documentation for the full list of commands.
	**`command_string`** Full command string for the command. For example  `get some_file.txt`
	**`session_id`** RTR session ID to run the command on
	*/
	Body *models.DomainCommandExecuteRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the r t r execute active responder command params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RTRExecuteActiveResponderCommandParams) WithDefaults() *RTRExecuteActiveResponderCommandParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the r t r execute active responder command params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RTRExecuteActiveResponderCommandParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the r t r execute active responder command params
func (o *RTRExecuteActiveResponderCommandParams) WithTimeout(timeout time.Duration) *RTRExecuteActiveResponderCommandParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the r t r execute active responder command params
func (o *RTRExecuteActiveResponderCommandParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the r t r execute active responder command params
func (o *RTRExecuteActiveResponderCommandParams) WithContext(ctx context.Context) *RTRExecuteActiveResponderCommandParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the r t r execute active responder command params
func (o *RTRExecuteActiveResponderCommandParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the r t r execute active responder command params
func (o *RTRExecuteActiveResponderCommandParams) WithHTTPClient(client *http.Client) *RTRExecuteActiveResponderCommandParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the r t r execute active responder command params
func (o *RTRExecuteActiveResponderCommandParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the r t r execute active responder command params
func (o *RTRExecuteActiveResponderCommandParams) WithBody(body *models.DomainCommandExecuteRequest) *RTRExecuteActiveResponderCommandParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the r t r execute active responder command params
func (o *RTRExecuteActiveResponderCommandParams) SetBody(body *models.DomainCommandExecuteRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *RTRExecuteActiveResponderCommandParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
