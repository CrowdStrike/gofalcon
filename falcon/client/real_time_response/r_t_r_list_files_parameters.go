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
)

// NewRTRListFilesParams creates a new RTRListFilesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRTRListFilesParams() *RTRListFilesParams {
	return &RTRListFilesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRTRListFilesParamsWithTimeout creates a new RTRListFilesParams object
// with the ability to set a timeout on a request.
func NewRTRListFilesParamsWithTimeout(timeout time.Duration) *RTRListFilesParams {
	return &RTRListFilesParams{
		timeout: timeout,
	}
}

// NewRTRListFilesParamsWithContext creates a new RTRListFilesParams object
// with the ability to set a context for a request.
func NewRTRListFilesParamsWithContext(ctx context.Context) *RTRListFilesParams {
	return &RTRListFilesParams{
		Context: ctx,
	}
}

// NewRTRListFilesParamsWithHTTPClient creates a new RTRListFilesParams object
// with the ability to set a custom HTTPClient for a request.
func NewRTRListFilesParamsWithHTTPClient(client *http.Client) *RTRListFilesParams {
	return &RTRListFilesParams{
		HTTPClient: client,
	}
}

/* RTRListFilesParams contains all the parameters to send to the API endpoint
   for the r t r list files operation.

   Typically these are written to a http.Request.
*/
type RTRListFilesParams struct {

	/* SessionID.

	   RTR Session id
	*/
	SessionID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the r t r list files params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RTRListFilesParams) WithDefaults() *RTRListFilesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the r t r list files params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RTRListFilesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the r t r list files params
func (o *RTRListFilesParams) WithTimeout(timeout time.Duration) *RTRListFilesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the r t r list files params
func (o *RTRListFilesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the r t r list files params
func (o *RTRListFilesParams) WithContext(ctx context.Context) *RTRListFilesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the r t r list files params
func (o *RTRListFilesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the r t r list files params
func (o *RTRListFilesParams) WithHTTPClient(client *http.Client) *RTRListFilesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the r t r list files params
func (o *RTRListFilesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSessionID adds the sessionID to the r t r list files params
func (o *RTRListFilesParams) WithSessionID(sessionID string) *RTRListFilesParams {
	o.SetSessionID(sessionID)
	return o
}

// SetSessionID adds the sessionId to the r t r list files params
func (o *RTRListFilesParams) SetSessionID(sessionID string) {
	o.SessionID = sessionID
}

// WriteToRequest writes these params to a swagger request
func (o *RTRListFilesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param session_id
	qrSessionID := o.SessionID
	qSessionID := qrSessionID
	if qSessionID != "" {

		if err := r.SetQueryParam("session_id", qSessionID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
