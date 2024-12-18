// Code generated by go-swagger; DO NOT EDIT.

package quick_scan_pro

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

// NewLaunchScanParams creates a new LaunchScanParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewLaunchScanParams() *LaunchScanParams {
	return &LaunchScanParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewLaunchScanParamsWithTimeout creates a new LaunchScanParams object
// with the ability to set a timeout on a request.
func NewLaunchScanParamsWithTimeout(timeout time.Duration) *LaunchScanParams {
	return &LaunchScanParams{
		timeout: timeout,
	}
}

// NewLaunchScanParamsWithContext creates a new LaunchScanParams object
// with the ability to set a context for a request.
func NewLaunchScanParamsWithContext(ctx context.Context) *LaunchScanParams {
	return &LaunchScanParams{
		Context: ctx,
	}
}

// NewLaunchScanParamsWithHTTPClient creates a new LaunchScanParams object
// with the ability to set a custom HTTPClient for a request.
func NewLaunchScanParamsWithHTTPClient(client *http.Client) *LaunchScanParams {
	return &LaunchScanParams{
		HTTPClient: client,
	}
}

/*
LaunchScanParams contains all the parameters to send to the API endpoint

	for the launch scan operation.

	Typically these are written to a http.Request.
*/
type LaunchScanParams struct {

	// Body.
	Body *models.QuickscanproLaunchScanRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the launch scan params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *LaunchScanParams) WithDefaults() *LaunchScanParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the launch scan params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *LaunchScanParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the launch scan params
func (o *LaunchScanParams) WithTimeout(timeout time.Duration) *LaunchScanParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the launch scan params
func (o *LaunchScanParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the launch scan params
func (o *LaunchScanParams) WithContext(ctx context.Context) *LaunchScanParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the launch scan params
func (o *LaunchScanParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the launch scan params
func (o *LaunchScanParams) WithHTTPClient(client *http.Client) *LaunchScanParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the launch scan params
func (o *LaunchScanParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the launch scan params
func (o *LaunchScanParams) WithBody(body *models.QuickscanproLaunchScanRequest) *LaunchScanParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the launch scan params
func (o *LaunchScanParams) SetBody(body *models.QuickscanproLaunchScanRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *LaunchScanParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
