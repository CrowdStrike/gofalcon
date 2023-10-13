// Code generated by go-swagger; DO NOT EDIT.

package falcon_container_cli

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

// NewReadImageVulnerabilitiesParams creates a new ReadImageVulnerabilitiesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewReadImageVulnerabilitiesParams() *ReadImageVulnerabilitiesParams {
	return &ReadImageVulnerabilitiesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewReadImageVulnerabilitiesParamsWithTimeout creates a new ReadImageVulnerabilitiesParams object
// with the ability to set a timeout on a request.
func NewReadImageVulnerabilitiesParamsWithTimeout(timeout time.Duration) *ReadImageVulnerabilitiesParams {
	return &ReadImageVulnerabilitiesParams{
		timeout: timeout,
	}
}

// NewReadImageVulnerabilitiesParamsWithContext creates a new ReadImageVulnerabilitiesParams object
// with the ability to set a context for a request.
func NewReadImageVulnerabilitiesParamsWithContext(ctx context.Context) *ReadImageVulnerabilitiesParams {
	return &ReadImageVulnerabilitiesParams{
		Context: ctx,
	}
}

// NewReadImageVulnerabilitiesParamsWithHTTPClient creates a new ReadImageVulnerabilitiesParams object
// with the ability to set a custom HTTPClient for a request.
func NewReadImageVulnerabilitiesParamsWithHTTPClient(client *http.Client) *ReadImageVulnerabilitiesParams {
	return &ReadImageVulnerabilitiesParams{
		HTTPClient: client,
	}
}

/* ReadImageVulnerabilitiesParams contains all the parameters to send to the API endpoint
   for the read image vulnerabilities operation.

   Typically these are written to a http.Request.
*/
type ReadImageVulnerabilitiesParams struct {

	// Body.
	Body *models.APIImageLookupRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the read image vulnerabilities params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadImageVulnerabilitiesParams) WithDefaults() *ReadImageVulnerabilitiesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the read image vulnerabilities params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadImageVulnerabilitiesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the read image vulnerabilities params
func (o *ReadImageVulnerabilitiesParams) WithTimeout(timeout time.Duration) *ReadImageVulnerabilitiesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the read image vulnerabilities params
func (o *ReadImageVulnerabilitiesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the read image vulnerabilities params
func (o *ReadImageVulnerabilitiesParams) WithContext(ctx context.Context) *ReadImageVulnerabilitiesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the read image vulnerabilities params
func (o *ReadImageVulnerabilitiesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the read image vulnerabilities params
func (o *ReadImageVulnerabilitiesParams) WithHTTPClient(client *http.Client) *ReadImageVulnerabilitiesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the read image vulnerabilities params
func (o *ReadImageVulnerabilitiesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the read image vulnerabilities params
func (o *ReadImageVulnerabilitiesParams) WithBody(body *models.APIImageLookupRequest) *ReadImageVulnerabilitiesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the read image vulnerabilities params
func (o *ReadImageVulnerabilitiesParams) SetBody(body *models.APIImageLookupRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ReadImageVulnerabilitiesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
