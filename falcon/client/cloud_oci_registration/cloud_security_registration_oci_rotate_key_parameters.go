// Code generated by go-swagger; DO NOT EDIT.

package cloud_oci_registration

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

// NewCloudSecurityRegistrationOciRotateKeyParams creates a new CloudSecurityRegistrationOciRotateKeyParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCloudSecurityRegistrationOciRotateKeyParams() *CloudSecurityRegistrationOciRotateKeyParams {
	return &CloudSecurityRegistrationOciRotateKeyParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCloudSecurityRegistrationOciRotateKeyParamsWithTimeout creates a new CloudSecurityRegistrationOciRotateKeyParams object
// with the ability to set a timeout on a request.
func NewCloudSecurityRegistrationOciRotateKeyParamsWithTimeout(timeout time.Duration) *CloudSecurityRegistrationOciRotateKeyParams {
	return &CloudSecurityRegistrationOciRotateKeyParams{
		timeout: timeout,
	}
}

// NewCloudSecurityRegistrationOciRotateKeyParamsWithContext creates a new CloudSecurityRegistrationOciRotateKeyParams object
// with the ability to set a context for a request.
func NewCloudSecurityRegistrationOciRotateKeyParamsWithContext(ctx context.Context) *CloudSecurityRegistrationOciRotateKeyParams {
	return &CloudSecurityRegistrationOciRotateKeyParams{
		Context: ctx,
	}
}

// NewCloudSecurityRegistrationOciRotateKeyParamsWithHTTPClient creates a new CloudSecurityRegistrationOciRotateKeyParams object
// with the ability to set a custom HTTPClient for a request.
func NewCloudSecurityRegistrationOciRotateKeyParamsWithHTTPClient(client *http.Client) *CloudSecurityRegistrationOciRotateKeyParams {
	return &CloudSecurityRegistrationOciRotateKeyParams{
		HTTPClient: client,
	}
}

/*
CloudSecurityRegistrationOciRotateKeyParams contains all the parameters to send to the API endpoint

	for the cloud security registration oci rotate key operation.

	Typically these are written to a http.Request.
*/
type CloudSecurityRegistrationOciRotateKeyParams struct {

	// Body.
	Body *models.DomainOCITenancyRotateKeyRequestExtV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the cloud security registration oci rotate key params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CloudSecurityRegistrationOciRotateKeyParams) WithDefaults() *CloudSecurityRegistrationOciRotateKeyParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the cloud security registration oci rotate key params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CloudSecurityRegistrationOciRotateKeyParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the cloud security registration oci rotate key params
func (o *CloudSecurityRegistrationOciRotateKeyParams) WithTimeout(timeout time.Duration) *CloudSecurityRegistrationOciRotateKeyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the cloud security registration oci rotate key params
func (o *CloudSecurityRegistrationOciRotateKeyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the cloud security registration oci rotate key params
func (o *CloudSecurityRegistrationOciRotateKeyParams) WithContext(ctx context.Context) *CloudSecurityRegistrationOciRotateKeyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the cloud security registration oci rotate key params
func (o *CloudSecurityRegistrationOciRotateKeyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the cloud security registration oci rotate key params
func (o *CloudSecurityRegistrationOciRotateKeyParams) WithHTTPClient(client *http.Client) *CloudSecurityRegistrationOciRotateKeyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the cloud security registration oci rotate key params
func (o *CloudSecurityRegistrationOciRotateKeyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the cloud security registration oci rotate key params
func (o *CloudSecurityRegistrationOciRotateKeyParams) WithBody(body *models.DomainOCITenancyRotateKeyRequestExtV1) *CloudSecurityRegistrationOciRotateKeyParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the cloud security registration oci rotate key params
func (o *CloudSecurityRegistrationOciRotateKeyParams) SetBody(body *models.DomainOCITenancyRotateKeyRequestExtV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CloudSecurityRegistrationOciRotateKeyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
