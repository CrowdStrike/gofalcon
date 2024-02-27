// Code generated by go-swagger; DO NOT EDIT.

package image_assessment_policies

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

// NewDeletePolicyParams creates a new DeletePolicyParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeletePolicyParams() *DeletePolicyParams {
	return &DeletePolicyParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeletePolicyParamsWithTimeout creates a new DeletePolicyParams object
// with the ability to set a timeout on a request.
func NewDeletePolicyParamsWithTimeout(timeout time.Duration) *DeletePolicyParams {
	return &DeletePolicyParams{
		timeout: timeout,
	}
}

// NewDeletePolicyParamsWithContext creates a new DeletePolicyParams object
// with the ability to set a context for a request.
func NewDeletePolicyParamsWithContext(ctx context.Context) *DeletePolicyParams {
	return &DeletePolicyParams{
		Context: ctx,
	}
}

// NewDeletePolicyParamsWithHTTPClient creates a new DeletePolicyParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeletePolicyParamsWithHTTPClient(client *http.Client) *DeletePolicyParams {
	return &DeletePolicyParams{
		HTTPClient: client,
	}
}

/*
DeletePolicyParams contains all the parameters to send to the API endpoint

	for the delete policy operation.

	Typically these are written to a http.Request.
*/
type DeletePolicyParams struct {

	/* ID.

	   Image Assessment Policy entity UUID
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete policy params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeletePolicyParams) WithDefaults() *DeletePolicyParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete policy params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeletePolicyParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete policy params
func (o *DeletePolicyParams) WithTimeout(timeout time.Duration) *DeletePolicyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete policy params
func (o *DeletePolicyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete policy params
func (o *DeletePolicyParams) WithContext(ctx context.Context) *DeletePolicyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete policy params
func (o *DeletePolicyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete policy params
func (o *DeletePolicyParams) WithHTTPClient(client *http.Client) *DeletePolicyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete policy params
func (o *DeletePolicyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the delete policy params
func (o *DeletePolicyParams) WithID(id string) *DeletePolicyParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the delete policy params
func (o *DeletePolicyParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *DeletePolicyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

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
