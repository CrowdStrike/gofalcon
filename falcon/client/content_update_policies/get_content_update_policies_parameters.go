// Code generated by go-swagger; DO NOT EDIT.

package content_update_policies

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

// NewGetContentUpdatePoliciesParams creates a new GetContentUpdatePoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetContentUpdatePoliciesParams() *GetContentUpdatePoliciesParams {
	return &GetContentUpdatePoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetContentUpdatePoliciesParamsWithTimeout creates a new GetContentUpdatePoliciesParams object
// with the ability to set a timeout on a request.
func NewGetContentUpdatePoliciesParamsWithTimeout(timeout time.Duration) *GetContentUpdatePoliciesParams {
	return &GetContentUpdatePoliciesParams{
		timeout: timeout,
	}
}

// NewGetContentUpdatePoliciesParamsWithContext creates a new GetContentUpdatePoliciesParams object
// with the ability to set a context for a request.
func NewGetContentUpdatePoliciesParamsWithContext(ctx context.Context) *GetContentUpdatePoliciesParams {
	return &GetContentUpdatePoliciesParams{
		Context: ctx,
	}
}

// NewGetContentUpdatePoliciesParamsWithHTTPClient creates a new GetContentUpdatePoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetContentUpdatePoliciesParamsWithHTTPClient(client *http.Client) *GetContentUpdatePoliciesParams {
	return &GetContentUpdatePoliciesParams{
		HTTPClient: client,
	}
}

/*
GetContentUpdatePoliciesParams contains all the parameters to send to the API endpoint

	for the get content update policies operation.

	Typically these are written to a http.Request.
*/
type GetContentUpdatePoliciesParams struct {

	/* Ids.

	   The IDs of the Content Update Policies to return
	*/
	Ids []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get content update policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetContentUpdatePoliciesParams) WithDefaults() *GetContentUpdatePoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get content update policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetContentUpdatePoliciesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get content update policies params
func (o *GetContentUpdatePoliciesParams) WithTimeout(timeout time.Duration) *GetContentUpdatePoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get content update policies params
func (o *GetContentUpdatePoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get content update policies params
func (o *GetContentUpdatePoliciesParams) WithContext(ctx context.Context) *GetContentUpdatePoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get content update policies params
func (o *GetContentUpdatePoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get content update policies params
func (o *GetContentUpdatePoliciesParams) WithHTTPClient(client *http.Client) *GetContentUpdatePoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get content update policies params
func (o *GetContentUpdatePoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the get content update policies params
func (o *GetContentUpdatePoliciesParams) WithIds(ids []string) *GetContentUpdatePoliciesParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get content update policies params
func (o *GetContentUpdatePoliciesParams) SetIds(ids []string) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *GetContentUpdatePoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

// bindParamGetContentUpdatePolicies binds the parameter ids
func (o *GetContentUpdatePoliciesParams) bindParamIds(formats strfmt.Registry) []string {
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
