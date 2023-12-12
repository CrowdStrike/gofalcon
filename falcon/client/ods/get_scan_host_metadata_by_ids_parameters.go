// Code generated by go-swagger; DO NOT EDIT.

package ods

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

// NewGetScanHostMetadataByIdsParams creates a new GetScanHostMetadataByIdsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetScanHostMetadataByIdsParams() *GetScanHostMetadataByIdsParams {
	return &GetScanHostMetadataByIdsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetScanHostMetadataByIdsParamsWithTimeout creates a new GetScanHostMetadataByIdsParams object
// with the ability to set a timeout on a request.
func NewGetScanHostMetadataByIdsParamsWithTimeout(timeout time.Duration) *GetScanHostMetadataByIdsParams {
	return &GetScanHostMetadataByIdsParams{
		timeout: timeout,
	}
}

// NewGetScanHostMetadataByIdsParamsWithContext creates a new GetScanHostMetadataByIdsParams object
// with the ability to set a context for a request.
func NewGetScanHostMetadataByIdsParamsWithContext(ctx context.Context) *GetScanHostMetadataByIdsParams {
	return &GetScanHostMetadataByIdsParams{
		Context: ctx,
	}
}

// NewGetScanHostMetadataByIdsParamsWithHTTPClient creates a new GetScanHostMetadataByIdsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetScanHostMetadataByIdsParamsWithHTTPClient(client *http.Client) *GetScanHostMetadataByIdsParams {
	return &GetScanHostMetadataByIdsParams{
		HTTPClient: client,
	}
}

/*
GetScanHostMetadataByIdsParams contains all the parameters to send to the API endpoint

	for the get scan host metadata by ids operation.

	Typically these are written to a http.Request.
*/
type GetScanHostMetadataByIdsParams struct {

	/* XCSUSERUUID.

	   The user ID
	*/
	XCSUSERUUID string

	/* Ids.

	   The scan IDs to retrieve the scan entities
	*/
	Ids []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get scan host metadata by ids params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetScanHostMetadataByIdsParams) WithDefaults() *GetScanHostMetadataByIdsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get scan host metadata by ids params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetScanHostMetadataByIdsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get scan host metadata by ids params
func (o *GetScanHostMetadataByIdsParams) WithTimeout(timeout time.Duration) *GetScanHostMetadataByIdsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get scan host metadata by ids params
func (o *GetScanHostMetadataByIdsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get scan host metadata by ids params
func (o *GetScanHostMetadataByIdsParams) WithContext(ctx context.Context) *GetScanHostMetadataByIdsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get scan host metadata by ids params
func (o *GetScanHostMetadataByIdsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get scan host metadata by ids params
func (o *GetScanHostMetadataByIdsParams) WithHTTPClient(client *http.Client) *GetScanHostMetadataByIdsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get scan host metadata by ids params
func (o *GetScanHostMetadataByIdsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithXCSUSERUUID adds the xCSUSERUUID to the get scan host metadata by ids params
func (o *GetScanHostMetadataByIdsParams) WithXCSUSERUUID(xCSUSERUUID string) *GetScanHostMetadataByIdsParams {
	o.SetXCSUSERUUID(xCSUSERUUID)
	return o
}

// SetXCSUSERUUID adds the xCSUSERUuid to the get scan host metadata by ids params
func (o *GetScanHostMetadataByIdsParams) SetXCSUSERUUID(xCSUSERUUID string) {
	o.XCSUSERUUID = xCSUSERUUID
}

// WithIds adds the ids to the get scan host metadata by ids params
func (o *GetScanHostMetadataByIdsParams) WithIds(ids []string) *GetScanHostMetadataByIdsParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get scan host metadata by ids params
func (o *GetScanHostMetadataByIdsParams) SetIds(ids []string) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *GetScanHostMetadataByIdsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param X-CS-USERUUID
	if err := r.SetHeaderParam("X-CS-USERUUID", o.XCSUSERUUID); err != nil {
		return err
	}

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

// bindParamGetScanHostMetadataByIds binds the parameter ids
func (o *GetScanHostMetadataByIdsParams) bindParamIds(formats strfmt.Registry) []string {
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
