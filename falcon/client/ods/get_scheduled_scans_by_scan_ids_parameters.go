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

// NewGetScheduledScansByScanIdsParams creates a new GetScheduledScansByScanIdsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetScheduledScansByScanIdsParams() *GetScheduledScansByScanIdsParams {
	return &GetScheduledScansByScanIdsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetScheduledScansByScanIdsParamsWithTimeout creates a new GetScheduledScansByScanIdsParams object
// with the ability to set a timeout on a request.
func NewGetScheduledScansByScanIdsParamsWithTimeout(timeout time.Duration) *GetScheduledScansByScanIdsParams {
	return &GetScheduledScansByScanIdsParams{
		timeout: timeout,
	}
}

// NewGetScheduledScansByScanIdsParamsWithContext creates a new GetScheduledScansByScanIdsParams object
// with the ability to set a context for a request.
func NewGetScheduledScansByScanIdsParamsWithContext(ctx context.Context) *GetScheduledScansByScanIdsParams {
	return &GetScheduledScansByScanIdsParams{
		Context: ctx,
	}
}

// NewGetScheduledScansByScanIdsParamsWithHTTPClient creates a new GetScheduledScansByScanIdsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetScheduledScansByScanIdsParamsWithHTTPClient(client *http.Client) *GetScheduledScansByScanIdsParams {
	return &GetScheduledScansByScanIdsParams{
		HTTPClient: client,
	}
}

/*
GetScheduledScansByScanIdsParams contains all the parameters to send to the API endpoint

	for the get scheduled scans by scan ids operation.

	Typically these are written to a http.Request.
*/
type GetScheduledScansByScanIdsParams struct {

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

// WithDefaults hydrates default values in the get scheduled scans by scan ids params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetScheduledScansByScanIdsParams) WithDefaults() *GetScheduledScansByScanIdsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get scheduled scans by scan ids params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetScheduledScansByScanIdsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get scheduled scans by scan ids params
func (o *GetScheduledScansByScanIdsParams) WithTimeout(timeout time.Duration) *GetScheduledScansByScanIdsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get scheduled scans by scan ids params
func (o *GetScheduledScansByScanIdsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get scheduled scans by scan ids params
func (o *GetScheduledScansByScanIdsParams) WithContext(ctx context.Context) *GetScheduledScansByScanIdsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get scheduled scans by scan ids params
func (o *GetScheduledScansByScanIdsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get scheduled scans by scan ids params
func (o *GetScheduledScansByScanIdsParams) WithHTTPClient(client *http.Client) *GetScheduledScansByScanIdsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get scheduled scans by scan ids params
func (o *GetScheduledScansByScanIdsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithXCSUSERUUID adds the xCSUSERUUID to the get scheduled scans by scan ids params
func (o *GetScheduledScansByScanIdsParams) WithXCSUSERUUID(xCSUSERUUID string) *GetScheduledScansByScanIdsParams {
	o.SetXCSUSERUUID(xCSUSERUUID)
	return o
}

// SetXCSUSERUUID adds the xCSUSERUuid to the get scheduled scans by scan ids params
func (o *GetScheduledScansByScanIdsParams) SetXCSUSERUUID(xCSUSERUUID string) {
	o.XCSUSERUUID = xCSUSERUUID
}

// WithIds adds the ids to the get scheduled scans by scan ids params
func (o *GetScheduledScansByScanIdsParams) WithIds(ids []string) *GetScheduledScansByScanIdsParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get scheduled scans by scan ids params
func (o *GetScheduledScansByScanIdsParams) SetIds(ids []string) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *GetScheduledScansByScanIdsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

// bindParamGetScheduledScansByScanIds binds the parameter ids
func (o *GetScheduledScansByScanIdsParams) bindParamIds(formats strfmt.Registry) []string {
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
