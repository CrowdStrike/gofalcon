// Code generated by go-swagger; DO NOT EDIT.

package cspm_registration

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

// NewGetCSPMCGPAccountParams creates a new GetCSPMCGPAccountParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetCSPMCGPAccountParams() *GetCSPMCGPAccountParams {
	return &GetCSPMCGPAccountParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetCSPMCGPAccountParamsWithTimeout creates a new GetCSPMCGPAccountParams object
// with the ability to set a timeout on a request.
func NewGetCSPMCGPAccountParamsWithTimeout(timeout time.Duration) *GetCSPMCGPAccountParams {
	return &GetCSPMCGPAccountParams{
		timeout: timeout,
	}
}

// NewGetCSPMCGPAccountParamsWithContext creates a new GetCSPMCGPAccountParams object
// with the ability to set a context for a request.
func NewGetCSPMCGPAccountParamsWithContext(ctx context.Context) *GetCSPMCGPAccountParams {
	return &GetCSPMCGPAccountParams{
		Context: ctx,
	}
}

// NewGetCSPMCGPAccountParamsWithHTTPClient creates a new GetCSPMCGPAccountParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetCSPMCGPAccountParamsWithHTTPClient(client *http.Client) *GetCSPMCGPAccountParams {
	return &GetCSPMCGPAccountParams{
		HTTPClient: client,
	}
}

/*
GetCSPMCGPAccountParams contains all the parameters to send to the API endpoint

	for the get c s p m c g p account operation.

	Typically these are written to a http.Request.
*/
type GetCSPMCGPAccountParams struct {

	/* Ids.

	   Hierarchical Resource IDs of accounts
	*/
	Ids []string

	/* Limit.

	   The maximum records to return. Defaults to 100.

	   Default: 100
	*/
	Limit *int64

	/* Offset.

	   The offset to start retrieving records from
	*/
	Offset *int64

	/* ParentType.

	   GCP Hierarchy Parent Type, organization/folder/project
	*/
	ParentType *string

	/* ScanType.

	   Type of scan, dry or full, to perform on selected accounts
	*/
	ScanType *string

	/* Sort.

	   Order fields in ascending or descending order. Ex: parent_type|asc.
	*/
	Sort *string

	/* Status.

	   Account status to filter results by.
	*/
	Status *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get c s p m c g p account params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCSPMCGPAccountParams) WithDefaults() *GetCSPMCGPAccountParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get c s p m c g p account params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCSPMCGPAccountParams) SetDefaults() {
	var (
		limitDefault = int64(100)
	)

	val := GetCSPMCGPAccountParams{
		Limit: &limitDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) WithTimeout(timeout time.Duration) *GetCSPMCGPAccountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) WithContext(ctx context.Context) *GetCSPMCGPAccountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) WithHTTPClient(client *http.Client) *GetCSPMCGPAccountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) WithIds(ids []string) *GetCSPMCGPAccountParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) SetIds(ids []string) {
	o.Ids = ids
}

// WithLimit adds the limit to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) WithLimit(limit *int64) *GetCSPMCGPAccountParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) WithOffset(offset *int64) *GetCSPMCGPAccountParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithParentType adds the parentType to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) WithParentType(parentType *string) *GetCSPMCGPAccountParams {
	o.SetParentType(parentType)
	return o
}

// SetParentType adds the parentType to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) SetParentType(parentType *string) {
	o.ParentType = parentType
}

// WithScanType adds the scanType to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) WithScanType(scanType *string) *GetCSPMCGPAccountParams {
	o.SetScanType(scanType)
	return o
}

// SetScanType adds the scanType to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) SetScanType(scanType *string) {
	o.ScanType = scanType
}

// WithSort adds the sort to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) WithSort(sort *string) *GetCSPMCGPAccountParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) SetSort(sort *string) {
	o.Sort = sort
}

// WithStatus adds the status to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) WithStatus(status *string) *GetCSPMCGPAccountParams {
	o.SetStatus(status)
	return o
}

// SetStatus adds the status to the get c s p m c g p account params
func (o *GetCSPMCGPAccountParams) SetStatus(status *string) {
	o.Status = status
}

// WriteToRequest writes these params to a swagger request
func (o *GetCSPMCGPAccountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if o.Limit != nil {

		// query param limit
		var qrLimit int64

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Offset != nil {

		// query param offset
		var qrOffset int64

		if o.Offset != nil {
			qrOffset = *o.Offset
		}
		qOffset := swag.FormatInt64(qrOffset)
		if qOffset != "" {

			if err := r.SetQueryParam("offset", qOffset); err != nil {
				return err
			}
		}
	}

	if o.ParentType != nil {

		// query param parent_type
		var qrParentType string

		if o.ParentType != nil {
			qrParentType = *o.ParentType
		}
		qParentType := qrParentType
		if qParentType != "" {

			if err := r.SetQueryParam("parent_type", qParentType); err != nil {
				return err
			}
		}
	}

	if o.ScanType != nil {

		// query param scan-type
		var qrScanType string

		if o.ScanType != nil {
			qrScanType = *o.ScanType
		}
		qScanType := qrScanType
		if qScanType != "" {

			if err := r.SetQueryParam("scan-type", qScanType); err != nil {
				return err
			}
		}
	}

	if o.Sort != nil {

		// query param sort
		var qrSort string

		if o.Sort != nil {
			qrSort = *o.Sort
		}
		qSort := qrSort
		if qSort != "" {

			if err := r.SetQueryParam("sort", qSort); err != nil {
				return err
			}
		}
	}

	if o.Status != nil {

		// query param status
		var qrStatus string

		if o.Status != nil {
			qrStatus = *o.Status
		}
		qStatus := qrStatus
		if qStatus != "" {

			if err := r.SetQueryParam("status", qStatus); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamGetCSPMCGPAccount binds the parameter ids
func (o *GetCSPMCGPAccountParams) bindParamIds(formats strfmt.Registry) []string {
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
