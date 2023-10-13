// Code generated by go-swagger; DO NOT EDIT.

package d4c_registration

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

// NewGetD4CGcpAccountParams creates a new GetD4CGcpAccountParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetD4CGcpAccountParams() *GetD4CGcpAccountParams {
	return &GetD4CGcpAccountParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetD4CGcpAccountParamsWithTimeout creates a new GetD4CGcpAccountParams object
// with the ability to set a timeout on a request.
func NewGetD4CGcpAccountParamsWithTimeout(timeout time.Duration) *GetD4CGcpAccountParams {
	return &GetD4CGcpAccountParams{
		timeout: timeout,
	}
}

// NewGetD4CGcpAccountParamsWithContext creates a new GetD4CGcpAccountParams object
// with the ability to set a context for a request.
func NewGetD4CGcpAccountParamsWithContext(ctx context.Context) *GetD4CGcpAccountParams {
	return &GetD4CGcpAccountParams{
		Context: ctx,
	}
}

// NewGetD4CGcpAccountParamsWithHTTPClient creates a new GetD4CGcpAccountParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetD4CGcpAccountParamsWithHTTPClient(client *http.Client) *GetD4CGcpAccountParams {
	return &GetD4CGcpAccountParams{
		HTTPClient: client,
	}
}

/* GetD4CGcpAccountParams contains all the parameters to send to the API endpoint
   for the get d4 c gcp account operation.

   Typically these are written to a http.Request.
*/
type GetD4CGcpAccountParams struct {

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

// WithDefaults hydrates default values in the get d4 c gcp account params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetD4CGcpAccountParams) WithDefaults() *GetD4CGcpAccountParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get d4 c gcp account params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetD4CGcpAccountParams) SetDefaults() {
	var (
		limitDefault = int64(100)
	)

	val := GetD4CGcpAccountParams{
		Limit: &limitDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) WithTimeout(timeout time.Duration) *GetD4CGcpAccountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) WithContext(ctx context.Context) *GetD4CGcpAccountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) WithHTTPClient(client *http.Client) *GetD4CGcpAccountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) WithIds(ids []string) *GetD4CGcpAccountParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) SetIds(ids []string) {
	o.Ids = ids
}

// WithLimit adds the limit to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) WithLimit(limit *int64) *GetD4CGcpAccountParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) WithOffset(offset *int64) *GetD4CGcpAccountParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithParentType adds the parentType to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) WithParentType(parentType *string) *GetD4CGcpAccountParams {
	o.SetParentType(parentType)
	return o
}

// SetParentType adds the parentType to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) SetParentType(parentType *string) {
	o.ParentType = parentType
}

// WithScanType adds the scanType to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) WithScanType(scanType *string) *GetD4CGcpAccountParams {
	o.SetScanType(scanType)
	return o
}

// SetScanType adds the scanType to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) SetScanType(scanType *string) {
	o.ScanType = scanType
}

// WithSort adds the sort to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) WithSort(sort *string) *GetD4CGcpAccountParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) SetSort(sort *string) {
	o.Sort = sort
}

// WithStatus adds the status to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) WithStatus(status *string) *GetD4CGcpAccountParams {
	o.SetStatus(status)
	return o
}

// SetStatus adds the status to the get d4 c gcp account params
func (o *GetD4CGcpAccountParams) SetStatus(status *string) {
	o.Status = status
}

// WriteToRequest writes these params to a swagger request
func (o *GetD4CGcpAccountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

// bindParamGetD4CGcpAccount binds the parameter ids
func (o *GetD4CGcpAccountParams) bindParamIds(formats strfmt.Registry) []string {
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
