// Code generated by go-swagger; DO NOT EDIT.

package custom_storage

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

// NewDeleteObjectParams creates a new DeleteObjectParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteObjectParams() *DeleteObjectParams {
	return &DeleteObjectParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteObjectParamsWithTimeout creates a new DeleteObjectParams object
// with the ability to set a timeout on a request.
func NewDeleteObjectParamsWithTimeout(timeout time.Duration) *DeleteObjectParams {
	return &DeleteObjectParams{
		timeout: timeout,
	}
}

// NewDeleteObjectParamsWithContext creates a new DeleteObjectParams object
// with the ability to set a context for a request.
func NewDeleteObjectParamsWithContext(ctx context.Context) *DeleteObjectParams {
	return &DeleteObjectParams{
		Context: ctx,
	}
}

// NewDeleteObjectParamsWithHTTPClient creates a new DeleteObjectParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteObjectParamsWithHTTPClient(client *http.Client) *DeleteObjectParams {
	return &DeleteObjectParams{
		HTTPClient: client,
	}
}

/*
DeleteObjectParams contains all the parameters to send to the API endpoint

	for the delete object operation.

	Typically these are written to a http.Request.
*/
type DeleteObjectParams struct {

	/* CollectionName.

	   The name of the collection
	*/
	CollectionName string

	/* DryRun.

	   If false, run the operation as normal.  If true, validate that the request *would* succeed, but don't execute it.
	*/
	DryRun bool

	/* ObjectKey.

	   The object key
	*/
	ObjectKey string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete object params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteObjectParams) WithDefaults() *DeleteObjectParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete object params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteObjectParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete object params
func (o *DeleteObjectParams) WithTimeout(timeout time.Duration) *DeleteObjectParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete object params
func (o *DeleteObjectParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete object params
func (o *DeleteObjectParams) WithContext(ctx context.Context) *DeleteObjectParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete object params
func (o *DeleteObjectParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete object params
func (o *DeleteObjectParams) WithHTTPClient(client *http.Client) *DeleteObjectParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete object params
func (o *DeleteObjectParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCollectionName adds the collectionName to the delete object params
func (o *DeleteObjectParams) WithCollectionName(collectionName string) *DeleteObjectParams {
	o.SetCollectionName(collectionName)
	return o
}

// SetCollectionName adds the collectionName to the delete object params
func (o *DeleteObjectParams) SetCollectionName(collectionName string) {
	o.CollectionName = collectionName
}

// WithDryRun adds the dryRun to the delete object params
func (o *DeleteObjectParams) WithDryRun(dryRun bool) *DeleteObjectParams {
	o.SetDryRun(dryRun)
	return o
}

// SetDryRun adds the dryRun to the delete object params
func (o *DeleteObjectParams) SetDryRun(dryRun bool) {
	o.DryRun = dryRun
}

// WithObjectKey adds the objectKey to the delete object params
func (o *DeleteObjectParams) WithObjectKey(objectKey string) *DeleteObjectParams {
	o.SetObjectKey(objectKey)
	return o
}

// SetObjectKey adds the objectKey to the delete object params
func (o *DeleteObjectParams) SetObjectKey(objectKey string) {
	o.ObjectKey = objectKey
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteObjectParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param collection_name
	if err := r.SetPathParam("collection_name", o.CollectionName); err != nil {
		return err
	}

	// query param dry_run
	qrDryRun := o.DryRun
	qDryRun := swag.FormatBool(qrDryRun)

	if err := r.SetQueryParam("dry_run", qDryRun); err != nil {
		return err
	}

	// path param object_key
	if err := r.SetPathParam("object_key", o.ObjectKey); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
