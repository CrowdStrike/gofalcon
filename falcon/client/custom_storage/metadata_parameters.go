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
)

// NewMetadataParams creates a new MetadataParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewMetadataParams() *MetadataParams {
	return &MetadataParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewMetadataParamsWithTimeout creates a new MetadataParams object
// with the ability to set a timeout on a request.
func NewMetadataParamsWithTimeout(timeout time.Duration) *MetadataParams {
	return &MetadataParams{
		timeout: timeout,
	}
}

// NewMetadataParamsWithContext creates a new MetadataParams object
// with the ability to set a context for a request.
func NewMetadataParamsWithContext(ctx context.Context) *MetadataParams {
	return &MetadataParams{
		Context: ctx,
	}
}

// NewMetadataParamsWithHTTPClient creates a new MetadataParams object
// with the ability to set a custom HTTPClient for a request.
func NewMetadataParamsWithHTTPClient(client *http.Client) *MetadataParams {
	return &MetadataParams{
		HTTPClient: client,
	}
}

/*
MetadataParams contains all the parameters to send to the API endpoint

	for the metadata operation.

	Typically these are written to a http.Request.
*/
type MetadataParams struct {

	/* CollectionName.

	   The name of the collection
	*/
	CollectionName string

	/* ObjectKey.

	   The object key
	*/
	ObjectKey string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the metadata params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *MetadataParams) WithDefaults() *MetadataParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the metadata params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *MetadataParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the metadata params
func (o *MetadataParams) WithTimeout(timeout time.Duration) *MetadataParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the metadata params
func (o *MetadataParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the metadata params
func (o *MetadataParams) WithContext(ctx context.Context) *MetadataParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the metadata params
func (o *MetadataParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the metadata params
func (o *MetadataParams) WithHTTPClient(client *http.Client) *MetadataParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the metadata params
func (o *MetadataParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCollectionName adds the collectionName to the metadata params
func (o *MetadataParams) WithCollectionName(collectionName string) *MetadataParams {
	o.SetCollectionName(collectionName)
	return o
}

// SetCollectionName adds the collectionName to the metadata params
func (o *MetadataParams) SetCollectionName(collectionName string) {
	o.CollectionName = collectionName
}

// WithObjectKey adds the objectKey to the metadata params
func (o *MetadataParams) WithObjectKey(objectKey string) *MetadataParams {
	o.SetObjectKey(objectKey)
	return o
}

// SetObjectKey adds the objectKey to the metadata params
func (o *MetadataParams) SetObjectKey(objectKey string) {
	o.ObjectKey = objectKey
}

// WriteToRequest writes these params to a swagger request
func (o *MetadataParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param collection_name
	if err := r.SetPathParam("collection_name", o.CollectionName); err != nil {
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
