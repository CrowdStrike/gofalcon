// Code generated by go-swagger; DO NOT EDIT.

package sample_uploads

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

// NewArchiveUploadV1Params creates a new ArchiveUploadV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewArchiveUploadV1Params() *ArchiveUploadV1Params {
	return &ArchiveUploadV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewArchiveUploadV1ParamsWithTimeout creates a new ArchiveUploadV1Params object
// with the ability to set a timeout on a request.
func NewArchiveUploadV1ParamsWithTimeout(timeout time.Duration) *ArchiveUploadV1Params {
	return &ArchiveUploadV1Params{
		timeout: timeout,
	}
}

// NewArchiveUploadV1ParamsWithContext creates a new ArchiveUploadV1Params object
// with the ability to set a context for a request.
func NewArchiveUploadV1ParamsWithContext(ctx context.Context) *ArchiveUploadV1Params {
	return &ArchiveUploadV1Params{
		Context: ctx,
	}
}

// NewArchiveUploadV1ParamsWithHTTPClient creates a new ArchiveUploadV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewArchiveUploadV1ParamsWithHTTPClient(client *http.Client) *ArchiveUploadV1Params {
	return &ArchiveUploadV1Params{
		HTTPClient: client,
	}
}

/* ArchiveUploadV1Params contains all the parameters to send to the API endpoint
   for the archive upload v1 operation.

   Typically these are written to a http.Request.
*/
type ArchiveUploadV1Params struct {

	/* Body.

	     Content of the uploaded archive in binary format. For example, use `--data-binary @$FILE_PATH` when using cURL. Max file size: 100 MB.

	Accepted file formats:

	- Portable executables: `.zip`, `.7z`.
	*/
	Body []int64

	/* Comment.

	   A descriptive comment to identify the file for other users.
	*/
	Comment *string

	/* IsConfidential.

	     Defines visibility of this file, either via the API or the Falcon console.

	- `true`: File is only shown to users within your customer account
	- `false`: File can be seen by other CrowdStrike customers

	Default: `true`.

	     Default: true
	*/
	IsConfidential *bool

	/* Name.

	   Name of the archive.
	*/
	Name string

	/* Password.

	   Archive password.
	*/
	Password *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the archive upload v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArchiveUploadV1Params) WithDefaults() *ArchiveUploadV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the archive upload v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArchiveUploadV1Params) SetDefaults() {
	var (
		isConfidentialDefault = bool(true)
	)

	val := ArchiveUploadV1Params{
		IsConfidential: &isConfidentialDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the archive upload v1 params
func (o *ArchiveUploadV1Params) WithTimeout(timeout time.Duration) *ArchiveUploadV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the archive upload v1 params
func (o *ArchiveUploadV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the archive upload v1 params
func (o *ArchiveUploadV1Params) WithContext(ctx context.Context) *ArchiveUploadV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the archive upload v1 params
func (o *ArchiveUploadV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the archive upload v1 params
func (o *ArchiveUploadV1Params) WithHTTPClient(client *http.Client) *ArchiveUploadV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the archive upload v1 params
func (o *ArchiveUploadV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the archive upload v1 params
func (o *ArchiveUploadV1Params) WithBody(body []int64) *ArchiveUploadV1Params {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the archive upload v1 params
func (o *ArchiveUploadV1Params) SetBody(body []int64) {
	o.Body = body
}

// WithComment adds the comment to the archive upload v1 params
func (o *ArchiveUploadV1Params) WithComment(comment *string) *ArchiveUploadV1Params {
	o.SetComment(comment)
	return o
}

// SetComment adds the comment to the archive upload v1 params
func (o *ArchiveUploadV1Params) SetComment(comment *string) {
	o.Comment = comment
}

// WithIsConfidential adds the isConfidential to the archive upload v1 params
func (o *ArchiveUploadV1Params) WithIsConfidential(isConfidential *bool) *ArchiveUploadV1Params {
	o.SetIsConfidential(isConfidential)
	return o
}

// SetIsConfidential adds the isConfidential to the archive upload v1 params
func (o *ArchiveUploadV1Params) SetIsConfidential(isConfidential *bool) {
	o.IsConfidential = isConfidential
}

// WithName adds the name to the archive upload v1 params
func (o *ArchiveUploadV1Params) WithName(name string) *ArchiveUploadV1Params {
	o.SetName(name)
	return o
}

// SetName adds the name to the archive upload v1 params
func (o *ArchiveUploadV1Params) SetName(name string) {
	o.Name = name
}

// WithPassword adds the password to the archive upload v1 params
func (o *ArchiveUploadV1Params) WithPassword(password *string) *ArchiveUploadV1Params {
	o.SetPassword(password)
	return o
}

// SetPassword adds the password to the archive upload v1 params
func (o *ArchiveUploadV1Params) SetPassword(password *string) {
	o.Password = password
}

// WriteToRequest writes these params to a swagger request
func (o *ArchiveUploadV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if o.Comment != nil {

		// query param comment
		var qrComment string

		if o.Comment != nil {
			qrComment = *o.Comment
		}
		qComment := qrComment
		if qComment != "" {

			if err := r.SetQueryParam("comment", qComment); err != nil {
				return err
			}
		}
	}

	if o.IsConfidential != nil {

		// query param is_confidential
		var qrIsConfidential bool

		if o.IsConfidential != nil {
			qrIsConfidential = *o.IsConfidential
		}
		qIsConfidential := swag.FormatBool(qrIsConfidential)
		if qIsConfidential != "" {

			if err := r.SetQueryParam("is_confidential", qIsConfidential); err != nil {
				return err
			}
		}
	}

	// query param name
	qrName := o.Name
	qName := qrName
	if qName != "" {

		if err := r.SetQueryParam("name", qName); err != nil {
			return err
		}
	}

	if o.Password != nil {

		// query param password
		var qrPassword string

		if o.Password != nil {
			qrPassword = *o.Password
		}
		qPassword := qrPassword
		if qPassword != "" {

			if err := r.SetQueryParam("password", qPassword); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
