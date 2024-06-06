// Code generated by go-swagger; DO NOT EDIT.

package user_management

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

	"github.com/aslape/gofalcon/falcon/models"
)

// NewGrantUserRoleIdsParams creates a new GrantUserRoleIdsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGrantUserRoleIdsParams() *GrantUserRoleIdsParams {
	return &GrantUserRoleIdsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGrantUserRoleIdsParamsWithTimeout creates a new GrantUserRoleIdsParams object
// with the ability to set a timeout on a request.
func NewGrantUserRoleIdsParamsWithTimeout(timeout time.Duration) *GrantUserRoleIdsParams {
	return &GrantUserRoleIdsParams{
		timeout: timeout,
	}
}

// NewGrantUserRoleIdsParamsWithContext creates a new GrantUserRoleIdsParams object
// with the ability to set a context for a request.
func NewGrantUserRoleIdsParamsWithContext(ctx context.Context) *GrantUserRoleIdsParams {
	return &GrantUserRoleIdsParams{
		Context: ctx,
	}
}

// NewGrantUserRoleIdsParamsWithHTTPClient creates a new GrantUserRoleIdsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGrantUserRoleIdsParamsWithHTTPClient(client *http.Client) *GrantUserRoleIdsParams {
	return &GrantUserRoleIdsParams{
		HTTPClient: client,
	}
}

/*
GrantUserRoleIdsParams contains all the parameters to send to the API endpoint

	for the grant user role ids operation.

	Typically these are written to a http.Request.
*/
type GrantUserRoleIdsParams struct {

	/* Body.

	   Role ID(s) of the role you want to assign
	*/
	Body *models.DomainRoleIDs

	/* UserUUID.

	   ID of a user. Find a user's ID from `/users/entities/user/v1`.
	*/
	UserUUID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the grant user role ids params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GrantUserRoleIdsParams) WithDefaults() *GrantUserRoleIdsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the grant user role ids params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GrantUserRoleIdsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the grant user role ids params
func (o *GrantUserRoleIdsParams) WithTimeout(timeout time.Duration) *GrantUserRoleIdsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the grant user role ids params
func (o *GrantUserRoleIdsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the grant user role ids params
func (o *GrantUserRoleIdsParams) WithContext(ctx context.Context) *GrantUserRoleIdsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the grant user role ids params
func (o *GrantUserRoleIdsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the grant user role ids params
func (o *GrantUserRoleIdsParams) WithHTTPClient(client *http.Client) *GrantUserRoleIdsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the grant user role ids params
func (o *GrantUserRoleIdsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the grant user role ids params
func (o *GrantUserRoleIdsParams) WithBody(body *models.DomainRoleIDs) *GrantUserRoleIdsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the grant user role ids params
func (o *GrantUserRoleIdsParams) SetBody(body *models.DomainRoleIDs) {
	o.Body = body
}

// WithUserUUID adds the userUUID to the grant user role ids params
func (o *GrantUserRoleIdsParams) WithUserUUID(userUUID string) *GrantUserRoleIdsParams {
	o.SetUserUUID(userUUID)
	return o
}

// SetUserUUID adds the userUuid to the grant user role ids params
func (o *GrantUserRoleIdsParams) SetUserUUID(userUUID string) {
	o.UserUUID = userUUID
}

// WriteToRequest writes these params to a swagger request
func (o *GrantUserRoleIdsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	// query param user_uuid
	qrUserUUID := o.UserUUID
	qUserUUID := qrUserUUID
	if qUserUUID != "" {

		if err := r.SetQueryParam("user_uuid", qUserUUID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
