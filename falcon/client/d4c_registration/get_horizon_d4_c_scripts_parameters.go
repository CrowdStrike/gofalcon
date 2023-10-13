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
)

// NewGetHorizonD4CScriptsParams creates a new GetHorizonD4CScriptsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetHorizonD4CScriptsParams() *GetHorizonD4CScriptsParams {
	return &GetHorizonD4CScriptsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetHorizonD4CScriptsParamsWithTimeout creates a new GetHorizonD4CScriptsParams object
// with the ability to set a timeout on a request.
func NewGetHorizonD4CScriptsParamsWithTimeout(timeout time.Duration) *GetHorizonD4CScriptsParams {
	return &GetHorizonD4CScriptsParams{
		timeout: timeout,
	}
}

// NewGetHorizonD4CScriptsParamsWithContext creates a new GetHorizonD4CScriptsParams object
// with the ability to set a context for a request.
func NewGetHorizonD4CScriptsParamsWithContext(ctx context.Context) *GetHorizonD4CScriptsParams {
	return &GetHorizonD4CScriptsParams{
		Context: ctx,
	}
}

// NewGetHorizonD4CScriptsParamsWithHTTPClient creates a new GetHorizonD4CScriptsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetHorizonD4CScriptsParamsWithHTTPClient(client *http.Client) *GetHorizonD4CScriptsParams {
	return &GetHorizonD4CScriptsParams{
		HTTPClient: client,
	}
}

/* GetHorizonD4CScriptsParams contains all the parameters to send to the API endpoint
   for the get horizon d4 c scripts operation.

   Typically these are written to a http.Request.
*/
type GetHorizonD4CScriptsParams struct {

	/* AccountType.

	   Account type (e.g.: commercial,gov) Only applicable when registering AWS commercial account in a Gov environment
	*/
	AccountType *string

	// Delete.
	Delete *string

	/* OrganizationID.

	   AWS organization ID
	*/
	OrganizationID *string

	/* SingleAccount.

	   Get static script for single account
	*/
	SingleAccount *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get horizon d4 c scripts params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetHorizonD4CScriptsParams) WithDefaults() *GetHorizonD4CScriptsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get horizon d4 c scripts params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetHorizonD4CScriptsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) WithTimeout(timeout time.Duration) *GetHorizonD4CScriptsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) WithContext(ctx context.Context) *GetHorizonD4CScriptsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) WithHTTPClient(client *http.Client) *GetHorizonD4CScriptsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAccountType adds the accountType to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) WithAccountType(accountType *string) *GetHorizonD4CScriptsParams {
	o.SetAccountType(accountType)
	return o
}

// SetAccountType adds the accountType to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) SetAccountType(accountType *string) {
	o.AccountType = accountType
}

// WithDelete adds the delete to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) WithDelete(delete *string) *GetHorizonD4CScriptsParams {
	o.SetDelete(delete)
	return o
}

// SetDelete adds the delete to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) SetDelete(delete *string) {
	o.Delete = delete
}

// WithOrganizationID adds the organizationID to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) WithOrganizationID(organizationID *string) *GetHorizonD4CScriptsParams {
	o.SetOrganizationID(organizationID)
	return o
}

// SetOrganizationID adds the organizationId to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) SetOrganizationID(organizationID *string) {
	o.OrganizationID = organizationID
}

// WithSingleAccount adds the singleAccount to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) WithSingleAccount(singleAccount *string) *GetHorizonD4CScriptsParams {
	o.SetSingleAccount(singleAccount)
	return o
}

// SetSingleAccount adds the singleAccount to the get horizon d4 c scripts params
func (o *GetHorizonD4CScriptsParams) SetSingleAccount(singleAccount *string) {
	o.SingleAccount = singleAccount
}

// WriteToRequest writes these params to a swagger request
func (o *GetHorizonD4CScriptsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AccountType != nil {

		// query param account_type
		var qrAccountType string

		if o.AccountType != nil {
			qrAccountType = *o.AccountType
		}
		qAccountType := qrAccountType
		if qAccountType != "" {

			if err := r.SetQueryParam("account_type", qAccountType); err != nil {
				return err
			}
		}
	}

	if o.Delete != nil {

		// query param delete
		var qrDelete string

		if o.Delete != nil {
			qrDelete = *o.Delete
		}
		qDelete := qrDelete
		if qDelete != "" {

			if err := r.SetQueryParam("delete", qDelete); err != nil {
				return err
			}
		}
	}

	if o.OrganizationID != nil {

		// query param organization-id
		var qrOrganizationID string

		if o.OrganizationID != nil {
			qrOrganizationID = *o.OrganizationID
		}
		qOrganizationID := qrOrganizationID
		if qOrganizationID != "" {

			if err := r.SetQueryParam("organization-id", qOrganizationID); err != nil {
				return err
			}
		}
	}

	if o.SingleAccount != nil {

		// query param single_account
		var qrSingleAccount string

		if o.SingleAccount != nil {
			qrSingleAccount = *o.SingleAccount
		}
		qSingleAccount := qrSingleAccount
		if qSingleAccount != "" {

			if err := r.SetQueryParam("single_account", qSingleAccount); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
