// Code generated by go-swagger; DO NOT EDIT.

package kubernetes_protection

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

// NewGetAzureInstallScriptParams creates a new GetAzureInstallScriptParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAzureInstallScriptParams() *GetAzureInstallScriptParams {
	return &GetAzureInstallScriptParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAzureInstallScriptParamsWithTimeout creates a new GetAzureInstallScriptParams object
// with the ability to set a timeout on a request.
func NewGetAzureInstallScriptParamsWithTimeout(timeout time.Duration) *GetAzureInstallScriptParams {
	return &GetAzureInstallScriptParams{
		timeout: timeout,
	}
}

// NewGetAzureInstallScriptParamsWithContext creates a new GetAzureInstallScriptParams object
// with the ability to set a context for a request.
func NewGetAzureInstallScriptParamsWithContext(ctx context.Context) *GetAzureInstallScriptParams {
	return &GetAzureInstallScriptParams{
		Context: ctx,
	}
}

// NewGetAzureInstallScriptParamsWithHTTPClient creates a new GetAzureInstallScriptParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAzureInstallScriptParamsWithHTTPClient(client *http.Client) *GetAzureInstallScriptParams {
	return &GetAzureInstallScriptParams{
		HTTPClient: client,
	}
}

/* GetAzureInstallScriptParams contains all the parameters to send to the API endpoint
   for the get azure install script operation.

   Typically these are written to a http.Request.
*/
type GetAzureInstallScriptParams struct {

	/* ID.

	   Azure Tenant ID
	*/
	ID *string

	/* SubscriptionID.

	   Azure Subscription IDs
	*/
	SubscriptionID []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get azure install script params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAzureInstallScriptParams) WithDefaults() *GetAzureInstallScriptParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get azure install script params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAzureInstallScriptParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get azure install script params
func (o *GetAzureInstallScriptParams) WithTimeout(timeout time.Duration) *GetAzureInstallScriptParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get azure install script params
func (o *GetAzureInstallScriptParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get azure install script params
func (o *GetAzureInstallScriptParams) WithContext(ctx context.Context) *GetAzureInstallScriptParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get azure install script params
func (o *GetAzureInstallScriptParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get azure install script params
func (o *GetAzureInstallScriptParams) WithHTTPClient(client *http.Client) *GetAzureInstallScriptParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get azure install script params
func (o *GetAzureInstallScriptParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the get azure install script params
func (o *GetAzureInstallScriptParams) WithID(id *string) *GetAzureInstallScriptParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get azure install script params
func (o *GetAzureInstallScriptParams) SetID(id *string) {
	o.ID = id
}

// WithSubscriptionID adds the subscriptionID to the get azure install script params
func (o *GetAzureInstallScriptParams) WithSubscriptionID(subscriptionID []string) *GetAzureInstallScriptParams {
	o.SetSubscriptionID(subscriptionID)
	return o
}

// SetSubscriptionID adds the subscriptionId to the get azure install script params
func (o *GetAzureInstallScriptParams) SetSubscriptionID(subscriptionID []string) {
	o.SubscriptionID = subscriptionID
}

// WriteToRequest writes these params to a swagger request
func (o *GetAzureInstallScriptParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.ID != nil {

		// query param id
		var qrID string

		if o.ID != nil {
			qrID = *o.ID
		}
		qID := qrID
		if qID != "" {

			if err := r.SetQueryParam("id", qID); err != nil {
				return err
			}
		}
	}

	if o.SubscriptionID != nil {

		// binding items for subscription_id
		joinedSubscriptionID := o.bindParamSubscriptionID(reg)

		// query array param subscription_id
		if err := r.SetQueryParam("subscription_id", joinedSubscriptionID...); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamGetAzureInstallScript binds the parameter subscription_id
func (o *GetAzureInstallScriptParams) bindParamSubscriptionID(formats strfmt.Registry) []string {
	subscriptionIDIR := o.SubscriptionID

	var subscriptionIDIC []string
	for _, subscriptionIDIIR := range subscriptionIDIR { // explode []string

		subscriptionIDIIV := subscriptionIDIIR // string as string
		subscriptionIDIC = append(subscriptionIDIC, subscriptionIDIIV)
	}

	// items.CollectionFormat: "csv"
	subscriptionIDIS := swag.JoinByFormat(subscriptionIDIC, "csv")

	return subscriptionIDIS
}
