// Code generated by go-swagger; DO NOT EDIT.

package discover

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

// NewCombinedHostsParams creates a new CombinedHostsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCombinedHostsParams() *CombinedHostsParams {
	return &CombinedHostsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCombinedHostsParamsWithTimeout creates a new CombinedHostsParams object
// with the ability to set a timeout on a request.
func NewCombinedHostsParamsWithTimeout(timeout time.Duration) *CombinedHostsParams {
	return &CombinedHostsParams{
		timeout: timeout,
	}
}

// NewCombinedHostsParamsWithContext creates a new CombinedHostsParams object
// with the ability to set a context for a request.
func NewCombinedHostsParamsWithContext(ctx context.Context) *CombinedHostsParams {
	return &CombinedHostsParams{
		Context: ctx,
	}
}

// NewCombinedHostsParamsWithHTTPClient creates a new CombinedHostsParams object
// with the ability to set a custom HTTPClient for a request.
func NewCombinedHostsParamsWithHTTPClient(client *http.Client) *CombinedHostsParams {
	return &CombinedHostsParams{
		HTTPClient: client,
	}
}

/*
CombinedHostsParams contains all the parameters to send to the API endpoint

	for the combined hosts operation.

	Typically these are written to a http.Request.
*/
type CombinedHostsParams struct {

	/* After.

	   A pagination token used with the `limit` parameter to manage pagination of results. On your first request, don't provide an `after` token. On subsequent requests, provide the `after` token from the previous response to continue from that place in the results.
	*/
	After *string

	/* Facet.

	     Select various details blocks to be returned for each host entity. Supported values:

	<ul><li>system_insights</li><li>third_party</li><li>risk_factors</li></ul>
	*/
	Facet []string

	/* Filter.

	     Filter assets using an FQL query. Common filter options include:<ul><li>entity_type:'managed'</li><li>product_type_desc:'Workstation'</li><li>platform_name:'Windows'</li><li>last_seen_timestamp:>'now-7d'</li></ul>
				Available filter fields that support exact match: id, aid, entity_type, country, city, platform_name, os_version, kernel_version, product_type_desc, tags, groups, agent_version, system_product_name, system_manufacturer, system_serial_number, bios_manufacturer, bios_version, ou, machine_domain, site_name, external_ip, hostname, local_ips_count, network_interfaces.local_ip, network_interfaces.mac_address, network_interfaces.interface_alias, network_interfaces.interface_description, network_interfaces.network_prefix, last_discoverer_aid, discoverer_count, discoverer_aids, discoverer_tags, discoverer_platform_names, discoverer_product_type_descs, confidence, internet_exposure,  os_is_eol, data_providers, data_providers_count, mac_addresses, local_ip_addresses, reduced_functionality_mode, number_of_disk_drives, processor_package_count, physical_core_count, logical_core_count, total_disk_space, disk_sizes.disk_name, disk_sizes.disk_space, cpu_processor_name, total_memory, encryption_status, encrypted_drives, encrypted_drives_count, unencrypted_drives, unencrypted_drives_count, os_security.secure_boot_requested_status, os_security.device_guard_status, os_security.device_guard_status, os_security.device_guard_status, os_security.system_guard_status, os_security.credential_guard_status, os_security.iommu_protection_status, os_security.secure_boot_enabled_status, os_security.uefi_memory_protection_status, os_security.virtualization_based_security_status, os_security.kernel_dma_protection_status, total_bios_files, bios_hashes_data.sha256_hash, bios_hashes_data.measurement_type, bios_id, average_processor_usage, average_memory_usage, average_memory_usage_pct, max_processor_usage, max_memory_usage, max_memory_usage_pct, used_disk_space, used_disk_space_pct, available_disk_space, available_disk_space_pct, mount_storage_info.mount_path, mount_storage_info.used_space, mount_storage_info.available_space, form_factor, servicenow_id, owned_by, managed_by, assigned_to, department, fqdn, used_for, object_guid, object_sid, ad_user_account_control, account_enabled, creation_timestamp, email, os_service_pack, location, state, cpu_manufacturer, discovering_by
				Available filter fields that supports wildcard (*): id, aid, entity_type, country, city, platform_name, os_version, kernel_version, product_type_desc, tags, groups, agent_version, system_product_name, system_manufacturer, system_serial_number, bios_manufacturer, bios_version, ou, machine_domain, site_name, external_ip, hostname, network_interfaces.local_ip, network_interfaces.mac_address, network_interfaces.interface_alias, network_interfaces.interface_description, network_interfaces.network_prefix, last_discoverer_aid, discoverer_aids, discoverer_tags, discoverer_platform_names, discoverer_product_type_descs, confidence, internet_exposure,  os_is_eol, data_providers, mac_addresses, local_ip_addresses, reduced_functionality_mode, disk_sizes.disk_name, cpu_processor_name, encryption_status, encrypted_drives, unencrypted_drives, os_security.secure_boot_requested_status, os_security.device_guard_status, os_security.device_guard_status, os_security.device_guard_status, os_security.system_guard_status, os_security.credential_guard_status, os_security.iommu_protection_status, os_security.secure_boot_enabled_status, os_security.uefi_memory_protection_status, os_security.virtualization_based_security_status, os_security.kernel_dma_protection_status, bios_hashes_data.sha256_hash, bios_hashes_data.measurement_type, bios_id, mount_storage_info.mount_path, form_factor, servicenow_id, owned_by, managed_by, assigned_to, department, fqdn, used_for, object_guid, object_sid, account_enabled, email, os_service_pack, location, state, cpu_manufacturer, discovering_by
				Available filter fields that supports range comparisons (>, <, >=, <=): first_seen_timestamp, last_seen_timestamp, local_ips_count, discoverer_count, confidence, number_of_disk_drives, processor_package_count, physical_core_count, data_providers_count, logical_core_count, total_disk_space, disk_sizes.disk_space, total_memory, encrypted_drives_count, unencrypted_drives_count, total_bios_files, average_processor_usage, average_memory_usage, average_memory_usage_pct, max_processor_usage, max_memory_usage, max_memory_usage_pct, used_disk_space, used_disk_space_pct, available_disk_space, available_disk_space_pct, mount_storage_info.used_space, mount_storage_info.available_space, ad_user_account_control, creation_timestamp
				All filter fields and operations supports negation (!).
	*/
	Filter string

	/* Limit.

	   The number of asset IDs to return in this response (min: 1, max: 1000, default: 100). Use with the `after` parameter to manage pagination of results.
	*/
	Limit *int64

	/* Sort.

	     Sort assets by their properties. A single sort field is allowed. Common sort options include:

	<ul><li>hostname|asc</li><li>product_type_desc|desc</li></ul>
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the combined hosts params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CombinedHostsParams) WithDefaults() *CombinedHostsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the combined hosts params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CombinedHostsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the combined hosts params
func (o *CombinedHostsParams) WithTimeout(timeout time.Duration) *CombinedHostsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the combined hosts params
func (o *CombinedHostsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the combined hosts params
func (o *CombinedHostsParams) WithContext(ctx context.Context) *CombinedHostsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the combined hosts params
func (o *CombinedHostsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the combined hosts params
func (o *CombinedHostsParams) WithHTTPClient(client *http.Client) *CombinedHostsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the combined hosts params
func (o *CombinedHostsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAfter adds the after to the combined hosts params
func (o *CombinedHostsParams) WithAfter(after *string) *CombinedHostsParams {
	o.SetAfter(after)
	return o
}

// SetAfter adds the after to the combined hosts params
func (o *CombinedHostsParams) SetAfter(after *string) {
	o.After = after
}

// WithFacet adds the facet to the combined hosts params
func (o *CombinedHostsParams) WithFacet(facet []string) *CombinedHostsParams {
	o.SetFacet(facet)
	return o
}

// SetFacet adds the facet to the combined hosts params
func (o *CombinedHostsParams) SetFacet(facet []string) {
	o.Facet = facet
}

// WithFilter adds the filter to the combined hosts params
func (o *CombinedHostsParams) WithFilter(filter string) *CombinedHostsParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the combined hosts params
func (o *CombinedHostsParams) SetFilter(filter string) {
	o.Filter = filter
}

// WithLimit adds the limit to the combined hosts params
func (o *CombinedHostsParams) WithLimit(limit *int64) *CombinedHostsParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the combined hosts params
func (o *CombinedHostsParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithSort adds the sort to the combined hosts params
func (o *CombinedHostsParams) WithSort(sort *string) *CombinedHostsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the combined hosts params
func (o *CombinedHostsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *CombinedHostsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.After != nil {

		// query param after
		var qrAfter string

		if o.After != nil {
			qrAfter = *o.After
		}
		qAfter := qrAfter
		if qAfter != "" {

			if err := r.SetQueryParam("after", qAfter); err != nil {
				return err
			}
		}
	}

	if o.Facet != nil {

		// binding items for facet
		joinedFacet := o.bindParamFacet(reg)

		// query array param facet
		if err := r.SetQueryParam("facet", joinedFacet...); err != nil {
			return err
		}
	}

	// query param filter
	qrFilter := o.Filter
	qFilter := qrFilter
	if qFilter != "" {

		if err := r.SetQueryParam("filter", qFilter); err != nil {
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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamCombinedHosts binds the parameter facet
func (o *CombinedHostsParams) bindParamFacet(formats strfmt.Registry) []string {
	facetIR := o.Facet

	var facetIC []string
	for _, facetIIR := range facetIR { // explode []string

		facetIIV := facetIIR // string as string
		facetIC = append(facetIC, facetIIV)
	}

	// items.CollectionFormat: "multi"
	facetIS := swag.JoinByFormat(facetIC, "multi")

	return facetIS
}
