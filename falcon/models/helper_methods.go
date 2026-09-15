package models

import (
	"fmt"
	"reflect"
	"strings"
)

var stringerType = reflect.TypeFor[fmt.Stringer]()

// renderErrorFields renders the exported, non-empty fields of an API error model
// in a brace-wrapped "{Field:value ...}" form, dereferencing pointers so that a
// *string shows the string rather than its address.
//
// The swagger generated Error() methods under falcon/client format their payload
// with %+v. For a field such as Errors []*DomainReconAPIError that prints raw
// pointer addresses unless the element type implements String(), so every model
// reachable that way needs one. They all delegate here, which keeps the
// rendering uniform and means a field added by a future regeneration is picked
// up automatically instead of being silently dropped.
func renderErrorFields(model any) string {
	value := reflect.ValueOf(model)
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return "<nil>"
		}
		value = value.Elem()
	}

	structType := value.Type()
	fields := make([]string, 0, structType.NumField())
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if !field.IsExported() {
			continue
		}

		fieldValue := value.Field(i)
		switch fieldValue.Kind() {
		case reflect.Pointer:
			if fieldValue.IsNil() {
				continue
			}
			// Keep a pointer that carries its own String(), so that fmt calls it.
			// Dereferencing would hand fmt a struct value, whose method set
			// excludes pointer-receiver methods, and its fields would render as
			// addresses again.
			if !fieldValue.Type().Implements(stringerType) {
				// A pointer to a zero value is still reported: the API uses these
				// pointers to distinguish an unset field from a zero one.
				fieldValue = fieldValue.Elem()
			}
		case reflect.Interface:
			if fieldValue.IsNil() {
				continue
			}
		case reflect.Slice, reflect.Map:
			if fieldValue.Len() == 0 {
				continue
			}
		default:
			if fieldValue.IsZero() {
				continue
			}
		}

		fields = append(fields, fmt.Sprintf("%s:%+v", field.Name, fieldValue.Interface()))
	}

	return "{" + strings.Join(fields, " ") + "}"
}

func (m *AccessscopemanagerV1Error) String() string                  { return renderErrorFields(m) }
func (m *AccessscopemanagerV1Meta) String() string                   { return renderErrorFields(m) }
func (m *AccessscopemanagerV1Pagination) String() string             { return renderErrorFields(m) }
func (m *APICursorMetaInfo) String() string                          { return renderErrorFields(m) }
func (m *APIDetectsQueryMeta) String() string                        { return renderErrorFields(m) }
func (m *APIDetectsQueryPaging) String() string                      { return renderErrorFields(m) }
func (m *APIIndicatorsQueryMeta) String() string                     { return renderErrorFields(m) }
func (m *APIIndicatorsQueryPaging) String() string                   { return renderErrorFields(m) }
func (m *APIMetaInfo) String() string                                { return renderErrorFields(m) }
func (m *APIModelEntityMetaInfo) String() string                     { return renderErrorFields(m) }
func (m *APIPaging) String() string                                  { return renderErrorFields(m) }
func (m *APIPatchAgentMetaInfo) String() string                      { return renderErrorFields(m) }
func (m *APISdmError) String() string                                { return renderErrorFields(m) }
func (m *AssetgroupmanagerV1Error) String() string                   { return renderErrorFields(m) }
func (m *AssetgroupmanagerV1Meta) String() string                    { return renderErrorFields(m) }
func (m *AssetgroupmanagerV1Pagination) String() string              { return renderErrorFields(m) }
func (m *ChangesHighVolumeQueryMeta) String() string                 { return renderErrorFields(m) }
func (m *ChangesHighVolumeQueryPaging) String() string               { return renderErrorFields(m) }
func (m *DetectsapiPostCombinedAlertsV1Meta) String() string         { return renderErrorFields(m) }
func (m *DetectsapiPostCombinedAlertsV1Paging) String() string       { return renderErrorFields(m) }
func (m *DeviceapiDevicePaging) String() string                      { return renderErrorFields(m) }
func (m *DeviceapiDevicePagingV2) String() string                    { return renderErrorFields(m) }
func (m *DeviceapiMetaInfo) String() string                          { return renderErrorFields(m) }
func (m *DeviceapiRequestMeta) String() string                       { return renderErrorFields(m) }
func (m *DevicecontrolapiRespMSAErrorV1) String() string             { return renderErrorFields(m) }
func (m *DevicecontrolapiRespMSAMetaV1) String() string              { return renderErrorFields(m) }
func (m *DevicecontrolapiRespPagingDetailsV1) String() string        { return renderErrorFields(m) }
func (m *DomainAPIQueryMetaV1) String() string                       { return renderErrorFields(m) }
func (m *DomainAPIQueryPagingV1) String() string                     { return renderErrorFields(m) }
func (m *DomainDiscoverAPIMetaInfo) String() string                  { return renderErrorFields(m) }
func (m *DomainDiscoverAPIPaging) String() string                    { return renderErrorFields(m) }
func (m *DomainFemEcosystemSubsidiariesMeta) String() string         { return renderErrorFields(m) }
func (m *DomainMetaInfo) String() string                             { return renderErrorFields(m) }
func (m *DomainMsaMetaInfoWithSearchAfter) String() string           { return renderErrorFields(m) }
func (m *DomainPagingWithSearchAfter) String() string                { return renderErrorFields(m) }
func (m *DomainQuota) String() string                                { return renderErrorFields(m) }
func (m *DomainReconAPIError) String() string                        { return renderErrorFields(m) }
func (m *DomainReconAPIErrorDetail) String() string                  { return renderErrorFields(m) }
func (m *DomainRuleMetaInfo) String() string                         { return renderErrorFields(m) }
func (m *DomainRuleQuota) String() string                            { return renderErrorFields(m) }
func (m *DomainSearchAfterMeta) String() string                      { return renderErrorFields(m) }
func (m *DomainSearchAfterPaging) String() string                    { return renderErrorFields(m) }
func (m *DomainSPAPIQueryMeta) String() string                       { return renderErrorFields(m) }
func (m *DomainSPAPIQueryPaging) String() string                     { return renderErrorFields(m) }
func (m *DomainVulnMetadataAPIMeta) String() string                  { return renderErrorFields(m) }
func (m *ErrorAppInventory) String() string                          { return renderErrorFields(m) }
func (m *ErrorAppInventoryUsers) String() string                     { return renderErrorFields(m) }
func (m *ErrorDismissAffected) String() string                       { return renderErrorFields(m) }
func (m *ErrorDismissSecurityCheck) String() string                  { return renderErrorFields(m) }
func (m *ErrorGetActivityMonitor) String() string                    { return renderErrorFields(m) }
func (m *ErrorGetAffected) String() string                           { return renderErrorFields(m) }
func (m *ErrorGetAlertsResponse) String() string                     { return renderErrorFields(m) }
func (m *ErrorGetAssetInventory) String() string                     { return renderErrorFields(m) }
func (m *ErrorGetDeviceInventory) String() string                    { return renderErrorFields(m) }
func (m *ErrorGetEndTransaction) String() string                     { return renderErrorFields(m) }
func (m *ErrorGetIntegrations) String() string                       { return renderErrorFields(m) }
func (m *ErrorGetMetrics) String() string                            { return renderErrorFields(m) }
func (m *ErrorGetSecurityChecks) String() string                     { return renderErrorFields(m) }
func (m *ErrorGetSecurityCompliance) String() string                 { return renderErrorFields(m) }
func (m *ErrorGetSupportedSaas) String() string                      { return renderErrorFields(m) }
func (m *ErrorGetSystemLogs) String() string                         { return renderErrorFields(m) }
func (m *ErrorGetSystemUsers) String() string                        { return renderErrorFields(m) }
func (m *ErrorGetTransactionStatus) String() string                  { return renderErrorFields(m) }
func (m *ErrorGetUserInventory) String() string                      { return renderErrorFields(m) }
func (m *ErrorUploadDataResponse) String() string                    { return renderErrorFields(m) }
func (m *FalconxMetaInfo) String() string                            { return renderErrorFields(m) }
func (m *FalconxQuota) String() string                               { return renderErrorFields(m) }
func (m *FwmgrAPIMetaInfo) String() string                           { return renderErrorFields(m) }
func (m *FwmgrAPIQueryPaging) String() string                        { return renderErrorFields(m) }
func (m *FwmgrMsaspecError) String() string                          { return renderErrorFields(m) }
func (m *FwmgrMsaspecMetaInfo) String() string                       { return renderErrorFields(m) }
func (m *FwmgrMsaspecPaging) String() string                         { return renderErrorFields(m) }
func (m *FwmgrMsaspecWrites) String() string                         { return renderErrorFields(m) }
func (m *GraphValidationError) String() string                       { return renderErrorFields(m) }
func (m *IocapiPaginationMeta) String() string                       { return renderErrorFields(m) }
func (m *IocapiResponseMeta) String() string                         { return renderErrorFields(m) }
func (m *MalqueryExternalHuntOptions) String() string                { return renderErrorFields(m) }
func (m *MalqueryFuzzySearchMetaInfo) String() string                { return renderErrorFields(m) }
func (m *MalqueryQueryError) String() string                         { return renderErrorFields(m) }
func (m *MalqueryQueryMetaInfo) String() string                      { return renderErrorFields(m) }
func (m *MalqueryRateLimitsMeta) String() string                     { return renderErrorFields(m) }
func (m *MalqueryRequestMetaInfo) String() string                    { return renderErrorFields(m) }
func (m *MalquerySamplesMetadataMetaInfo) String() string            { return renderErrorFields(m) }
func (m *MalquerySearchParameter) String() string                    { return renderErrorFields(m) }
func (m *MalqueryStats) String() string                              { return renderErrorFields(m) }
func (m *MalqueryUserRequestCount) String() string                   { return renderErrorFields(m) }
func (m *MetaAppInventory) String() string                           { return renderErrorFields(m) }
func (m *MetaAppInventoryUsers) String() string                      { return renderErrorFields(m) }
func (m *MetaDismissAffected) String() string                        { return renderErrorFields(m) }
func (m *MetaDismissSecurityCheck) String() string                   { return renderErrorFields(m) }
func (m *MetaGetActivityMonitor) String() string                     { return renderErrorFields(m) }
func (m *MetaGetAffected) String() string                            { return renderErrorFields(m) }
func (m *MetaGetAlertsResponse) String() string                      { return renderErrorFields(m) }
func (m *MetaGetAssetInventory) String() string                      { return renderErrorFields(m) }
func (m *MetaGetDeviceInventory) String() string                     { return renderErrorFields(m) }
func (m *MetaGetEndTransaction) String() string                      { return renderErrorFields(m) }
func (m *MetaGetIntegrations) String() string                        { return renderErrorFields(m) }
func (m *MetaGetMetrics) String() string                             { return renderErrorFields(m) }
func (m *MetaGetSecurityChecks) String() string                      { return renderErrorFields(m) }
func (m *MetaGetSecurityCompliance) String() string                  { return renderErrorFields(m) }
func (m *MetaGetSupportedSaas) String() string                       { return renderErrorFields(m) }
func (m *MetaGetSystemLogs) String() string                          { return renderErrorFields(m) }
func (m *MetaGetSystemUsers) String() string                         { return renderErrorFields(m) }
func (m *MetaGetTransactionStatus) String() string                   { return renderErrorFields(m) }
func (m *MetaGetUserInventory) String() string                       { return renderErrorFields(m) }
func (m *MetaUploadDataResponse) String() string                     { return renderErrorFields(m) }
func (m *MlscannerapiMetaInfo) String() string                       { return renderErrorFields(m) }
func (m *MlscannerapiQuota) String() string                          { return renderErrorFields(m) }
func (m *MsaAPIError) String() string                                { return renderErrorFields(m) }
func (m *MsahandlerMSAError) String() string                         { return renderErrorFields(m) }
func (m *MsahandlerMSAMeta) String() string                          { return renderErrorFields(m) }
func (m *MsahandlerPagination) String() string                       { return renderErrorFields(m) }
func (m *MsaMetaInfo) String() string                                { return renderErrorFields(m) }
func (m *MsaPaging) String() string                                  { return renderErrorFields(m) }
func (m *MsaResources) String() string                               { return renderErrorFields(m) }
func (m *MsaspecWrites) String() string                              { return renderErrorFields(m) }
func (m *PaginationMetaAppInventory) String() string                 { return renderErrorFields(m) }
func (m *PaginationMetaAppInventoryUsers) String() string            { return renderErrorFields(m) }
func (m *PaginationMetaDismissAffected) String() string              { return renderErrorFields(m) }
func (m *PaginationMetaDismissSecurityCheck) String() string         { return renderErrorFields(m) }
func (m *PaginationMetaGetActivityMonitor) String() string           { return renderErrorFields(m) }
func (m *PaginationMetaGetAffected) String() string                  { return renderErrorFields(m) }
func (m *PaginationMetaGetAlertsResponse) String() string            { return renderErrorFields(m) }
func (m *PaginationMetaGetAssetInventory) String() string            { return renderErrorFields(m) }
func (m *PaginationMetaGetDeviceInventory) String() string           { return renderErrorFields(m) }
func (m *PaginationMetaGetEndTransaction) String() string            { return renderErrorFields(m) }
func (m *PaginationMetaGetIntegrations) String() string              { return renderErrorFields(m) }
func (m *PaginationMetaGetMetrics) String() string                   { return renderErrorFields(m) }
func (m *PaginationMetaGetSecurityChecks) String() string            { return renderErrorFields(m) }
func (m *PaginationMetaGetSecurityCompliance) String() string        { return renderErrorFields(m) }
func (m *PaginationMetaGetSupportedSaas) String() string             { return renderErrorFields(m) }
func (m *PaginationMetaGetSystemLogs) String() string                { return renderErrorFields(m) }
func (m *PaginationMetaGetSystemUsers) String() string               { return renderErrorFields(m) }
func (m *PaginationMetaGetTransactionStatus) String() string         { return renderErrorFields(m) }
func (m *PaginationMetaGetUserInventory) String() string             { return renderErrorFields(m) }
func (m *PaginationMetaUploadDataResponse) String() string           { return renderErrorFields(m) }
func (m *PolicymanagerError) String() string                         { return renderErrorFields(m) }
func (m *QuickscanproError) String() string                          { return renderErrorFields(m) }
func (m *QuickscanproMetaInfo) String() string                       { return renderErrorFields(m) }
func (m *QuickscanproQuotaResource) String() string                  { return renderErrorFields(m) }
func (m *ReconmsaAPIError) String() string                           { return renderErrorFields(m) }
func (m *ReconmsaAPIErrorDetail) String() string                     { return renderErrorFields(m) }
func (m *RegistrationIOMEventIDResponseMeta) String() string         { return renderErrorFields(m) }
func (m *RegistrationMSAMetaInfoExtension) String() string           { return renderErrorFields(m) }
func (m *RegistrationMSAPagingExtension) String() string             { return renderErrorFields(m) }
func (m *RegistrationNextTokenPagination) String() string            { return renderErrorFields(m) }
func (m *ResponsesError) String() string                             { return renderErrorFields(m) }
func (m *RestCursorAndLimitMetaInfo) String() string                 { return renderErrorFields(m) }
func (m *RestCursorMetaInfo) String() string                         { return renderErrorFields(m) }
func (m *RestPaging) String() string                                 { return renderErrorFields(m) }
func (m *ThreatgraphMeta) String() string                            { return renderErrorFields(m) }
func (m *ThreatgraphPaging) String() string                          { return renderErrorFields(m) }
func (m *VulnerabilitymetadataapiVulnAPIQueryPaging) String() string { return renderErrorFields(m) }
