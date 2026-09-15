package models

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	testErrorMessage = "The provided rule filter is empty"
	testErrorField   = "filter"
)

// errorModelsWithString lists every model given a String() in helper_methods.go.
// Go cannot enumerate a package's types at run time, so the list is explicit; the
// tests below drive all of it, which is what keeps it honest.
func errorModelsWithString() []fmt.Stringer {
	return []fmt.Stringer{
		&AccessscopemanagerV1Error{},
		&AccessscopemanagerV1Meta{},
		&AccessscopemanagerV1Pagination{},
		&APICursorMetaInfo{},
		&APIDetectsQueryMeta{},
		&APIDetectsQueryPaging{},
		&APIIndicatorsQueryMeta{},
		&APIIndicatorsQueryPaging{},
		&APIMetaInfo{},
		&APIModelEntityMetaInfo{},
		&APIPaging{},
		&APIPatchAgentMetaInfo{},
		&APISdmError{},
		&AssetgroupmanagerV1Error{},
		&AssetgroupmanagerV1Meta{},
		&AssetgroupmanagerV1Pagination{},
		&ChangesHighVolumeQueryMeta{},
		&ChangesHighVolumeQueryPaging{},
		&DetectsapiPostCombinedAlertsV1Meta{},
		&DetectsapiPostCombinedAlertsV1Paging{},
		&DeviceapiDevicePaging{},
		&DeviceapiDevicePagingV2{},
		&DeviceapiMetaInfo{},
		&DeviceapiRequestMeta{},
		&DevicecontrolapiRespMSAErrorV1{},
		&DevicecontrolapiRespMSAMetaV1{},
		&DevicecontrolapiRespPagingDetailsV1{},
		&DomainAPIQueryMetaV1{},
		&DomainAPIQueryPagingV1{},
		&DomainDiscoverAPIMetaInfo{},
		&DomainDiscoverAPIPaging{},
		&DomainFemEcosystemSubsidiariesMeta{},
		&DomainMetaInfo{},
		&DomainMsaMetaInfoWithSearchAfter{},
		&DomainPagingWithSearchAfter{},
		&DomainQuota{},
		&DomainReconAPIError{},
		&DomainReconAPIErrorDetail{},
		&DomainRuleMetaInfo{},
		&DomainRuleQuota{},
		&DomainSearchAfterMeta{},
		&DomainSearchAfterPaging{},
		&DomainSPAPIQueryMeta{},
		&DomainSPAPIQueryPaging{},
		&DomainVulnMetadataAPIMeta{},
		&ErrorAppInventory{},
		&ErrorAppInventoryUsers{},
		&ErrorDismissAffected{},
		&ErrorDismissSecurityCheck{},
		&ErrorGetActivityMonitor{},
		&ErrorGetAffected{},
		&ErrorGetAlertsResponse{},
		&ErrorGetAssetInventory{},
		&ErrorGetDeviceInventory{},
		&ErrorGetEndTransaction{},
		&ErrorGetIntegrations{},
		&ErrorGetMetrics{},
		&ErrorGetSecurityChecks{},
		&ErrorGetSecurityCompliance{},
		&ErrorGetSupportedSaas{},
		&ErrorGetSystemLogs{},
		&ErrorGetSystemUsers{},
		&ErrorGetTransactionStatus{},
		&ErrorGetUserInventory{},
		&ErrorUploadDataResponse{},
		&FalconxMetaInfo{},
		&FalconxQuota{},
		&FwmgrAPIMetaInfo{},
		&FwmgrAPIQueryPaging{},
		&FwmgrMsaspecError{},
		&FwmgrMsaspecMetaInfo{},
		&FwmgrMsaspecPaging{},
		&FwmgrMsaspecWrites{},
		&GraphValidationError{},
		&IocapiPaginationMeta{},
		&IocapiResponseMeta{},
		&MalqueryExternalHuntOptions{},
		&MalqueryFuzzySearchMetaInfo{},
		&MalqueryQueryError{},
		&MalqueryQueryMetaInfo{},
		&MalqueryRateLimitsMeta{},
		&MalqueryRequestMetaInfo{},
		&MalquerySamplesMetadataMetaInfo{},
		&MalquerySearchParameter{},
		&MalqueryStats{},
		&MalqueryUserRequestCount{},
		&MetaAppInventory{},
		&MetaAppInventoryUsers{},
		&MetaDismissAffected{},
		&MetaDismissSecurityCheck{},
		&MetaGetActivityMonitor{},
		&MetaGetAffected{},
		&MetaGetAlertsResponse{},
		&MetaGetAssetInventory{},
		&MetaGetDeviceInventory{},
		&MetaGetEndTransaction{},
		&MetaGetIntegrations{},
		&MetaGetMetrics{},
		&MetaGetSecurityChecks{},
		&MetaGetSecurityCompliance{},
		&MetaGetSupportedSaas{},
		&MetaGetSystemLogs{},
		&MetaGetSystemUsers{},
		&MetaGetTransactionStatus{},
		&MetaGetUserInventory{},
		&MetaUploadDataResponse{},
		&MlscannerapiMetaInfo{},
		&MlscannerapiQuota{},
		&MsaAPIError{},
		&MsahandlerMSAError{},
		&MsahandlerMSAMeta{},
		&MsahandlerPagination{},
		&MsaMetaInfo{},
		&MsaPaging{},
		&MsaResources{},
		&MsaspecWrites{},
		&PaginationMetaAppInventory{},
		&PaginationMetaAppInventoryUsers{},
		&PaginationMetaDismissAffected{},
		&PaginationMetaDismissSecurityCheck{},
		&PaginationMetaGetActivityMonitor{},
		&PaginationMetaGetAffected{},
		&PaginationMetaGetAlertsResponse{},
		&PaginationMetaGetAssetInventory{},
		&PaginationMetaGetDeviceInventory{},
		&PaginationMetaGetEndTransaction{},
		&PaginationMetaGetIntegrations{},
		&PaginationMetaGetMetrics{},
		&PaginationMetaGetSecurityChecks{},
		&PaginationMetaGetSecurityCompliance{},
		&PaginationMetaGetSupportedSaas{},
		&PaginationMetaGetSystemLogs{},
		&PaginationMetaGetSystemUsers{},
		&PaginationMetaGetTransactionStatus{},
		&PaginationMetaGetUserInventory{},
		&PaginationMetaUploadDataResponse{},
		&PolicymanagerError{},
		&QuickscanproError{},
		&QuickscanproMetaInfo{},
		&QuickscanproQuotaResource{},
		&ReconmsaAPIError{},
		&ReconmsaAPIErrorDetail{},
		&RegistrationIOMEventIDResponseMeta{},
		&RegistrationMSAMetaInfoExtension{},
		&RegistrationMSAPagingExtension{},
		&RegistrationNextTokenPagination{},
		&ResponsesError{},
		&RestCursorAndLimitMetaInfo{},
		&RestCursorMetaInfo{},
		&RestPaging{},
		&ThreatgraphMeta{},
		&ThreatgraphPaging{},
		&VulnerabilitymetadataapiVulnAPIQueryPaging{},
	}
}

// fillEveryField populates every exported field reachable from v, allocating
// pointers and appending one element to each slice, so that a rendering test sees
// a fully populated model rather than only the fields the author thought of.
func fillEveryField(v reflect.Value, depth int) {
	if depth > 5 || !v.CanSet() {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		fillEveryField(v.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fillEveryField(v.Field(i), depth+1)
			}
		}
	case reflect.String:
		v.SetString("filled")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Interface:
		v.Set(reflect.ValueOf("filled"))
	case reflect.Slice:
		elem := reflect.New(v.Type().Elem()).Elem()
		fillEveryField(elem, depth+1)
		v.Set(reflect.Append(v, elem))
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
	}
}

// TestErrorModelsRenderEmptyAsBraces pins the rendering of a model with no field
// set, and fails to compile if any of these types loses its String() method.
func TestErrorModelsRenderEmptyAsBraces(t *testing.T) {
	for _, model := range errorModelsWithString() {
		if got := model.String(); got != "{}" {
			t.Errorf("%T with no field set rendered %q, want \"{}\"", model, got)
		}
	}
}

// TestErrorModelsFullyPopulatedRenderNoAddress populates every field of every
// model and asserts the rendering never shows a pointer address. This is the
// check that caught the nested leak in MsaMetaInfo, whose *MsaPaging fields are
// all pointers. See issue #719.
func TestErrorModelsFullyPopulatedRenderNoAddress(t *testing.T) {
	for _, model := range errorModelsWithString() {
		fillEveryField(reflect.ValueOf(model).Elem(), 0)

		got := model.String()
		if strings.Contains(got, "0x") {
			t.Errorf("%T leaked a pointer address: %s", model, got)
		}
		if strings.Contains(got, "PANIC") {
			t.Errorf("%T panicked while rendering: %s", model, got)
		}
		if strings.Count(got, "{") != strings.Count(got, "}") {
			t.Errorf("%T rendered unbalanced braces: %s", model, got)
		}
	}
}

// TestErrorPayloadsRenderNoAddress renders representative response models the way
// the generated Error() methods do, one per family of Meta type, covering both
// the Errors and the Meta field.
func TestErrorPayloadsRenderNoAddress(t *testing.T) {
	payloads := []any{
		&MsaErrorsOnly{},
		&MsahandlerQuerySkillUsageResponse{},
		&FwmgrAPINetworkLocationSummariesResponse{},
		&DomainSPAPICombinedInstalledPatchesResponse{},
		&DomainDiscoverAPICombinedHostsResponse{},
		&CustomStorageObjectKeys{},
	}

	for _, payload := range payloads {
		value := reflect.ValueOf(payload).Elem()

		errorsField := value.FieldByName("Errors")
		element := reflect.New(errorsField.Type().Elem().Elem())
		fillEveryField(element.Elem(), 0)
		errorsField.Set(reflect.Append(errorsField, element))

		if meta := value.FieldByName("Meta"); meta.IsValid() && meta.Kind() == reflect.Pointer {
			fillEveryField(meta, 0)
		}

		got := fmt.Sprintf("%+v", payload)
		if strings.Contains(got, "0x") {
			t.Errorf("%T leaked a pointer address: %s", payload, got)
		}
		if !strings.Contains(got, "Message:filled") {
			t.Errorf("%T did not render the error message: %s", payload, got)
		}
	}
}

// TestErrorModelStringRendersMessage checks the message survives rendering when
// only some pointer fields are set, which is the shape a real API error takes.
func TestErrorModelStringRendersMessage(t *testing.T) {
	message := testErrorMessage
	field := testErrorField
	code := int32(400)
	codeText := "400"

	tests := []struct {
		name  string
		value fmt.Stringer
	}{
		{"code and message", &DomainReconAPIError{Code: &code, Message: &message}},
		{"message only", &DomainReconAPIError{Message: &message}},
		{"string code", &ErrorGetAlertsResponse{Code: &codeText, Message: &message}},
		{"non-pointer fields", &AccessscopemanagerV1Error{Code: codeText, ID: "id", Message: message}},
		{"nested details", &DomainReconAPIError{
			Code:    &code,
			Details: []*DomainReconAPIErrorDetail{{Field: &field, Message: &message}},
		}},
		{"nested recon details", &ReconmsaAPIError{
			Code:    &code,
			Details: []*ReconmsaAPIErrorDetail{{Field: &field, Message: &message}},
		}},
		{"msa api error", &MsaAPIError{Code: &code, Message: &message}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.value.String()
			if strings.Contains(got, "0x") {
				t.Errorf("String() leaked a pointer address: %s", got)
			}
			if !strings.Contains(got, testErrorMessage) {
				t.Errorf("String() = %q, want it to contain %q", got, testErrorMessage)
			}
		})
	}
}

// TestErrorPayloadRenderingMatchesIssueReproducer replays the reproducer from
// issue #719: the covered and the previously leaking payload must both show the
// message when formatted with %+v.
func TestErrorPayloadRenderingMatchesIssueReproducer(t *testing.T) {
	message := testErrorMessage
	code := int32(400)

	payloads := []any{
		&MsaReplyMetaOnly{
			Errors: []*MsaAPIError{{Code: &code, Message: &message}},
			Meta:   &MsaMetaInfo{},
		},
		&DomainErrorsOnly{
			Errors: []*DomainReconAPIError{{Code: &code, Message: &message}},
			Meta:   &MsaMetaInfo{},
		},
	}

	for _, payload := range payloads {
		got := fmt.Sprintf("%+v", payload)
		if strings.Contains(got, "0x") {
			t.Errorf("%T rendered a pointer address: %s", payload, got)
		}
		if !strings.Contains(got, message) {
			t.Errorf("%T did not render the message: %s", payload, got)
		}
	}
}

// TestMsaMetaInfoNestedPointersRender covers the leak the original #116 fix left
// behind: MsaMetaInfo.String() rendered *MsaPaging and *MsaResources with %+v, so
// their all-pointer fields printed as addresses.
func TestMsaMetaInfoNestedPointersRender(t *testing.T) {
	limit, offset := int32(10), int32(0)
	total := int64(99)
	queryTime := 0.0009
	traceID := "44b31c94"
	affected := int32(3)

	meta := &MsaMetaInfo{
		Pagination: &MsaPaging{Limit: &limit, Offset: &offset, Total: &total},
		PoweredBy:  "recon",
		QueryTime:  &queryTime,
		TraceID:    &traceID,
		Writes:     &MsaResources{ResourcesAffected: &affected},
	}

	got := meta.String()
	if strings.Contains(got, "0x") {
		t.Fatalf("MsaMetaInfo leaked a pointer address: %s", got)
	}
	for _, want := range []string{"Limit:10", "Offset:0", "Total:99", "PoweredBy:recon", "ResourcesAffected:3"} {
		if !strings.Contains(got, want) {
			t.Errorf("MsaMetaInfo rendering %q is missing %q", got, want)
		}
	}
}

// TestErrorModelRenderingIsBraceBalanced guards the defect MsaMetaInfo.String()
// carried since v0.2.9, where it emitted a trailing "}" with no opening brace.
func TestErrorModelRenderingIsBraceBalanced(t *testing.T) {
	code := int32(400)
	message := testErrorMessage

	values := []fmt.Stringer{
		&MsaAPIError{Code: &code},
		&MsaAPIError{Code: &code, Message: &message},
		&MsaMetaInfo{},
		&MsaMetaInfo{PoweredBy: "recon"},
		&MsaPaging{},
		&DomainReconAPIError{Code: &code},
	}

	for _, value := range values {
		got := value.String()
		if strings.Count(got, "{") != strings.Count(got, "}") {
			t.Errorf("%T rendered unbalanced braces: %q", value, got)
		}
		if strings.HasSuffix(got, " }") {
			t.Errorf("%T rendered a trailing space before the closing brace: %q", value, got)
		}
	}
}

// TestErrorModelStringNilPointerElement documents that a nil element in an Errors
// slice renders as <nil> rather than panicking.
func TestErrorModelStringNilPointerElement(t *testing.T) {
	payload := &DomainErrorsOnly{Errors: []*DomainReconAPIError{nil}}

	got := fmt.Sprintf("%+v", payload)
	if strings.Contains(got, "0x") || strings.Contains(got, "PANIC") {
		t.Errorf("nil element rendered as %s", got)
	}
	if !strings.Contains(got, "<nil>") {
		t.Errorf("nil element rendered as %s, want <nil>", got)
	}
}

// TestRenderErrorFieldsKeepsPointerToZero checks that a pointer to a zero value
// is still reported, since the API uses these pointers to tell an unset field
// from a zero one.
func TestRenderErrorFieldsKeepsPointerToZero(t *testing.T) {
	zero := int32(0)
	message := testErrorMessage

	got := (&DomainReconAPIError{Code: &zero, Message: &message}).String()
	if !strings.Contains(got, "Code:0") {
		t.Errorf("String() = %q, want it to report Code:0", got)
	}
}

// TestRenderErrorFieldsNilReceiver checks the helper does not panic when called
// on a nil model.
func TestRenderErrorFieldsNilReceiver(t *testing.T) {
	var model *DomainReconAPIError
	if got := model.String(); got != "<nil>" {
		t.Errorf("nil receiver rendered %q, want \"<nil>\"", got)
	}
}
