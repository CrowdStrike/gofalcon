// Package models_test holds the tests for the hand-written String() methods in
// helper_methods.go.
//
// These tests deliberately live in an external test package rather than in
// package models. An in-package test file makes the toolchain build a test
// variant of models, and models is 3200 files, so golangci-lint then analyses
// the whole package twice. That roughly doubled lint time and pushed the macOS
// CI job past its --timeout. Nothing here needs unexported access, so keep it
// external.
package models_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
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
		&models.AccessscopemanagerV1Error{},
		&models.AccessscopemanagerV1Meta{},
		&models.AccessscopemanagerV1Pagination{},
		&models.APICursorMetaInfo{},
		&models.APIDetectsQueryMeta{},
		&models.APIDetectsQueryPaging{},
		&models.APIIndicatorsQueryMeta{},
		&models.APIIndicatorsQueryPaging{},
		&models.APIMetaInfo{},
		&models.APIModelEntityMetaInfo{},
		&models.APIPaging{},
		&models.APIPatchAgentMetaInfo{},
		&models.APISdmError{},
		&models.AssetgroupmanagerV1Error{},
		&models.AssetgroupmanagerV1Meta{},
		&models.AssetgroupmanagerV1Pagination{},
		&models.ChangesHighVolumeQueryMeta{},
		&models.ChangesHighVolumeQueryPaging{},
		&models.DetectsapiPostCombinedAlertsV1Meta{},
		&models.DetectsapiPostCombinedAlertsV1Paging{},
		&models.DeviceapiDevicePaging{},
		&models.DeviceapiDevicePagingV2{},
		&models.DeviceapiMetaInfo{},
		&models.DeviceapiRequestMeta{},
		&models.DevicecontrolapiRespMSAErrorV1{},
		&models.DevicecontrolapiRespMSAMetaV1{},
		&models.DevicecontrolapiRespPagingDetailsV1{},
		&models.DomainAPIQueryMetaV1{},
		&models.DomainAPIQueryPagingV1{},
		&models.DomainDiscoverAPIMetaInfo{},
		&models.DomainDiscoverAPIPaging{},
		&models.DomainFemEcosystemSubsidiariesMeta{},
		&models.DomainMetaInfo{},
		&models.DomainMsaMetaInfoWithSearchAfter{},
		&models.DomainPagingWithSearchAfter{},
		&models.DomainQuota{},
		&models.DomainReconAPIError{},
		&models.DomainReconAPIErrorDetail{},
		&models.DomainRuleMetaInfo{},
		&models.DomainRuleQuota{},
		&models.DomainSearchAfterMeta{},
		&models.DomainSearchAfterPaging{},
		&models.DomainSPAPIQueryMeta{},
		&models.DomainSPAPIQueryPaging{},
		&models.DomainVulnMetadataAPIMeta{},
		&models.ErrorAppInventory{},
		&models.ErrorAppInventoryUsers{},
		&models.ErrorDismissAffected{},
		&models.ErrorDismissSecurityCheck{},
		&models.ErrorGetActivityMonitor{},
		&models.ErrorGetAffected{},
		&models.ErrorGetAlertsResponse{},
		&models.ErrorGetAssetInventory{},
		&models.ErrorGetDeviceInventory{},
		&models.ErrorGetEndTransaction{},
		&models.ErrorGetIntegrations{},
		&models.ErrorGetMetrics{},
		&models.ErrorGetSecurityChecks{},
		&models.ErrorGetSecurityCompliance{},
		&models.ErrorGetSupportedSaas{},
		&models.ErrorGetSystemLogs{},
		&models.ErrorGetSystemUsers{},
		&models.ErrorGetTransactionStatus{},
		&models.ErrorGetUserInventory{},
		&models.ErrorUploadDataResponse{},
		&models.FalconxMetaInfo{},
		&models.FalconxQuota{},
		&models.FwmgrAPIMetaInfo{},
		&models.FwmgrAPIQueryPaging{},
		&models.FwmgrMsaspecError{},
		&models.FwmgrMsaspecMetaInfo{},
		&models.FwmgrMsaspecPaging{},
		&models.FwmgrMsaspecWrites{},
		&models.GraphValidationError{},
		&models.IocapiPaginationMeta{},
		&models.IocapiResponseMeta{},
		&models.MalqueryExternalHuntOptions{},
		&models.MalqueryFuzzySearchMetaInfo{},
		&models.MalqueryQueryError{},
		&models.MalqueryQueryMetaInfo{},
		&models.MalqueryRateLimitsMeta{},
		&models.MalqueryRequestMetaInfo{},
		&models.MalquerySamplesMetadataMetaInfo{},
		&models.MalquerySearchParameter{},
		&models.MalqueryStats{},
		&models.MalqueryUserRequestCount{},
		&models.MetaAppInventory{},
		&models.MetaAppInventoryUsers{},
		&models.MetaDismissAffected{},
		&models.MetaDismissSecurityCheck{},
		&models.MetaGetActivityMonitor{},
		&models.MetaGetAffected{},
		&models.MetaGetAlertsResponse{},
		&models.MetaGetAssetInventory{},
		&models.MetaGetDeviceInventory{},
		&models.MetaGetEndTransaction{},
		&models.MetaGetIntegrations{},
		&models.MetaGetMetrics{},
		&models.MetaGetSecurityChecks{},
		&models.MetaGetSecurityCompliance{},
		&models.MetaGetSupportedSaas{},
		&models.MetaGetSystemLogs{},
		&models.MetaGetSystemUsers{},
		&models.MetaGetTransactionStatus{},
		&models.MetaGetUserInventory{},
		&models.MetaUploadDataResponse{},
		&models.MlscannerapiMetaInfo{},
		&models.MlscannerapiQuota{},
		&models.MsaAPIError{},
		&models.MsahandlerMSAError{},
		&models.MsahandlerMSAMeta{},
		&models.MsahandlerPagination{},
		&models.MsaMetaInfo{},
		&models.MsaPaging{},
		&models.MsaResources{},
		&models.MsaspecWrites{},
		&models.PaginationMetaAppInventory{},
		&models.PaginationMetaAppInventoryUsers{},
		&models.PaginationMetaDismissAffected{},
		&models.PaginationMetaDismissSecurityCheck{},
		&models.PaginationMetaGetActivityMonitor{},
		&models.PaginationMetaGetAffected{},
		&models.PaginationMetaGetAlertsResponse{},
		&models.PaginationMetaGetAssetInventory{},
		&models.PaginationMetaGetDeviceInventory{},
		&models.PaginationMetaGetEndTransaction{},
		&models.PaginationMetaGetIntegrations{},
		&models.PaginationMetaGetMetrics{},
		&models.PaginationMetaGetSecurityChecks{},
		&models.PaginationMetaGetSecurityCompliance{},
		&models.PaginationMetaGetSupportedSaas{},
		&models.PaginationMetaGetSystemLogs{},
		&models.PaginationMetaGetSystemUsers{},
		&models.PaginationMetaGetTransactionStatus{},
		&models.PaginationMetaGetUserInventory{},
		&models.PaginationMetaUploadDataResponse{},
		&models.PolicymanagerError{},
		&models.QuickscanproError{},
		&models.QuickscanproMetaInfo{},
		&models.QuickscanproQuotaResource{},
		&models.ReconmsaAPIError{},
		&models.ReconmsaAPIErrorDetail{},
		&models.RegistrationIOMEventIDResponseMeta{},
		&models.RegistrationMSAMetaInfoExtension{},
		&models.RegistrationMSAPagingExtension{},
		&models.RegistrationNextTokenPagination{},
		&models.ResponsesError{},
		&models.RestCursorAndLimitMetaInfo{},
		&models.RestCursorMetaInfo{},
		&models.RestPaging{},
		&models.ThreatgraphMeta{},
		&models.ThreatgraphPaging{},
		&models.VulnerabilitymetadataapiVulnAPIQueryPaging{},
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
// check that caught the nested leak in models.MsaMetaInfo, whose *models.MsaPaging fields are
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
		&models.MsaErrorsOnly{},
		&models.MsahandlerQuerySkillUsageResponse{},
		&models.FwmgrAPINetworkLocationSummariesResponse{},
		&models.DomainSPAPICombinedInstalledPatchesResponse{},
		&models.DomainDiscoverAPICombinedHostsResponse{},
		&models.CustomStorageObjectKeys{},
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
		{"code and message", &models.DomainReconAPIError{Code: &code, Message: &message}},
		{"message only", &models.DomainReconAPIError{Message: &message}},
		{"string code", &models.ErrorGetAlertsResponse{Code: &codeText, Message: &message}},
		{"non-pointer fields", &models.AccessscopemanagerV1Error{Code: codeText, ID: "id", Message: message}},
		{"nested details", &models.DomainReconAPIError{
			Code:    &code,
			Details: []*models.DomainReconAPIErrorDetail{{Field: &field, Message: &message}},
		}},
		{"nested recon details", &models.ReconmsaAPIError{
			Code:    &code,
			Details: []*models.ReconmsaAPIErrorDetail{{Field: &field, Message: &message}},
		}},
		{"msa api error", &models.MsaAPIError{Code: &code, Message: &message}},
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
		&models.MsaReplyMetaOnly{
			Errors: []*models.MsaAPIError{{Code: &code, Message: &message}},
			Meta:   &models.MsaMetaInfo{},
		},
		&models.DomainErrorsOnly{
			Errors: []*models.DomainReconAPIError{{Code: &code, Message: &message}},
			Meta:   &models.MsaMetaInfo{},
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
// behind: models.MsaMetaInfo.String() rendered *models.MsaPaging and *models.MsaResources with %+v, so
// their all-pointer fields printed as addresses.
func TestMsaMetaInfoNestedPointersRender(t *testing.T) {
	limit, offset := int32(10), int32(0)
	total := int64(99)
	queryTime := 0.0009
	traceID := "44b31c94"
	affected := int32(3)

	meta := &models.MsaMetaInfo{
		Pagination: &models.MsaPaging{Limit: &limit, Offset: &offset, Total: &total},
		PoweredBy:  "recon",
		QueryTime:  &queryTime,
		TraceID:    &traceID,
		Writes:     &models.MsaResources{ResourcesAffected: &affected},
	}

	got := meta.String()
	if strings.Contains(got, "0x") {
		t.Fatalf("models.MsaMetaInfo leaked a pointer address: %s", got)
	}
	for _, want := range []string{"Limit:10", "Offset:0", "Total:99", "PoweredBy:recon", "ResourcesAffected:3"} {
		if !strings.Contains(got, want) {
			t.Errorf("models.MsaMetaInfo rendering %q is missing %q", got, want)
		}
	}
}

// TestErrorModelRenderingIsBraceBalanced guards the defect models.MsaMetaInfo.String()
// carried since v0.2.9, where it emitted a trailing "}" with no opening brace.
func TestErrorModelRenderingIsBraceBalanced(t *testing.T) {
	code := int32(400)
	message := testErrorMessage

	values := []fmt.Stringer{
		&models.MsaAPIError{Code: &code},
		&models.MsaAPIError{Code: &code, Message: &message},
		&models.MsaMetaInfo{},
		&models.MsaMetaInfo{PoweredBy: "recon"},
		&models.MsaPaging{},
		&models.DomainReconAPIError{Code: &code},
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
	payload := &models.DomainErrorsOnly{Errors: []*models.DomainReconAPIError{nil}}

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

	got := (&models.DomainReconAPIError{Code: &zero, Message: &message}).String()
	if !strings.Contains(got, "Code:0") {
		t.Errorf("String() = %q, want it to report Code:0", got)
	}
}

// TestRenderErrorFieldsNilReceiver checks the helper does not panic when called
// on a nil model.
func TestRenderErrorFieldsNilReceiver(t *testing.T) {
	var model *models.DomainReconAPIError
	if got := model.String(); got != "<nil>" {
		t.Errorf("nil receiver rendered %q, want \"<nil>\"", got)
	}
}
