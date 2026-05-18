package testing

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/detects"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

// TestFakeClient_HostOperations verifies host query and detail retrieval using mock handlers.
func TestFakeClient_HostOperations(t *testing.T) {
	fakeClient := NewFakeClient()
	deviceIDs := GenerateDeviceIDs(3)

	fakeClient.AddMockHandler("QueryDevicesByFilter", func(request Request) (bool, interface{}, error) {
		queryTime := 0.1
		traceID := "test-trace-id"
		total := int64(len(deviceIDs))
		limit := int32(len(deviceIDs))

		response := &hosts.QueryDevicesByFilterOK{
			Payload: &models.MsaQueryResponse{
				Meta: &models.MsaMetaInfo{
					QueryTime:  &queryTime,
					TraceID:    &traceID,
					PoweredBy:  "test-powered-by",
					Pagination: &models.MsaPaging{Total: &total, Limit: &limit},
				},
				Resources: deviceIDs,
			},
		}
		return true, response, nil
	})

	fakeClient.AddMockHandler("GetDeviceDetailsV2", func(request Request) (bool, interface{}, error) {
		var devices []*models.DeviceapiDeviceSwagger
		for i, deviceID := range deviceIDs {
			cidPtr := "test-cid"
			deviceIDPtr := deviceID
			device := &models.DeviceapiDeviceSwagger{
				AgentVersion:       "6.45.15806.0",
				Cid:                &cidPtr,
				DeviceID:           &deviceIDPtr,
				FirstSeen:          time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
				Hostname:           fmt.Sprintf("test-host-%d.example.com", i+1),
				LastSeen:           time.Now().Add(-time.Minute).Format(time.RFC3339),
				LocalIP:            fmt.Sprintf("192.168.1.%d", i+100),
				MacAddress:         fmt.Sprintf("00:11:22:33:44:%02x", i+10),
				OsVersion:          "Windows 10",
				SystemManufacturer: "Dell Inc.",
				SystemProductName:  "OptiPlex 7090",
			}
			devices = append(devices, device)
		}

		queryTime := 0.2
		traceID := "test-trace-id"
		response := &hosts.GetDeviceDetailsV2OK{
			Payload: &models.DeviceapiDeviceDetailsResponseSwagger{
				Meta: &models.MsaMetaInfo{
					QueryTime: &queryTime,
					TraceID:   &traceID,
					PoweredBy: "test-powered-by",
				},
				Resources: devices,
			},
		}
		return true, response, nil
	})

	client := fakeClient.GetClient()

	queryResult, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !equalStringSlices(deviceIDs, queryResult.Payload.Resources) {
		t.Fatalf("expected device IDs %v, got %v", deviceIDs, queryResult.Payload.Resources)
	}

	detailsResult, err := client.Hosts.GetDeviceDetailsV2(&hosts.GetDeviceDetailsV2Params{
		Ids: deviceIDs,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(detailsResult.Payload.Resources) != len(deviceIDs) {
		t.Fatalf("expected %d devices, got %d", len(deviceIDs), len(detailsResult.Payload.Resources))
	}

	requests := fakeClient.Requests()
	if len(requests) != 2 {
		t.Fatalf("expected 2 recorded requests, got %d", len(requests))
	}
	if requests[0].GetOperationID() != "QueryDevicesByFilter" {
		t.Fatalf("expected first operation 'QueryDevicesByFilter', got '%s'", requests[0].GetOperationID())
	}
	if requests[1].GetOperationID() != "GetDeviceDetailsV2" {
		t.Fatalf("expected second operation 'GetDeviceDetailsV2', got '%s'", requests[1].GetOperationID())
	}
}

// TestFakeClient_DetectionOperations verifies detection query and summary retrieval.
func TestFakeClient_DetectionOperations(t *testing.T) {
	fakeClient := NewFakeClient()
	detectionIDs := GenerateDetectionIDs(2)

	fakeClient.AddMockHandler("QueryDetects", func(request Request) (bool, interface{}, error) {
		queryTime := 0.15
		traceID := "test-detection-trace-id"
		total := int64(len(detectionIDs))
		limit := int32(len(detectionIDs))

		response := &detects.QueryDetectsOK{
			Payload: &models.MsaQueryResponse{
				Meta: &models.MsaMetaInfo{
					QueryTime:  &queryTime,
					TraceID:    &traceID,
					PoweredBy:  "test-powered-by",
					Pagination: &models.MsaPaging{Total: &total, Limit: &limit},
				},
				Resources: detectionIDs,
			},
		}
		return true, response, nil
	})

	fakeClient.AddMockHandler("GetDetectSummaries", func(request Request) (bool, interface{}, error) {
		var detections []*models.DomainAPIDetectionDocument
		for i, detectionID := range detectionIDs {
			severity := int32(3)
			if i%2 == 0 {
				severity = 5
			}
			cidPtr := "test-cid"
			detectionIDPtr := detectionID
			displayName := "Medium"
			if severity == 5 {
				displayName = "Critical"
			}
			showInUI := true
			statusPtr := "new"

			detection := &models.DomainAPIDetectionDocument{
				Cid:                    &cidPtr,
				DetectionID:            &detectionIDPtr,
				MaxSeverity:            &severity,
				MaxSeverityDisplayname: &displayName,
				ShowInUI:               &showInUI,
				Status:                 &statusPtr,
			}
			detections = append(detections, detection)
		}

		queryTime := 0.25
		traceID := "test-detection-trace-id"
		response := &detects.GetDetectSummariesOK{
			Payload: &models.DomainMsaDetectSummariesResponse{
				Meta: &models.MsaMetaInfo{
					QueryTime: &queryTime,
					TraceID:   &traceID,
					PoweredBy: "test-powered-by",
				},
				Resources: detections,
			},
		}
		return true, response, nil
	})

	client := fakeClient.GetClient()

	queryResult, err := client.Detects.QueryDetects(&detects.QueryDetectsParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !equalStringSlices(detectionIDs, queryResult.Payload.Resources) {
		t.Fatalf("expected detection IDs %v, got %v", detectionIDs, queryResult.Payload.Resources)
	}

	summariesResult, err := client.Detects.GetDetectSummaries(&detects.GetDetectSummariesParams{
		Body: &models.MsaIdsRequest{Ids: detectionIDs},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summariesResult.Payload.Resources) != len(detectionIDs) {
		t.Fatalf("expected %d detections, got %d", len(detectionIDs), len(summariesResult.Payload.Resources))
	}

	for i, detection := range summariesResult.Payload.Resources {
		if *detection.DetectionID != detectionIDs[i] {
			t.Fatalf("expected detection ID %s, got %s", detectionIDs[i], *detection.DetectionID)
		}
		if detection.MaxSeverity == nil {
			t.Fatal("severity must not be nil")
		}
		if detection.Status == nil {
			t.Fatal("status must not be nil")
		}
	}
}

// TestFakeClient_CustomMockHandler verifies parameter inspection via GetParamsAs.
func TestFakeClient_CustomMockHandler(t *testing.T) {
	fakeClient := NewFakeClient()

	customResponse := &hosts.QueryDevicesByFilterOK{Payload: nil}

	fakeClient.AddMockHandler("QueryDevicesByFilter", func(request Request) (bool, interface{}, error) {
		if params, ok := GetParamsAs[hosts.QueryDevicesByFilterParams](request); ok {
			t.Logf("Received parameters: %+v", params)
		}
		return true, customResponse, nil
	})

	client := fakeClient.GetClient()
	result, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != customResponse {
		t.Fatalf("expected custom response %p, got %p", customResponse, result)
	}
}

// TestFakeClient_ErrorMockHandler verifies error simulation via AddErrorMockHandler.
func TestFakeClient_ErrorMockHandler(t *testing.T) {
	fakeClient := NewFakeClient()
	testError := fmt.Errorf("test API error")

	fakeClient.AddErrorMockHandler("QueryDevicesByFilter", testError)

	client := fakeClient.GetClient()
	_, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
	if err == nil {
		t.Fatal("expected an error but got none")
	}
	if err != testError {
		t.Fatalf("expected error %v, got %v", testError, err)
	}
}

// TestFakeClient_StaticMockHandler verifies consistent responses across multiple calls.
func TestFakeClient_StaticMockHandler(t *testing.T) {
	fakeClient := NewFakeClient()

	queryTime := 0.1
	traceID := "test-trace-id"
	deviceIDs := []string{"static-device-id"}
	total := int64(len(deviceIDs))
	limit := int32(len(deviceIDs))

	staticResponse := &hosts.QueryDevicesByFilterOK{
		Payload: &models.MsaQueryResponse{
			Meta: &models.MsaMetaInfo{
				QueryTime:  &queryTime,
				TraceID:    &traceID,
				PoweredBy:  "test-powered-by",
				Pagination: &models.MsaPaging{Total: &total, Limit: &limit},
			},
			Resources: deviceIDs,
		},
	}

	fakeClient.AddStaticMockHandler("QueryDevicesByFilter", staticResponse)

	client := fakeClient.GetClient()
	for i := range 3 {
		result, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
		if err != nil {
			t.Fatalf("unexpected error on call %d: %v", i+1, err)
		}
		if !equalStringSlices(deviceIDs, result.Payload.Resources) {
			t.Fatalf("call %d: expected %v, got %v", i+1, deviceIDs, result.Payload.Resources)
		}
	}

	if len(fakeClient.Requests()) != 3 {
		t.Fatalf("expected 3 recorded requests, got %d", len(fakeClient.Requests()))
	}
}

// TestFakeClient_RequestTracking verifies request recording, filtering, and clearing.
func TestFakeClient_RequestTracking(t *testing.T) {
	fakeClient := NewFakeClient()

	fakeClient.AddMockHandler("QueryDevicesByFilter", func(request Request) (bool, interface{}, error) {
		queryTime := 0.1
		traceID := "test-trace-id"
		deviceIDs := []string{"test"}
		total := int64(len(deviceIDs))
		limit := int32(len(deviceIDs))

		response := &hosts.QueryDevicesByFilterOK{
			Payload: &models.MsaQueryResponse{
				Meta: &models.MsaMetaInfo{
					QueryTime:  &queryTime,
					TraceID:    &traceID,
					PoweredBy:  "test-powered-by",
					Pagination: &models.MsaPaging{Total: &total, Limit: &limit},
				},
				Resources: deviceIDs,
			},
		}
		return true, response, nil
	})

	client := fakeClient.GetClient()
	_, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	_, err = client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if len(fakeClient.FilterRequests("QueryDevicesByFilter")) != 2 {
		t.Fatalf("expected 2 filtered requests, got %d", len(fakeClient.FilterRequests("QueryDevicesByFilter")))
	}

	fakeClient.ClearRequests()
	if len(fakeClient.Requests()) != 0 {
		t.Fatalf("expected 0 requests after clearing, got %d", len(fakeClient.Requests()))
	}
}

// TestFakeClient_ResetFunctionality verifies that Reset clears both requests and handlers.
func TestFakeClient_ResetFunctionality(t *testing.T) {
	fakeClient := NewFakeClient()

	fakeClient.AddMockHandler("QueryDevicesByFilter", func(request Request) (bool, interface{}, error) {
		queryTime := 0.1
		traceID := "test-trace-id"
		deviceIDs := []string{"test"}
		total := int64(len(deviceIDs))
		limit := int32(len(deviceIDs))

		response := &hosts.QueryDevicesByFilterOK{
			Payload: &models.MsaQueryResponse{
				Meta: &models.MsaMetaInfo{
					QueryTime:  &queryTime,
					TraceID:    &traceID,
					PoweredBy:  "test-powered-by",
					Pagination: &models.MsaPaging{Total: &total, Limit: &limit},
				},
				Resources: deviceIDs,
			},
		}
		return true, response, nil
	})

	client := fakeClient.GetClient()
	_, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
	if err != nil {
		t.Fatalf("API call failed: %v", err)
	}

	if len(fakeClient.Requests()) != 1 {
		t.Fatalf("expected 1 request before reset, got %d", len(fakeClient.Requests()))
	}
	if len(fakeClient.HandlerChain) != 1 {
		t.Fatalf("expected 1 handler before reset, got %d", len(fakeClient.HandlerChain))
	}

	fakeClient.Reset()

	if len(fakeClient.Requests()) != 0 {
		t.Fatalf("expected 0 requests after reset, got %d", len(fakeClient.Requests()))
	}
	if len(fakeClient.HandlerChain) != 0 {
		t.Fatalf("expected 0 handlers after reset, got %d", len(fakeClient.HandlerChain))
	}
}

// TestFakeClient_PrependMockHandler verifies that prepended handlers take precedence.
func TestFakeClient_PrependMockHandler(t *testing.T) {
	fakeClient := NewFakeClient()

	fakeClient.AddMockHandler("QueryDevicesByFilter", func(request Request) (bool, interface{}, error) {
		queryTime := 0.1
		traceID := "test-trace-id"
		deviceIDs := []string{"second"}
		total := int64(len(deviceIDs))
		limit := int32(len(deviceIDs))

		response := &hosts.QueryDevicesByFilterOK{
			Payload: &models.MsaQueryResponse{
				Meta: &models.MsaMetaInfo{
					QueryTime:  &queryTime,
					TraceID:    &traceID,
					PoweredBy:  "test-powered-by",
					Pagination: &models.MsaPaging{Total: &total, Limit: &limit},
				},
				Resources: deviceIDs,
			},
		}
		return true, response, nil
	})

	fakeClient.PrependMockHandler("QueryDevicesByFilter", func(request Request) (bool, interface{}, error) {
		queryTime := 0.1
		traceID := "test-trace-id"
		deviceIDs := []string{"first"}
		total := int64(len(deviceIDs))
		limit := int32(len(deviceIDs))

		response := &hosts.QueryDevicesByFilterOK{
			Payload: &models.MsaQueryResponse{
				Meta: &models.MsaMetaInfo{
					QueryTime:  &queryTime,
					TraceID:    &traceID,
					PoweredBy:  "test-powered-by",
					Pagination: &models.MsaPaging{Total: &total, Limit: &limit},
				},
				Resources: deviceIDs,
			},
		}
		return true, response, nil
	})

	client := fakeClient.GetClient()
	result, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"first"}
	if !equalStringSlices(expected, result.Payload.Resources) {
		t.Fatalf("expected resources %v, got %v", expected, result.Payload.Resources)
	}
}

// TestFakeClient_NoMatchingMockHandler verifies the error when no handler matches.
func TestFakeClient_NoMatchingMockHandler(t *testing.T) {
	fakeClient := NewFakeClient()

	client := fakeClient.GetClient()
	_, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})

	if err == nil {
		t.Fatal("expected an error when no mock handler is configured")
	}
	if !strings.Contains(err.Error(), "no mock handler found for operation") {
		t.Fatalf("expected 'no mock handler found' error, got: %v", err)
	}
}

// TestNewFakeClientFromConfig verifies the convenience constructor returns a usable FakeClient.
func TestNewFakeClientFromConfig(t *testing.T) {
	fakeClient := NewFakeClientFromConfig()

	if fakeClient == nil {
		t.Fatal("fakeClient should be properly initialized")
	}

	client := fakeClient.GetClient()
	if client.Hosts == nil {
		t.Fatal("Hosts service should be available")
	}
	if client.Detects == nil {
		t.Fatal("Detects service should be available")
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
