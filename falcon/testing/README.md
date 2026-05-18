# GoFalcon Testing Framework

This package provides a fake client for testing GoFalcon applications without API credentials or network calls.

## Overview

The fake client uses a mock handler pattern (inspired by Kubernetes' fake client) to intercept API operations at the transport layer and route them through configurable handlers.

## Key Features

- **Mock Handler Chain**: Configure responses per operation, with precedence control
- **Request Tracking**: Record and verify all API calls
- **Thread-Safe**: Safe for concurrent testing
- **Type-Safe**: Uses the same generated OpenAPI types as the real client
- **Default Handlers**: Catch-all wildcard handlers for unmatched operations
- **Zero Dependencies**: No network calls or credentials needed

## Quick Start

```go
package myapp_test

import (
    "testing"
    faketest "github.com/crowdstrike/gofalcon/falcon/testing"
    "github.com/crowdstrike/gofalcon/falcon/client/hosts"
    "github.com/crowdstrike/gofalcon/falcon/models"
)

func TestMyApplication(t *testing.T) {
    fakeClient := faketest.NewFakeClient()
    deviceIDs := faketest.GenerateDeviceIDs(3)

    fakeClient.AddMockHandler("QueryDevicesByFilter", func(request faketest.Request) (bool, interface{}, error) {
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

    client := fakeClient.GetClient()
    result, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    // result.Payload.Resources == deviceIDs
}
```

### Drop-in Replacement

```go
// Instead of:
// client, err := falcon.NewClient(&falcon.ApiConfig{...})

// Use:
fakeClient := faketest.NewFakeClientFromConfig()
fakeClient.AddMockHandler("QueryDevicesByFilter", myHandler)
client := fakeClient.GetClient()
```

## API Reference

### Constructors

| Function | Returns | Description |
|----------|---------|-------------|
| `NewFakeClient()` | `*FakeClient` | Create a new fake client |
| `NewFakeClientFromConfig()` | `*FakeClient` | Convenience constructor (same as `NewFakeClient`) |

### Handler Configuration

| Method | Description |
|--------|-------------|
| `AddMockHandler(operationID, handler)` | Append handler to chain |
| `PrependMockHandler(operationID, handler)` | Prepend handler (higher priority) |
| `AddStaticMockHandler(operationID, response)` | Always return the same response |
| `AddErrorMockHandler(operationID, err)` | Always return an error |
| `SetDefaultHandler(handler)` | Catch-all for unmatched operations (uses `"*"` wildcard) |

### Request Tracking

| Method | Description |
|--------|-------------|
| `Requests() []Request` | All recorded requests (chronological) |
| `FilterRequests(operationID) []Request` | Requests matching an operation ID |
| `CountRequests(operationID) int` | Count of requests matching an operation ID |
| `ClearRequests()` | Clear request history |
| `Reset()` | Clear both requests and handlers |

### Utility Functions

| Function | Description |
|----------|-------------|
| `GenerateDeviceIDs(count)` | Deterministic 32-char hex IDs with `d` prefix |
| `GenerateDetectionIDs(count)` | Deterministic 32-char hex IDs with `a` prefix |
| `GetParamsAs[T](request)` | Type-safe parameter extraction |
| `MatchesOperation(request, operationID)` | Check if request matches operation |
| `NewRequest(operationID, params)` | Create a Request for testing |

### ID Format

Generated IDs are 32-character lowercase hex strings:
```go
faketest.GenerateDeviceIDs(2)    // ["d0000000000000000000000000000001", "d0000000000000000000000000000002"]
faketest.GenerateDetectionIDs(2) // ["a0000000000000000000000000000001", "a0000000000000000000000000000002"]
```

## Mock Handler Patterns

### Parameter Inspection

```go
fakeClient.AddMockHandler("QueryDevicesByFilter", func(request faketest.Request) (bool, interface{}, error) {
    if params, ok := faketest.GetParamsAs[hosts.QueryDevicesByFilterParams](request); ok {
        if params.Filter != nil && strings.Contains(*params.Filter, "critical") {
            return true, criticalResponse, nil
        }
    }
    return true, defaultResponse, nil
})
```

### Handler Precedence

Handlers are tried in chain order. `PrependMockHandler` adds to the front (higher priority).
A handler returning `(false, nil, nil)` declines and falls through to the next handler:

```go
// General handler returns all devices
fakeClient.AddMockHandler("QueryDevicesByFilter", func(request faketest.Request) (bool, interface{}, error) {
    return true, allDevicesResponse, nil
})

// Override: when called with a Windows filter, return filtered results
fakeClient.PrependMockHandler("QueryDevicesByFilter", func(request faketest.Request) (bool, interface{}, error) {
    params, ok := faketest.GetParamsAs[hosts.QueryDevicesByFilterParams](request)
    if ok && params.Filter != nil && strings.Contains(*params.Filter, "platform_name:'Windows'") {
        return true, windowsOnlyResponse, nil
    }
    return false, nil, nil // not handled, fall through to next handler
})
```

### Default/Catch-All Handler

```go
// Fail-fast: surface unexpected API calls as test failures
fakeClient.SetDefaultHandler(func(request faketest.Request) (bool, interface{}, error) {
    return true, nil, fmt.Errorf("unexpected operation: %s", request.GetOperationID())
})

// Permissive: return nil for any unhandled operation (useful during exploratory testing)
fakeClient.SetDefaultHandler(func(request faketest.Request) (bool, interface{}, error) {
    return true, nil, nil
})
```

### Error Simulation

```go
fakeClient.AddErrorMockHandler("QueryDevicesByFilter", errors.New("rate limit exceeded"))
```

## Request Verification

```go
client.Hosts.QueryDevicesByFilter(params)
client.Hosts.GetDeviceDetailsV2(params)

// Verify call count
if fakeClient.CountRequests("QueryDevicesByFilter") != 1 {
    t.Fatal("expected exactly 1 query call")
}

// Verify call order
requests := fakeClient.Requests()
if requests[0].GetOperationID() != "QueryDevicesByFilter" {
    t.Fatal("expected query first")
}
```

## Thread Safety

The fake client is safe for concurrent use. Handlers execute outside the internal lock, so handlers may safely call `Requests()`, `CountRequests()`, or other FakeClient methods without deadlocking.

## Examples

See `example_test.go` for working examples of all features.

## Interface Mocking

In addition to the fake client (which intercepts at the transport layer), you can mock individual services at the interface level. Each generated service package exports a `ClientService` interface, and the top-level `*client.CrowdStrikeAPISpecification` struct holds services as interface-typed fields.

This lets you write focused unit tests that depend only on the methods you call, with no handler chain setup.

### How It Works

1. Define a mock struct that embeds the `ClientService` interface (satisfies methods you don't call)
2. Override only the methods your code uses
3. Pass the mock to your application code via the interface

### Example: Mocking the Hosts Service

```go
package myapp_test

import (
    "testing"

    "github.com/crowdstrike/gofalcon/falcon/client/hosts"
    "github.com/crowdstrike/gofalcon/falcon/models"
)

// mockHosts implements hosts.ClientService — only override what you need.
type mockHosts struct {
    hosts.ClientService // embedded interface covers methods you don't call
    QueryDevicesByFilterFunc func(params *hosts.QueryDevicesByFilterParams, opts ...hosts.ClientOption) (*hosts.QueryDevicesByFilterOK, error)
}

func (m *mockHosts) QueryDevicesByFilter(params *hosts.QueryDevicesByFilterParams, opts ...hosts.ClientOption) (*hosts.QueryDevicesByFilterOK, error) {
    return m.QueryDevicesByFilterFunc(params, opts...)
}

func TestListDevices(t *testing.T) {
    mock := &mockHosts{
        QueryDevicesByFilterFunc: func(_ *hosts.QueryDevicesByFilterParams, _ ...hosts.ClientOption) (*hosts.QueryDevicesByFilterOK, error) {
            return &hosts.QueryDevicesByFilterOK{
                Payload: &models.MsaQueryResponse{
                    Resources: []string{"device-1", "device-2"},
                },
            }, nil
        },
    }

    // Pass mock to your application code that accepts hosts.ClientService
    devices, err := listDevices(mock)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(devices) != 2 {
        t.Fatalf("expected 2 devices, got %d", len(devices))
    }
}

// Your application code accepts the interface, not the concrete client
func listDevices(client hosts.ClientService) ([]string, error) {
    resp, err := client.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
    if err != nil {
        return nil, err
    }
    return resp.Payload.Resources, nil
}
```

### Injecting Into the Full Client

Use `NewMockClient()` to get a fully-wired client where every service panics with a clear message if called without being replaced. Then swap in your mock for the service under test:

```go
import (
    faketest "github.com/crowdstrike/gofalcon/falcon/testing"
)

func TestWithFullClient(t *testing.T) {
    mock := &mockHosts{
        QueryDevicesByFilterFunc: func(_ *hosts.QueryDevicesByFilterParams, _ ...hosts.ClientOption) (*hosts.QueryDevicesByFilterOK, error) {
            return &hosts.QueryDevicesByFilterOK{
                Payload: &models.MsaQueryResponse{Resources: []string{"dev-1"}},
            }, nil
        },
    }

    // All services wired — unconfigured ones panic with a helpful message
    apiClient := faketest.NewMockClient()
    apiClient.Hosts = mock

    result, err := apiClient.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
    // ...
}
```

### When to Use Which Approach

| Approach | Best For |
|----------|----------|
| **FakeClient** (transport-level) | Testing code that uses `*client.CrowdStrikeAPISpecification` with many services, full request tracking, handler chaining |
| **Interface mock** (service-level) | Unit testing code that depends on a single `ClientService` interface, minimal setup, compile-time method signature safety |

### Available Interfaces

Every service package exports a `ClientService` interface. Common ones:

- `github.com/crowdstrike/gofalcon/falcon/client/hosts.ClientService`
- `github.com/crowdstrike/gofalcon/falcon/client/detects.ClientService`
- `github.com/crowdstrike/gofalcon/falcon/client/incidents.ClientService`
- `github.com/crowdstrike/gofalcon/falcon/client/alerts.ClientService`
- `github.com/crowdstrike/gofalcon/falcon/client/ioc.ClientService`

See any service package's `*_client.go` file for its full interface definition.

## Architecture

The fake client implements `runtime.ClientTransport` (the same interface the real HTTP transport uses). When any generated service method is called, it routes through `FakeTransport.Submit()` → `FakeClient.ProcessRequest()` → handler chain. This makes it a true drop-in replacement with zero code changes to application logic.
