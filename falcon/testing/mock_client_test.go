package testing

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestNewMockClient(t *testing.T) {
	t.Parallel()

	mc := NewMockClient()
	if mc == nil {
		t.Fatal("NewMockClient() returned nil")
	}
	if mc.Hosts == nil {
		t.Fatal("Hosts service should be wired")
	}
	if mc.Detects == nil {
		t.Fatal("Detects service should be wired")
	}
}

func TestNewMockClient_PanicsOnUnconfiguredCall(t *testing.T) {
	t.Parallel()

	mc := NewMockClient()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on unconfigured service call")
		}
	}()

	mc.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
}

func TestNewMockClient_ReplacedServiceWorks(t *testing.T) {
	t.Parallel()

	mc := NewMockClient()

	mc.Hosts = &mockHostsForTest{
		queryFunc: func(_ *hosts.QueryDevicesByFilterParams, _ ...hosts.ClientOption) (*hosts.QueryDevicesByFilterOK, error) {
			return &hosts.QueryDevicesByFilterOK{
				Payload: &models.MsaQueryResponse{Resources: []string{"dev-1"}},
			}, nil
		},
	}

	result, err := mc.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Payload.Resources) != 1 {
		t.Fatalf("expected 1 device, got %d", len(result.Payload.Resources))
	}
}

// mockHostsForTest demonstrates the interface mocking pattern inline.
type mockHostsForTest struct {
	hosts.ClientService
	queryFunc func(params *hosts.QueryDevicesByFilterParams, opts ...hosts.ClientOption) (*hosts.QueryDevicesByFilterOK, error)
}

func (m *mockHostsForTest) QueryDevicesByFilter(params *hosts.QueryDevicesByFilterParams, opts ...hosts.ClientOption) (*hosts.QueryDevicesByFilterOK, error) {
	return m.queryFunc(params, opts...)
}
