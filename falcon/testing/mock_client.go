package testing

import (
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// panicTransport implements runtime.ClientTransport and panics with a clear message
// when any unconfigured service method is called.
type panicTransport struct{}

// Submit panics with the operation ID to surface unconfigured mock calls clearly.
func (t *panicTransport) Submit(op *runtime.ClientOperation) (interface{}, error) {
	panic(fmt.Sprintf("mock client: no mock configured for operation %q — replace the service field with your own interface mock", op.ID))
}

// NewMockClient returns a fully-wired CrowdStrikeAPISpecification where every service
// panics with a clear message if called without being replaced. Swap individual service
// fields with your own ClientService interface mocks for the services under test.
//
// Example:
//
//	mc := faketest.NewMockClient()
//	mc.Hosts = &myMockHosts{...}  // only mock what you test
//	result, err := mc.Hosts.QueryDevicesByFilter(params)
func NewMockClient() *client.CrowdStrikeAPISpecification {
	return client.New(&panicTransport{}, strfmt.Default)
}
