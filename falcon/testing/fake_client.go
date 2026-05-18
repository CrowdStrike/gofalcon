package testing

import (
	"fmt"
	"sync"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// FakeClient provides a fake implementation of the CrowdStrike API client for testing.
// It uses a mock handler pattern similar to Kubernetes' fake client to allow configurable responses.
type FakeClient struct {
	sync.RWMutex

	// requests tracks all API calls made to the fake client
	requests []Request

	// HandlerChain is the list of mock handlers that will be attempted for every
	// request in the order they are tried.
	HandlerChain []MockHandler

	// The underlying CrowdStrike client with fake transport
	client *client.CrowdStrikeAPISpecification
}

// MockHandler is an interface to allow composition of mock response functions for API operations.
type MockHandler interface {
	// Handles indicates whether this MockHandler deals with a given operation.
	Handles(request Request) bool
	// Handle processes the operation and returns results. It may choose to
	// delegate by indicating handled=false.
	Handle(request Request) (handled bool, ret interface{}, err error)
}

// MockHandlerFunc is a function that returns a response for a given Request.
// If "handled" is false, the fake client will continue to the next MockHandlerFunc.
type MockHandlerFunc func(request Request) (handled bool, ret interface{}, err error)

// Request represents an API operation call with its parameters and metadata.
type Request interface {
	// GetOperationID returns the OpenAPI operation ID (e.g., "QueryDevicesByFilter")
	GetOperationID() string
	// GetParams returns the operation parameters
	GetParams() interface{}
	// GetTimestamp returns when the request was created
	GetTimestamp() time.Time
	// DeepCopy creates a copy of the request to avoid mutation
	DeepCopy() Request
}

// RequestImpl provides a basic implementation of the Request interface.
type RequestImpl struct {
	OperationID string
	Params      interface{}
	Timestamp   time.Time
}

func (r RequestImpl) GetOperationID() string  { return r.OperationID }
func (r RequestImpl) GetParams() interface{}  { return r.Params }
func (r RequestImpl) GetTimestamp() time.Time { return r.Timestamp }
func (r RequestImpl) DeepCopy() Request {
	return RequestImpl{
		OperationID: r.OperationID,
		Params:      r.Params, // Note: shallow copy of params
		Timestamp:   r.Timestamp,
	}
}

// SimpleMockHandler provides a basic mock handler implementation that matches operations by ID.
type SimpleMockHandler struct {
	OperationID string
	Handler     MockHandlerFunc
}

func (h *SimpleMockHandler) Handles(request Request) bool {
	return h.OperationID == "*" || h.OperationID == request.GetOperationID()
}

func (h *SimpleMockHandler) Handle(request Request) (bool, interface{}, error) {
	return h.Handler(request)
}

// NewFakeClient creates a new fake CrowdStrike API client for testing.
func NewFakeClient() *FakeClient {
	fc := &FakeClient{
		requests:     []Request{},
		HandlerChain: []MockHandler{},
	}

	// Create the client with fake transport
	transport := &FakeTransport{fakeClient: fc}
	fc.client = client.New(transport, strfmt.Default)

	return fc
}

// NewFakeClientFromConfig creates a fake client that can be used as a drop-in replacement
// for falcon.NewClient(). Call GetClient() to obtain the underlying API client.
func NewFakeClientFromConfig() *FakeClient {
	return NewFakeClient()
}

// GetClient returns the underlying CrowdStrike API client.
func (fc *FakeClient) GetClient() *client.CrowdStrikeAPISpecification {
	return fc.client
}

// AddMockHandler appends a mock handler to the end of the chain.
func (fc *FakeClient) AddMockHandler(operationID string, handler MockHandlerFunc) {
	fc.Lock()
	defer fc.Unlock()
	fc.HandlerChain = append(fc.HandlerChain, &SimpleMockHandler{operationID, handler})
}

// PrependMockHandler adds a mock handler to the beginning of the chain.
func (fc *FakeClient) PrependMockHandler(operationID string, handler MockHandlerFunc) {
	fc.Lock()
	defer fc.Unlock()
	fc.HandlerChain = append([]MockHandler{&SimpleMockHandler{operationID, handler}}, fc.HandlerChain...)
}

// AddStaticMockHandler adds a mock handler that always returns the same static response.
func (fc *FakeClient) AddStaticMockHandler(operationID string, response interface{}) {
	fc.AddMockHandler(operationID, func(request Request) (bool, interface{}, error) {
		return true, response, nil
	})
}

// AddErrorMockHandler adds a mock handler that always returns the specified error.
func (fc *FakeClient) AddErrorMockHandler(operationID string, err error) {
	fc.AddMockHandler(operationID, func(request Request) (bool, interface{}, error) {
		return true, nil, err
	})
}

// ProcessRequest processes an API operation through the mock handler chain.
// This is called by the FakeTransport when API operations are executed.
func (fc *FakeClient) ProcessRequest(request Request, defaultReturnObj interface{}) (interface{}, error) {
	fc.Lock()
	fc.requests = append(fc.requests, request.DeepCopy())
	handlers := make([]MockHandler, len(fc.HandlerChain))
	copy(handlers, fc.HandlerChain)
	fc.Unlock()

	for _, handler := range handlers {
		if !handler.Handles(request) {
			continue
		}

		handled, ret, err := handler.Handle(request)
		if !handled {
			continue
		}

		return ret, err
	}

	if defaultReturnObj != nil {
		return defaultReturnObj, nil
	}

	return nil, fmt.Errorf("no mock handler found for operation: %s", request.GetOperationID())
}

// Requests returns a chronologically ordered slice of requests called on the fake client.
func (fc *FakeClient) Requests() []Request {
	fc.RLock()
	defer fc.RUnlock()
	requests := make([]Request, len(fc.requests))
	copy(requests, fc.requests)
	return requests
}

// ClearRequests clears the history of requests called on the fake client.
func (fc *FakeClient) ClearRequests() {
	fc.Lock()
	defer fc.Unlock()
	fc.requests = []Request{}
}

// FilterRequests returns requests that match the specified operation ID.
func (fc *FakeClient) FilterRequests(operationID string) []Request {
	fc.RLock()
	defer fc.RUnlock()

	var filtered []Request
	for _, request := range fc.requests {
		if request.GetOperationID() == operationID {
			filtered = append(filtered, request)
		}
	}
	return filtered
}

// CountRequests returns the number of requests matching the specified operation ID.
func (fc *FakeClient) CountRequests(operationID string) int {
	fc.RLock()
	defer fc.RUnlock()

	count := 0
	for _, request := range fc.requests {
		if request.GetOperationID() == operationID {
			count++
		}
	}
	return count
}

// SetDefaultHandler sets a catch-all handler that matches any operation not handled
// by more specific handlers. It appends to the end of the handler chain.
func (fc *FakeClient) SetDefaultHandler(handler MockHandlerFunc) {
	fc.AddMockHandler("*", handler)
}

// Reset clears all requests and mock handlers, returning the client to initial state.
func (fc *FakeClient) Reset() {
	fc.Lock()
	defer fc.Unlock()
	fc.requests = []Request{}
	fc.HandlerChain = []MockHandler{}
}

// FakeTransport implements runtime.ClientTransport for the fake client.
// It intercepts all API operations and routes them through the fake client's mock handler chain.
type FakeTransport struct {
	fakeClient *FakeClient
}

// Submit implements runtime.ClientTransport.Submit().
func (ft *FakeTransport) Submit(op *runtime.ClientOperation) (interface{}, error) {
	// Create a request from the operation
	request := RequestImpl{
		OperationID: op.ID,
		Params:      op.Params,
		Timestamp:   time.Now(),
	}

	// Process through the fake client
	return ft.fakeClient.ProcessRequest(request, nil)
}

// NewRequest creates a new Request for testing purposes.
func NewRequest(operationID string, params interface{}) Request {
	return RequestImpl{
		OperationID: operationID,
		Params:      params,
		Timestamp:   time.Now(),
	}
}

// MatchesOperation returns true if the request matches the specified operation ID.
func MatchesOperation(request Request, operationID string) bool {
	return request.GetOperationID() == operationID
}

// GetParamsAs attempts to cast the request's parameters to the specified type.
// This is a helper for mock handlers that need to inspect parameters.
func GetParamsAs[T any](request Request) (*T, bool) {
	if params, ok := request.GetParams().(*T); ok {
		return params, true
	}
	return nil, false
}

// GenerateDeviceIDs generates a slice of deterministic device IDs for testing.
// IDs are 32-character lowercase hex strings resembling real CrowdStrike device IDs.
func GenerateDeviceIDs(count int) []string {
	ids := make([]string, count)
	for i := 0; i < count; i++ {
		ids[i] = fmt.Sprintf("d%031x", i+1)
	}
	return ids
}

// GenerateDetectionIDs generates a slice of deterministic detection IDs for testing.
// IDs are 32-character lowercase hex strings resembling real CrowdStrike detection IDs.
func GenerateDetectionIDs(count int) []string {
	ids := make([]string, count)
	for i := 0; i < count; i++ {
		ids[i] = fmt.Sprintf("a%031x", i+1)
	}
	return ids
}
