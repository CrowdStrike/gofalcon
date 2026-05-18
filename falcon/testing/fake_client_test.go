package testing

import (
	"sync"
	"testing"
)

func TestProcessRequest_NoDeadlockOnReentrantCall(t *testing.T) {
	fakeClient := NewFakeClient()

	fakeClient.AddMockHandler("OuterOp", func(request Request) (bool, interface{}, error) {
		// This would deadlock with the old lock-during-handler implementation
		_ = fakeClient.Requests()
		return true, "outer-result", nil
	})

	result, err := fakeClient.ProcessRequest(NewRequest("OuterOp", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "outer-result" {
		t.Fatalf("expected 'outer-result', got %v", result)
	}
}

func TestProcessRequest_ConcurrentSafety(t *testing.T) {
	fakeClient := NewFakeClient()

	fakeClient.AddMockHandler("ConcurrentOp", func(request Request) (bool, interface{}, error) {
		return true, "ok", nil
	})

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := fakeClient.ProcessRequest(NewRequest("ConcurrentOp", nil), nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if len(fakeClient.Requests()) != 50 {
		t.Fatalf("expected 50 requests, got %d", len(fakeClient.Requests()))
	}
}

func TestCountRequests(t *testing.T) {
	fakeClient := NewFakeClient()

	fakeClient.SetDefaultHandler(func(request Request) (bool, interface{}, error) {
		return true, "ok", nil
	})

	fakeClient.ProcessRequest(NewRequest("OpA", nil), nil)
	fakeClient.ProcessRequest(NewRequest("OpA", nil), nil)
	fakeClient.ProcessRequest(NewRequest("OpB", nil), nil)

	if got := fakeClient.CountRequests("OpA"); got != 2 {
		t.Fatalf("expected 2 OpA requests, got %d", got)
	}
	if got := fakeClient.CountRequests("OpB"); got != 1 {
		t.Fatalf("expected 1 OpB request, got %d", got)
	}
	if got := fakeClient.CountRequests("OpC"); got != 0 {
		t.Fatalf("expected 0 OpC requests, got %d", got)
	}
}

func TestSetDefaultHandler(t *testing.T) {
	fakeClient := NewFakeClient()

	fakeClient.SetDefaultHandler(func(request Request) (bool, interface{}, error) {
		return true, "default-response", nil
	})

	result, err := fakeClient.ProcessRequest(NewRequest("AnyOperation", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "default-response" {
		t.Fatalf("expected 'default-response', got %v", result)
	}

	result, err = fakeClient.ProcessRequest(NewRequest("AnotherOperation", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "default-response" {
		t.Fatalf("expected 'default-response', got %v", result)
	}
}

func TestSetDefaultHandler_SpecificHandlerTakesPrecedence(t *testing.T) {
	fakeClient := NewFakeClient()

	fakeClient.AddMockHandler("SpecificOp", func(request Request) (bool, interface{}, error) {
		return true, "specific-response", nil
	})
	fakeClient.SetDefaultHandler(func(request Request) (bool, interface{}, error) {
		return true, "default-response", nil
	})

	result, err := fakeClient.ProcessRequest(NewRequest("SpecificOp", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "specific-response" {
		t.Fatalf("expected 'specific-response', got %v", result)
	}

	result, err = fakeClient.ProcessRequest(NewRequest("OtherOp", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "default-response" {
		t.Fatalf("expected 'default-response', got %v", result)
	}
}

func TestGenerateDeviceIDs_Format(t *testing.T) {
	ids := GenerateDeviceIDs(3)

	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs, got %d", len(ids))
	}
	for i, id := range ids {
		if len(id) != 32 {
			t.Fatalf("ID %d: expected 32 chars, got %d (%q)", i, len(id), id)
		}
		if id[0] != 'd' {
			t.Fatalf("ID %d: expected 'd' prefix, got %q", i, id)
		}
	}

	if ids[0] == ids[1] {
		t.Fatal("IDs should be unique")
	}
}

func TestGenerateDetectionIDs_Format(t *testing.T) {
	ids := GenerateDetectionIDs(3)

	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs, got %d", len(ids))
	}
	for i, id := range ids {
		if len(id) != 32 {
			t.Fatalf("ID %d: expected 32 chars, got %d (%q)", i, len(id), id)
		}
		if id[0] != 'a' {
			t.Fatalf("ID %d: expected 'a' prefix, got %q", i, id)
		}
	}

	if ids[0] == ids[1] {
		t.Fatal("IDs should be unique")
	}
}
