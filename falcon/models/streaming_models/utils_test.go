package streaming_models

import (
	"encoding/json"
	"testing"
)

type StringTest struct {
	Value *String `json:"value,omitempty"`
}

func TestString(t *testing.T) {
	testCases := []struct {
		name           string
		jsonData       string
		expectedOutput string
	}{
		{
			name:           "Integer value",
			jsonData:       `{"value": 42}`,
			expectedOutput: `{"value":"42"}`,
		},
		{
			name:           "String integer value",
			jsonData:       `{"value": "99"}`,
			expectedOutput: `{"value":"99"}`,
		},
		{
			name:           "Empty string",
			jsonData:       `{"value": ""}`,
			expectedOutput: `{"value":""}`,
		},
		{
			name:           "Arbitrary string",
			jsonData:       `{"value": "malware-detection"}`,
			expectedOutput: `{"value":"malware-detection"}`,
		},
		{
			name:           "Float value",
			jsonData:       `{"value": 123.45}`,
			expectedOutput: `{"value":"123"}`,
		},
		{
			name:           "Null value",
			jsonData:       `{"value": null}`,
			expectedOutput: `{}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test unmarshaling
			var test StringTest
			err := json.Unmarshal([]byte(tc.jsonData), &test)
			if err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			// Test marshaling
			marshaled, err := json.Marshal(test)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}

			if string(marshaled) != tc.expectedOutput {
				t.Errorf("Expected marshaled output to be %q, got %q", tc.expectedOutput, string(marshaled))
			}
		})
	}
}
