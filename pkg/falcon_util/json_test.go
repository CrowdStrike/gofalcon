package falcon_util

import (
	"encoding/json"
	"testing"
)

func TestStringOrNumberUnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  StringOrNumber
	}{
		{name: "numeric code from gateway", input: `403`, want: "403"},
		{name: "numeric string code", input: `"400"`, want: "400"},
		{name: "alphabetic string code", input: `"name"`, want: "name"},
		{name: "named string code", input: `"NotFound"`, want: "NotFound"},
		{name: "empty string code", input: `""`, want: ""},
		{name: "json null leaves value unchanged", input: `null`, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got StringOrNumber
			if err := json.Unmarshal([]byte(tt.input), &got); err != nil {
				t.Fatalf("Unmarshal(%s) returned error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("Unmarshal(%s) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestStringOrNumberMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input StringOrNumber
		want  string
	}{
		{name: "numeric-looking value encodes as string", input: "403", want: `"403"`},
		{name: "named value encodes as string", input: "NotFound", want: `"NotFound"`},
		{name: "empty value encodes as empty string", input: "", want: `""`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("Marshal(%q) returned error: %v", tt.input, err)
			}
			if string(got) != tt.want {
				t.Errorf("Marshal(%q) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestStringOrNumberRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "numeric decodes then re-encodes as string", input: `403`, want: `"403"`},
		{name: "string round-trips unchanged", input: `"NotFound"`, want: `"NotFound"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var decoded StringOrNumber
			if err := json.Unmarshal([]byte(tt.input), &decoded); err != nil {
				t.Fatalf("Unmarshal(%s) returned error: %v", tt.input, err)
			}
			got, err := json.Marshal(decoded)
			if err != nil {
				t.Fatalf("Marshal(%q) returned error: %v", decoded, err)
			}
			if string(got) != tt.want {
				t.Errorf("round-trip of %s = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}
