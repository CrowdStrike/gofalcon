package falcon_util

import (
	"bytes"
	"encoding/json"
)

// PrettyJson converts given interface to prettified json. Useful for debugging.
func PrettyJson(obj interface{}) (string, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetIndent("", "    ")
	if err := enc.Encode(obj); err != nil {
		return "", err
	}
	return out.String(), nil
}

// StringOrNumber is a string-backed type for JSON fields that a service may encode as
// either a JSON number or a JSON string. The gateway fronting the cloud-security
// endpoints returns an error "code" as a number (e.g. 403), while the service itself
// returns arbitrary string codes (e.g. "NotFound", "name"). Both decode into the string
// form, and the value always re-encodes as a JSON string.
type StringOrNumber string

// UnmarshalJSON decodes a JSON string or number into the underlying string. A quoted
// token is unquoted; any other scalar (such as a number) is stored verbatim. A JSON null
// leaves the value unchanged.
func (s *StringOrNumber) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		*s = StringOrNumber(str)
		return nil
	}
	*s = StringOrNumber(data)
	return nil
}

// MarshalJSON encodes the value as a JSON string so the model round-trips regardless of
// whether the value originated as a number or a string.
func (s StringOrNumber) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}
