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
