package streaming_models

import (
	"encoding/json"
	"fmt"
	"strconv"
)

type IntOrString uint64

func (st *IntOrString) UnmarshalJSON(b []byte) error {
	var item interface{}
	if err := json.Unmarshal(b, &item); err != nil {
		return err
	}

	switch v := item.(type) {
	case uint64:
		*st = IntOrString(v)
	case float64:
		*st = IntOrString(uint64(v))
	case string:
		i := uint64(0)
		if v != "" {
			var err error
			i, err = strconv.ParseUint(v, 10, 0)
			if err != nil {
				return err
			}
		}
		*st = IntOrString(i)
	default:
		return fmt.Errorf("Not implemented: Cannot parse: %v (type %T) to IntOrString", item, item)
	}
	return nil
}

// String provides a more flexible representation than IntOrString, where:
// 1. It can store arbitrary string values (not just numbers)
// 2. Unlike IntOrString which requires numeric strings and fails on arbitrary text
// 3. It preserves the original format in string form
//
// This is particularly useful for fields like IncidentType which can be:
// - An integer (e.g. 1)
// - A string containing an integer (e.g. "1")
// - A descriptive string (e.g. "malware-detection")
//
// Since it tries to follow IntOrString's behavior, it converts float64 values to uint64.
//
// All values are stored and output as strings in JSON.
type String string

// UnmarshalJSON implements the json.Unmarshaler interface
func (s *String) UnmarshalJSON(b []byte) error {
	var item interface{}
	if err := json.Unmarshal(b, &item); err != nil {
		return err
	}

	switch v := item.(type) {
	case uint64:
		*s = String(fmt.Sprintf("%d", v))
	case float64:
		*s = String(fmt.Sprintf("%d", uint64(v)))
	case string:
		*s = String(v)
	default:
		return fmt.Errorf("Cannot parse: %v (type %T) to String", item, item)
	}
	return nil
}
