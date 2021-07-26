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
		i, err := strconv.ParseUint(v, 10, 0)
		if err != nil {
			return err
		}
		*st = IntOrString(i)
	default:
		return fmt.Errorf("Not implemented: Cannot parse: %v (type %T) to IntOrString", item, item)
	}
	return nil
}
