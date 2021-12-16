package models

import (
	"fmt"
)

// LastPage returns true when there are more pages
func (p *MsaPaging) LastPage() (bool, error) {
	if p.Limit == nil || p.Offset == nil || p.Total == nil {
		return true, fmt.Errorf("Pagination info corrupted: %v", p)
	} else if *p.Total < int64(*p.Offset) {
		return true, fmt.Errorf("Pagination info corrupted: Total(%d) < Offset(%d)", *p.Total, *p.Offset)
	} else {
		return (*p.Total - int64(*p.Offset)) <= int64(*p.Limit), nil
	}
}
