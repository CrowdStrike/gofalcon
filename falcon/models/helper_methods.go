package models

import (
	"fmt"
)

func (m *MsaAPIError) String() string {
	msg := "{"

	if m.Code != nil {
		msg += fmt.Sprintf("Code:%+v ", *m.Code)
	}
	if m.ID != "" {
		msg += fmt.Sprintf("ID:%+v ", m.ID)
	}
	if m.Message != nil {
		msg += fmt.Sprintf("Message:%+v", *m.Message)
	}
	return msg + "}"
}

func (m *MsaMetaInfo) String() string {
	msg := fmt.Sprintf("PoweredBy:%+v ", m.PoweredBy)
	if m.Pagination != nil {
		msg += fmt.Sprintf("Pagination:%+v ", *m.Pagination)
	}
	if m.QueryTime != nil {
		msg += fmt.Sprintf("QueryTime:%+v ", *m.QueryTime)
	}
	if m.Writes != nil {
		msg += fmt.Sprintf("Writes:%+v ", *m.Writes)
	}
	if m.TraceID != nil {
		msg += fmt.Sprintf("TraceID:%+v", *m.TraceID)
	}
	return msg + "}"
}
