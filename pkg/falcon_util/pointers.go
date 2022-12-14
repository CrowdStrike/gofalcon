package falcon_util

// DerefInt returns the deferenced int32 value or 0 if nil.
func DerefInt32(i *int32) int32 {
	if i != nil {
		return *i
	}
	return int32(0)
}

// DerefString returns the deferenced string value or empty string if nil.
func DerefString(s *string) string {
	if s != nil {
		return *s
	}

	return ""
}

// StrPtr creates a string pointer from a string literal, for APIs that require pointers rather than values.
func StrPtr(s string) *string {
	return &s
}
