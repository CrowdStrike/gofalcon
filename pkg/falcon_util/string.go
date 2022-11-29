package falcon_util

// DerefString returns the deferenced string value or empty string if nil.
func DerefString(s *string) string {
	if s != nil {
		return *s
	}

	return ""
}
