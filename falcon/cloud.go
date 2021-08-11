package falcon

import (
	"fmt"
	"strings"
)

// CloudType represents type of CrowdStrike Falcon cloud region.
type CloudType int

const (
	CloudUs1 = iota
	CloudUs2
	CloudEu1
	CloudUsGov1
)

// Cloud parses clould string (example: us-1, us-2, eu-1, us-gov-1, etc). If a string is not recognised CloudUs1 is returned.
func Cloud(cloudString string) CloudType {
	c, _ := CloudValidate(cloudString)
	return c
}

// CloudValidate parses cloud string (example: us-1, us-2, eu-1, us-gov-1, etc.). Error is returned when string cannot be recognised
func CloudValidate(cloudString string) (CloudType, error) {
	trimmed := strings.TrimSpace(cloudString)
	lower := strings.ToLower(trimmed)
	switch lower {
	case "us-1":
		return CloudUs1, nil
	case "us-2":
		return CloudUs2, nil
	case "eu-1":
		return CloudEu1, nil
	case "us-gov-1":
		return CloudUsGov1, nil
	}
	return CloudUs1, fmt.Errorf("unrecognized CrowdStrike Falcon Cloud: %s", lower)
}

// Host returns default hostname for given cloud.
func (c CloudType) Host() string {
	switch c {
	default:
		fallthrough
	case CloudUs1:
		return "api.crowdstrike.com"
	case CloudUs2:
		return "api.us-2.crowdstrike.com"
	case CloudEu1:
		return "api.eu-1.crowdstrike.com"
	case CloudUsGov1:
		return "api.laggar.gcw.crowdstrike.com"
	}
}
