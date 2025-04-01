package falcon

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"golang.org/x/oauth2"
)

// AssertNoError converts MsaAPIError to golang errors.
// Falcon API oftentimes returns payload structure that may include application errors within MsaAPIError list.
// For the users of the API it is often times desirable to convert the application errors from CrowdStrike platform to golang native errors to inform application flow.
func AssertNoError(payloadErrors []*models.MsaAPIError) error {
	if len(payloadErrors) == 0 {
		return nil
	}
	var sb strings.Builder

	for _, payloadError := range payloadErrors {
		sb.WriteString("API Error " + payloadError.ID + ": " + *payloadError.Message)
	}
	return errors.New(sb.String())
}

// ErrorExplain extracts as much information from the error object as possible and returns as human readable string. This is useful for developers as gofalcon/falcon/client library is swagger generated and various error classes do not adhere to a common interface.
func ErrorExplain(apiError error) string {
	if urlError, ok := apiError.(*url.Error); ok {
		cause := urlError.Unwrap()
		if _, ok := cause.(*oauth2.RetrieveError); ok {
			return apiError.Error()
		}
	}

	explained := tryErrorExplain(apiError)
	if explained != "" {
		return explained
	}
	return fmt.Sprintf("%v", apiError)
}

// CommonPayload is interface for *Payload structures in the gofalcon/falcon/client library.
type CommonPayload interface {
	MarshalBinary() ([]byte, error)
}

// ErrorExtractPayload pops out a .Payload member from the API Error (if included).
func ErrorExtractPayload(apiError error) CommonPayload {
	errorValue := reflect.ValueOf(apiError)
	if errorValue.Kind() != reflect.Interface && errorValue.Kind() != reflect.Ptr {
		// Not ours error
		return nil
	}
	errorStruct := errorValue.Elem()
	payloadValue := errorStruct.FieldByName("Payload")
	if !payloadValue.IsValid() {
		return nil
	}
	if !payloadValue.CanInterface() {
		// This error struct does not have 'Payload' member
		return nil
	}
	payload := payloadValue.Interface()
	casted, ok := payload.(CommonPayload)
	if !ok {
		// Cannot be casted
		return nil
	}
	return casted
}

func tryErrorExplain(apiError error) string {
	payload := ErrorExtractPayload(apiError)
	if payload == nil {
		return ""
	}
	bytes, err := payload.MarshalBinary()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%v\n[BODY %s]", apiError, string(bytes))
}
