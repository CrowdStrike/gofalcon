// Code generated by go-swagger; DO NOT EDIT.

package hosts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// QueryDeviceLoginHistoryV2Reader is a Reader for the QueryDeviceLoginHistoryV2 structure.
type QueryDeviceLoginHistoryV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryDeviceLoginHistoryV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryDeviceLoginHistoryV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewQueryDeviceLoginHistoryV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryDeviceLoginHistoryV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /devices/combined/devices/login-history/v2] QueryDeviceLoginHistoryV2", response, response.Code())
	}
}

// NewQueryDeviceLoginHistoryV2OK creates a QueryDeviceLoginHistoryV2OK with default headers values
func NewQueryDeviceLoginHistoryV2OK() *QueryDeviceLoginHistoryV2OK {
	return &QueryDeviceLoginHistoryV2OK{}
}

/*
QueryDeviceLoginHistoryV2OK describes a response with status code 200, with default header values.

OK
*/
type QueryDeviceLoginHistoryV2OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DeviceapiLoginHistoryResponseV1
}

// IsSuccess returns true when this query device login history v2 o k response has a 2xx status code
func (o *QueryDeviceLoginHistoryV2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query device login history v2 o k response has a 3xx status code
func (o *QueryDeviceLoginHistoryV2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query device login history v2 o k response has a 4xx status code
func (o *QueryDeviceLoginHistoryV2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query device login history v2 o k response has a 5xx status code
func (o *QueryDeviceLoginHistoryV2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this query device login history v2 o k response a status code equal to that given
func (o *QueryDeviceLoginHistoryV2OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query device login history v2 o k response
func (o *QueryDeviceLoginHistoryV2OK) Code() int {
	return 200
}

func (o *QueryDeviceLoginHistoryV2OK) Error() string {
	return fmt.Sprintf("[POST /devices/combined/devices/login-history/v2][%d] queryDeviceLoginHistoryV2OK  %+v", 200, o.Payload)
}

func (o *QueryDeviceLoginHistoryV2OK) String() string {
	return fmt.Sprintf("[POST /devices/combined/devices/login-history/v2][%d] queryDeviceLoginHistoryV2OK  %+v", 200, o.Payload)
}

func (o *QueryDeviceLoginHistoryV2OK) GetPayload() *models.DeviceapiLoginHistoryResponseV1 {
	return o.Payload
}

func (o *QueryDeviceLoginHistoryV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	o.Payload = new(models.DeviceapiLoginHistoryResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryDeviceLoginHistoryV2Forbidden creates a QueryDeviceLoginHistoryV2Forbidden with default headers values
func NewQueryDeviceLoginHistoryV2Forbidden() *QueryDeviceLoginHistoryV2Forbidden {
	return &QueryDeviceLoginHistoryV2Forbidden{}
}

/*
QueryDeviceLoginHistoryV2Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryDeviceLoginHistoryV2Forbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaReplyMetaOnly
}

// IsSuccess returns true when this query device login history v2 forbidden response has a 2xx status code
func (o *QueryDeviceLoginHistoryV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query device login history v2 forbidden response has a 3xx status code
func (o *QueryDeviceLoginHistoryV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query device login history v2 forbidden response has a 4xx status code
func (o *QueryDeviceLoginHistoryV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query device login history v2 forbidden response has a 5xx status code
func (o *QueryDeviceLoginHistoryV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query device login history v2 forbidden response a status code equal to that given
func (o *QueryDeviceLoginHistoryV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query device login history v2 forbidden response
func (o *QueryDeviceLoginHistoryV2Forbidden) Code() int {
	return 403
}

func (o *QueryDeviceLoginHistoryV2Forbidden) Error() string {
	return fmt.Sprintf("[POST /devices/combined/devices/login-history/v2][%d] queryDeviceLoginHistoryV2Forbidden  %+v", 403, o.Payload)
}

func (o *QueryDeviceLoginHistoryV2Forbidden) String() string {
	return fmt.Sprintf("[POST /devices/combined/devices/login-history/v2][%d] queryDeviceLoginHistoryV2Forbidden  %+v", 403, o.Payload)
}

func (o *QueryDeviceLoginHistoryV2Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryDeviceLoginHistoryV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	o.Payload = new(models.MsaReplyMetaOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryDeviceLoginHistoryV2TooManyRequests creates a QueryDeviceLoginHistoryV2TooManyRequests with default headers values
func NewQueryDeviceLoginHistoryV2TooManyRequests() *QueryDeviceLoginHistoryV2TooManyRequests {
	return &QueryDeviceLoginHistoryV2TooManyRequests{}
}

/*
QueryDeviceLoginHistoryV2TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryDeviceLoginHistoryV2TooManyRequests struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	/* Too many requests, retry after this time (as milliseconds since epoch)
	 */
	XRateLimitRetryAfter int64

	Payload *models.MsaReplyMetaOnly
}

// IsSuccess returns true when this query device login history v2 too many requests response has a 2xx status code
func (o *QueryDeviceLoginHistoryV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query device login history v2 too many requests response has a 3xx status code
func (o *QueryDeviceLoginHistoryV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query device login history v2 too many requests response has a 4xx status code
func (o *QueryDeviceLoginHistoryV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query device login history v2 too many requests response has a 5xx status code
func (o *QueryDeviceLoginHistoryV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query device login history v2 too many requests response a status code equal to that given
func (o *QueryDeviceLoginHistoryV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query device login history v2 too many requests response
func (o *QueryDeviceLoginHistoryV2TooManyRequests) Code() int {
	return 429
}

func (o *QueryDeviceLoginHistoryV2TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /devices/combined/devices/login-history/v2][%d] queryDeviceLoginHistoryV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryDeviceLoginHistoryV2TooManyRequests) String() string {
	return fmt.Sprintf("[POST /devices/combined/devices/login-history/v2][%d] queryDeviceLoginHistoryV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryDeviceLoginHistoryV2TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryDeviceLoginHistoryV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	// hydrates response header X-RateLimit-RetryAfter
	hdrXRateLimitRetryAfter := response.GetHeader("X-RateLimit-RetryAfter")

	if hdrXRateLimitRetryAfter != "" {
		valxRateLimitRetryAfter, err := swag.ConvertInt64(hdrXRateLimitRetryAfter)
		if err != nil {
			return errors.InvalidType("X-RateLimit-RetryAfter", "header", "int64", hdrXRateLimitRetryAfter)
		}
		o.XRateLimitRetryAfter = valxRateLimitRetryAfter
	}

	o.Payload = new(models.MsaReplyMetaOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
