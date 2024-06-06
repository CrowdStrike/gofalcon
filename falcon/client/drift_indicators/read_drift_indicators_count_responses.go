// Code generated by go-swagger; DO NOT EDIT.

package drift_indicators

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/aslape/gofalcon/falcon/models"
)

// ReadDriftIndicatorsCountReader is a Reader for the ReadDriftIndicatorsCount structure.
type ReadDriftIndicatorsCountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReadDriftIndicatorsCountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewReadDriftIndicatorsCountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewReadDriftIndicatorsCountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewReadDriftIndicatorsCountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewReadDriftIndicatorsCountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/aggregates/drift-indicators/count/v1] ReadDriftIndicatorsCount", response, response.Code())
	}
}

// NewReadDriftIndicatorsCountOK creates a ReadDriftIndicatorsCountOK with default headers values
func NewReadDriftIndicatorsCountOK() *ReadDriftIndicatorsCountOK {
	return &ReadDriftIndicatorsCountOK{}
}

/*
ReadDriftIndicatorsCountOK describes a response with status code 200, with default header values.

OK
*/
type ReadDriftIndicatorsCountOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DriftindicatorsDriftIndicatorsCountValue
}

// IsSuccess returns true when this read drift indicators count o k response has a 2xx status code
func (o *ReadDriftIndicatorsCountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this read drift indicators count o k response has a 3xx status code
func (o *ReadDriftIndicatorsCountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read drift indicators count o k response has a 4xx status code
func (o *ReadDriftIndicatorsCountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this read drift indicators count o k response has a 5xx status code
func (o *ReadDriftIndicatorsCountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this read drift indicators count o k response a status code equal to that given
func (o *ReadDriftIndicatorsCountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the read drift indicators count o k response
func (o *ReadDriftIndicatorsCountOK) Code() int {
	return 200
}

func (o *ReadDriftIndicatorsCountOK) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/drift-indicators/count/v1][%d] readDriftIndicatorsCountOK  %+v", 200, o.Payload)
}

func (o *ReadDriftIndicatorsCountOK) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/drift-indicators/count/v1][%d] readDriftIndicatorsCountOK  %+v", 200, o.Payload)
}

func (o *ReadDriftIndicatorsCountOK) GetPayload() *models.DriftindicatorsDriftIndicatorsCountValue {
	return o.Payload
}

func (o *ReadDriftIndicatorsCountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DriftindicatorsDriftIndicatorsCountValue)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewReadDriftIndicatorsCountForbidden creates a ReadDriftIndicatorsCountForbidden with default headers values
func NewReadDriftIndicatorsCountForbidden() *ReadDriftIndicatorsCountForbidden {
	return &ReadDriftIndicatorsCountForbidden{}
}

/*
ReadDriftIndicatorsCountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ReadDriftIndicatorsCountForbidden struct {

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

// IsSuccess returns true when this read drift indicators count forbidden response has a 2xx status code
func (o *ReadDriftIndicatorsCountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read drift indicators count forbidden response has a 3xx status code
func (o *ReadDriftIndicatorsCountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read drift indicators count forbidden response has a 4xx status code
func (o *ReadDriftIndicatorsCountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this read drift indicators count forbidden response has a 5xx status code
func (o *ReadDriftIndicatorsCountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this read drift indicators count forbidden response a status code equal to that given
func (o *ReadDriftIndicatorsCountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the read drift indicators count forbidden response
func (o *ReadDriftIndicatorsCountForbidden) Code() int {
	return 403
}

func (o *ReadDriftIndicatorsCountForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/drift-indicators/count/v1][%d] readDriftIndicatorsCountForbidden  %+v", 403, o.Payload)
}

func (o *ReadDriftIndicatorsCountForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/drift-indicators/count/v1][%d] readDriftIndicatorsCountForbidden  %+v", 403, o.Payload)
}

func (o *ReadDriftIndicatorsCountForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReadDriftIndicatorsCountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReadDriftIndicatorsCountTooManyRequests creates a ReadDriftIndicatorsCountTooManyRequests with default headers values
func NewReadDriftIndicatorsCountTooManyRequests() *ReadDriftIndicatorsCountTooManyRequests {
	return &ReadDriftIndicatorsCountTooManyRequests{}
}

/*
ReadDriftIndicatorsCountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ReadDriftIndicatorsCountTooManyRequests struct {

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

// IsSuccess returns true when this read drift indicators count too many requests response has a 2xx status code
func (o *ReadDriftIndicatorsCountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read drift indicators count too many requests response has a 3xx status code
func (o *ReadDriftIndicatorsCountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read drift indicators count too many requests response has a 4xx status code
func (o *ReadDriftIndicatorsCountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this read drift indicators count too many requests response has a 5xx status code
func (o *ReadDriftIndicatorsCountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this read drift indicators count too many requests response a status code equal to that given
func (o *ReadDriftIndicatorsCountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the read drift indicators count too many requests response
func (o *ReadDriftIndicatorsCountTooManyRequests) Code() int {
	return 429
}

func (o *ReadDriftIndicatorsCountTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/drift-indicators/count/v1][%d] readDriftIndicatorsCountTooManyRequests  %+v", 429, o.Payload)
}

func (o *ReadDriftIndicatorsCountTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/drift-indicators/count/v1][%d] readDriftIndicatorsCountTooManyRequests  %+v", 429, o.Payload)
}

func (o *ReadDriftIndicatorsCountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReadDriftIndicatorsCountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReadDriftIndicatorsCountInternalServerError creates a ReadDriftIndicatorsCountInternalServerError with default headers values
func NewReadDriftIndicatorsCountInternalServerError() *ReadDriftIndicatorsCountInternalServerError {
	return &ReadDriftIndicatorsCountInternalServerError{}
}

/*
ReadDriftIndicatorsCountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ReadDriftIndicatorsCountInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.CoreEntitiesResponse
}

// IsSuccess returns true when this read drift indicators count internal server error response has a 2xx status code
func (o *ReadDriftIndicatorsCountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read drift indicators count internal server error response has a 3xx status code
func (o *ReadDriftIndicatorsCountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read drift indicators count internal server error response has a 4xx status code
func (o *ReadDriftIndicatorsCountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this read drift indicators count internal server error response has a 5xx status code
func (o *ReadDriftIndicatorsCountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this read drift indicators count internal server error response a status code equal to that given
func (o *ReadDriftIndicatorsCountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the read drift indicators count internal server error response
func (o *ReadDriftIndicatorsCountInternalServerError) Code() int {
	return 500
}

func (o *ReadDriftIndicatorsCountInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/drift-indicators/count/v1][%d] readDriftIndicatorsCountInternalServerError  %+v", 500, o.Payload)
}

func (o *ReadDriftIndicatorsCountInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/drift-indicators/count/v1][%d] readDriftIndicatorsCountInternalServerError  %+v", 500, o.Payload)
}

func (o *ReadDriftIndicatorsCountInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *ReadDriftIndicatorsCountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.CoreEntitiesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
