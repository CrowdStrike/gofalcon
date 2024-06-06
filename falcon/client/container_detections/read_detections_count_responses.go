// Code generated by go-swagger; DO NOT EDIT.

package container_detections

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

// ReadDetectionsCountReader is a Reader for the ReadDetectionsCount structure.
type ReadDetectionsCountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReadDetectionsCountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewReadDetectionsCountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewReadDetectionsCountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewReadDetectionsCountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewReadDetectionsCountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/aggregates/detections/count/v1] ReadDetectionsCount", response, response.Code())
	}
}

// NewReadDetectionsCountOK creates a ReadDetectionsCountOK with default headers values
func NewReadDetectionsCountOK() *ReadDetectionsCountOK {
	return &ReadDetectionsCountOK{}
}

/*
ReadDetectionsCountOK describes a response with status code 200, with default header values.

OK
*/
type ReadDetectionsCountOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DetectionsAPIDetectionsCount
}

// IsSuccess returns true when this read detections count o k response has a 2xx status code
func (o *ReadDetectionsCountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this read detections count o k response has a 3xx status code
func (o *ReadDetectionsCountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read detections count o k response has a 4xx status code
func (o *ReadDetectionsCountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this read detections count o k response has a 5xx status code
func (o *ReadDetectionsCountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this read detections count o k response a status code equal to that given
func (o *ReadDetectionsCountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the read detections count o k response
func (o *ReadDetectionsCountOK) Code() int {
	return 200
}

func (o *ReadDetectionsCountOK) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/detections/count/v1][%d] readDetectionsCountOK  %+v", 200, o.Payload)
}

func (o *ReadDetectionsCountOK) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/detections/count/v1][%d] readDetectionsCountOK  %+v", 200, o.Payload)
}

func (o *ReadDetectionsCountOK) GetPayload() *models.DetectionsAPIDetectionsCount {
	return o.Payload
}

func (o *ReadDetectionsCountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DetectionsAPIDetectionsCount)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewReadDetectionsCountForbidden creates a ReadDetectionsCountForbidden with default headers values
func NewReadDetectionsCountForbidden() *ReadDetectionsCountForbidden {
	return &ReadDetectionsCountForbidden{}
}

/*
ReadDetectionsCountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ReadDetectionsCountForbidden struct {

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

// IsSuccess returns true when this read detections count forbidden response has a 2xx status code
func (o *ReadDetectionsCountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read detections count forbidden response has a 3xx status code
func (o *ReadDetectionsCountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read detections count forbidden response has a 4xx status code
func (o *ReadDetectionsCountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this read detections count forbidden response has a 5xx status code
func (o *ReadDetectionsCountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this read detections count forbidden response a status code equal to that given
func (o *ReadDetectionsCountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the read detections count forbidden response
func (o *ReadDetectionsCountForbidden) Code() int {
	return 403
}

func (o *ReadDetectionsCountForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/detections/count/v1][%d] readDetectionsCountForbidden  %+v", 403, o.Payload)
}

func (o *ReadDetectionsCountForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/detections/count/v1][%d] readDetectionsCountForbidden  %+v", 403, o.Payload)
}

func (o *ReadDetectionsCountForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReadDetectionsCountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReadDetectionsCountTooManyRequests creates a ReadDetectionsCountTooManyRequests with default headers values
func NewReadDetectionsCountTooManyRequests() *ReadDetectionsCountTooManyRequests {
	return &ReadDetectionsCountTooManyRequests{}
}

/*
ReadDetectionsCountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ReadDetectionsCountTooManyRequests struct {

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

// IsSuccess returns true when this read detections count too many requests response has a 2xx status code
func (o *ReadDetectionsCountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read detections count too many requests response has a 3xx status code
func (o *ReadDetectionsCountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read detections count too many requests response has a 4xx status code
func (o *ReadDetectionsCountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this read detections count too many requests response has a 5xx status code
func (o *ReadDetectionsCountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this read detections count too many requests response a status code equal to that given
func (o *ReadDetectionsCountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the read detections count too many requests response
func (o *ReadDetectionsCountTooManyRequests) Code() int {
	return 429
}

func (o *ReadDetectionsCountTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/detections/count/v1][%d] readDetectionsCountTooManyRequests  %+v", 429, o.Payload)
}

func (o *ReadDetectionsCountTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/detections/count/v1][%d] readDetectionsCountTooManyRequests  %+v", 429, o.Payload)
}

func (o *ReadDetectionsCountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReadDetectionsCountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReadDetectionsCountInternalServerError creates a ReadDetectionsCountInternalServerError with default headers values
func NewReadDetectionsCountInternalServerError() *ReadDetectionsCountInternalServerError {
	return &ReadDetectionsCountInternalServerError{}
}

/*
ReadDetectionsCountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ReadDetectionsCountInternalServerError struct {

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

// IsSuccess returns true when this read detections count internal server error response has a 2xx status code
func (o *ReadDetectionsCountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read detections count internal server error response has a 3xx status code
func (o *ReadDetectionsCountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read detections count internal server error response has a 4xx status code
func (o *ReadDetectionsCountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this read detections count internal server error response has a 5xx status code
func (o *ReadDetectionsCountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this read detections count internal server error response a status code equal to that given
func (o *ReadDetectionsCountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the read detections count internal server error response
func (o *ReadDetectionsCountInternalServerError) Code() int {
	return 500
}

func (o *ReadDetectionsCountInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/detections/count/v1][%d] readDetectionsCountInternalServerError  %+v", 500, o.Payload)
}

func (o *ReadDetectionsCountInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/detections/count/v1][%d] readDetectionsCountInternalServerError  %+v", 500, o.Payload)
}

func (o *ReadDetectionsCountInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *ReadDetectionsCountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
