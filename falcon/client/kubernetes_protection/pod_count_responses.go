// Code generated by go-swagger; DO NOT EDIT.

package kubernetes_protection

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

// PodCountReader is a Reader for the PodCount structure.
type PodCountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PodCountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPodCountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewPodCountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPodCountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPodCountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/aggregates/pods/count/v1] PodCount", response, response.Code())
	}
}

// NewPodCountOK creates a PodCountOK with default headers values
func NewPodCountOK() *PodCountOK {
	return &PodCountOK{}
}

/*
PodCountOK describes a response with status code 200, with default header values.

OK
*/
type PodCountOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.CommonCountResponse
}

// IsSuccess returns true when this pod count o k response has a 2xx status code
func (o *PodCountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pod count o k response has a 3xx status code
func (o *PodCountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pod count o k response has a 4xx status code
func (o *PodCountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this pod count o k response has a 5xx status code
func (o *PodCountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this pod count o k response a status code equal to that given
func (o *PodCountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the pod count o k response
func (o *PodCountOK) Code() int {
	return 200
}

func (o *PodCountOK) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/pods/count/v1][%d] podCountOK  %+v", 200, o.Payload)
}

func (o *PodCountOK) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/pods/count/v1][%d] podCountOK  %+v", 200, o.Payload)
}

func (o *PodCountOK) GetPayload() *models.CommonCountResponse {
	return o.Payload
}

func (o *PodCountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.CommonCountResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPodCountForbidden creates a PodCountForbidden with default headers values
func NewPodCountForbidden() *PodCountForbidden {
	return &PodCountForbidden{}
}

/*
PodCountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PodCountForbidden struct {

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

// IsSuccess returns true when this pod count forbidden response has a 2xx status code
func (o *PodCountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this pod count forbidden response has a 3xx status code
func (o *PodCountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pod count forbidden response has a 4xx status code
func (o *PodCountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this pod count forbidden response has a 5xx status code
func (o *PodCountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this pod count forbidden response a status code equal to that given
func (o *PodCountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the pod count forbidden response
func (o *PodCountForbidden) Code() int {
	return 403
}

func (o *PodCountForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/pods/count/v1][%d] podCountForbidden  %+v", 403, o.Payload)
}

func (o *PodCountForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/pods/count/v1][%d] podCountForbidden  %+v", 403, o.Payload)
}

func (o *PodCountForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *PodCountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewPodCountTooManyRequests creates a PodCountTooManyRequests with default headers values
func NewPodCountTooManyRequests() *PodCountTooManyRequests {
	return &PodCountTooManyRequests{}
}

/*
PodCountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type PodCountTooManyRequests struct {

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

// IsSuccess returns true when this pod count too many requests response has a 2xx status code
func (o *PodCountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this pod count too many requests response has a 3xx status code
func (o *PodCountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pod count too many requests response has a 4xx status code
func (o *PodCountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this pod count too many requests response has a 5xx status code
func (o *PodCountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this pod count too many requests response a status code equal to that given
func (o *PodCountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the pod count too many requests response
func (o *PodCountTooManyRequests) Code() int {
	return 429
}

func (o *PodCountTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/pods/count/v1][%d] podCountTooManyRequests  %+v", 429, o.Payload)
}

func (o *PodCountTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/pods/count/v1][%d] podCountTooManyRequests  %+v", 429, o.Payload)
}

func (o *PodCountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *PodCountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewPodCountInternalServerError creates a PodCountInternalServerError with default headers values
func NewPodCountInternalServerError() *PodCountInternalServerError {
	return &PodCountInternalServerError{}
}

/*
PodCountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PodCountInternalServerError struct {

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

// IsSuccess returns true when this pod count internal server error response has a 2xx status code
func (o *PodCountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this pod count internal server error response has a 3xx status code
func (o *PodCountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pod count internal server error response has a 4xx status code
func (o *PodCountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this pod count internal server error response has a 5xx status code
func (o *PodCountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this pod count internal server error response a status code equal to that given
func (o *PodCountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the pod count internal server error response
func (o *PodCountInternalServerError) Code() int {
	return 500
}

func (o *PodCountInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/pods/count/v1][%d] podCountInternalServerError  %+v", 500, o.Payload)
}

func (o *PodCountInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/pods/count/v1][%d] podCountInternalServerError  %+v", 500, o.Payload)
}

func (o *PodCountInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *PodCountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
