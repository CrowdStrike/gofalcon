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

// SearchDetectionsReader is a Reader for the SearchDetections structure.
type SearchDetectionsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SearchDetectionsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSearchDetectionsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewSearchDetectionsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSearchDetectionsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewSearchDetectionsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/queries/detections/v1] SearchDetections", response, response.Code())
	}
}

// NewSearchDetectionsOK creates a SearchDetectionsOK with default headers values
func NewSearchDetectionsOK() *SearchDetectionsOK {
	return &SearchDetectionsOK{}
}

/*
SearchDetectionsOK describes a response with status code 200, with default header values.

OK
*/
type SearchDetectionsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.CommonGenericEntityResponseString
}

// IsSuccess returns true when this search detections o k response has a 2xx status code
func (o *SearchDetectionsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this search detections o k response has a 3xx status code
func (o *SearchDetectionsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search detections o k response has a 4xx status code
func (o *SearchDetectionsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this search detections o k response has a 5xx status code
func (o *SearchDetectionsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this search detections o k response a status code equal to that given
func (o *SearchDetectionsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the search detections o k response
func (o *SearchDetectionsOK) Code() int {
	return 200
}

func (o *SearchDetectionsOK) Error() string {
	return fmt.Sprintf("[GET /container-security/queries/detections/v1][%d] searchDetectionsOK  %+v", 200, o.Payload)
}

func (o *SearchDetectionsOK) String() string {
	return fmt.Sprintf("[GET /container-security/queries/detections/v1][%d] searchDetectionsOK  %+v", 200, o.Payload)
}

func (o *SearchDetectionsOK) GetPayload() *models.CommonGenericEntityResponseString {
	return o.Payload
}

func (o *SearchDetectionsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.CommonGenericEntityResponseString)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSearchDetectionsForbidden creates a SearchDetectionsForbidden with default headers values
func NewSearchDetectionsForbidden() *SearchDetectionsForbidden {
	return &SearchDetectionsForbidden{}
}

/*
SearchDetectionsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SearchDetectionsForbidden struct {

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

// IsSuccess returns true when this search detections forbidden response has a 2xx status code
func (o *SearchDetectionsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search detections forbidden response has a 3xx status code
func (o *SearchDetectionsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search detections forbidden response has a 4xx status code
func (o *SearchDetectionsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this search detections forbidden response has a 5xx status code
func (o *SearchDetectionsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this search detections forbidden response a status code equal to that given
func (o *SearchDetectionsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the search detections forbidden response
func (o *SearchDetectionsForbidden) Code() int {
	return 403
}

func (o *SearchDetectionsForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/queries/detections/v1][%d] searchDetectionsForbidden  %+v", 403, o.Payload)
}

func (o *SearchDetectionsForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/queries/detections/v1][%d] searchDetectionsForbidden  %+v", 403, o.Payload)
}

func (o *SearchDetectionsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *SearchDetectionsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSearchDetectionsTooManyRequests creates a SearchDetectionsTooManyRequests with default headers values
func NewSearchDetectionsTooManyRequests() *SearchDetectionsTooManyRequests {
	return &SearchDetectionsTooManyRequests{}
}

/*
SearchDetectionsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type SearchDetectionsTooManyRequests struct {

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

// IsSuccess returns true when this search detections too many requests response has a 2xx status code
func (o *SearchDetectionsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search detections too many requests response has a 3xx status code
func (o *SearchDetectionsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search detections too many requests response has a 4xx status code
func (o *SearchDetectionsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this search detections too many requests response has a 5xx status code
func (o *SearchDetectionsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this search detections too many requests response a status code equal to that given
func (o *SearchDetectionsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the search detections too many requests response
func (o *SearchDetectionsTooManyRequests) Code() int {
	return 429
}

func (o *SearchDetectionsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/queries/detections/v1][%d] searchDetectionsTooManyRequests  %+v", 429, o.Payload)
}

func (o *SearchDetectionsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/queries/detections/v1][%d] searchDetectionsTooManyRequests  %+v", 429, o.Payload)
}

func (o *SearchDetectionsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *SearchDetectionsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSearchDetectionsInternalServerError creates a SearchDetectionsInternalServerError with default headers values
func NewSearchDetectionsInternalServerError() *SearchDetectionsInternalServerError {
	return &SearchDetectionsInternalServerError{}
}

/*
SearchDetectionsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type SearchDetectionsInternalServerError struct {

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

// IsSuccess returns true when this search detections internal server error response has a 2xx status code
func (o *SearchDetectionsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search detections internal server error response has a 3xx status code
func (o *SearchDetectionsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search detections internal server error response has a 4xx status code
func (o *SearchDetectionsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this search detections internal server error response has a 5xx status code
func (o *SearchDetectionsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this search detections internal server error response a status code equal to that given
func (o *SearchDetectionsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the search detections internal server error response
func (o *SearchDetectionsInternalServerError) Code() int {
	return 500
}

func (o *SearchDetectionsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/queries/detections/v1][%d] searchDetectionsInternalServerError  %+v", 500, o.Payload)
}

func (o *SearchDetectionsInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/queries/detections/v1][%d] searchDetectionsInternalServerError  %+v", 500, o.Payload)
}

func (o *SearchDetectionsInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *SearchDetectionsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
