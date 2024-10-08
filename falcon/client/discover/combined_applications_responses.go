// Code generated by go-swagger; DO NOT EDIT.

package discover

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

// CombinedApplicationsReader is a Reader for the CombinedApplications structure.
type CombinedApplicationsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CombinedApplicationsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCombinedApplicationsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCombinedApplicationsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCombinedApplicationsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCombinedApplicationsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCombinedApplicationsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /discover/combined/applications/v1] combined-applications", response, response.Code())
	}
}

// NewCombinedApplicationsOK creates a CombinedApplicationsOK with default headers values
func NewCombinedApplicationsOK() *CombinedApplicationsOK {
	return &CombinedApplicationsOK{}
}

/*
CombinedApplicationsOK describes a response with status code 200, with default header values.

OK
*/
type CombinedApplicationsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainDiscoverAPICombinedApplicationsResponse
}

// IsSuccess returns true when this combined applications o k response has a 2xx status code
func (o *CombinedApplicationsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this combined applications o k response has a 3xx status code
func (o *CombinedApplicationsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this combined applications o k response has a 4xx status code
func (o *CombinedApplicationsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this combined applications o k response has a 5xx status code
func (o *CombinedApplicationsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this combined applications o k response a status code equal to that given
func (o *CombinedApplicationsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the combined applications o k response
func (o *CombinedApplicationsOK) Code() int {
	return 200
}

func (o *CombinedApplicationsOK) Error() string {
	return fmt.Sprintf("[GET /discover/combined/applications/v1][%d] combinedApplicationsOK  %+v", 200, o.Payload)
}

func (o *CombinedApplicationsOK) String() string {
	return fmt.Sprintf("[GET /discover/combined/applications/v1][%d] combinedApplicationsOK  %+v", 200, o.Payload)
}

func (o *CombinedApplicationsOK) GetPayload() *models.DomainDiscoverAPICombinedApplicationsResponse {
	return o.Payload
}

func (o *CombinedApplicationsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainDiscoverAPICombinedApplicationsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCombinedApplicationsBadRequest creates a CombinedApplicationsBadRequest with default headers values
func NewCombinedApplicationsBadRequest() *CombinedApplicationsBadRequest {
	return &CombinedApplicationsBadRequest{}
}

/*
CombinedApplicationsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CombinedApplicationsBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this combined applications bad request response has a 2xx status code
func (o *CombinedApplicationsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this combined applications bad request response has a 3xx status code
func (o *CombinedApplicationsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this combined applications bad request response has a 4xx status code
func (o *CombinedApplicationsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this combined applications bad request response has a 5xx status code
func (o *CombinedApplicationsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this combined applications bad request response a status code equal to that given
func (o *CombinedApplicationsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the combined applications bad request response
func (o *CombinedApplicationsBadRequest) Code() int {
	return 400
}

func (o *CombinedApplicationsBadRequest) Error() string {
	return fmt.Sprintf("[GET /discover/combined/applications/v1][%d] combinedApplicationsBadRequest  %+v", 400, o.Payload)
}

func (o *CombinedApplicationsBadRequest) String() string {
	return fmt.Sprintf("[GET /discover/combined/applications/v1][%d] combinedApplicationsBadRequest  %+v", 400, o.Payload)
}

func (o *CombinedApplicationsBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CombinedApplicationsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCombinedApplicationsForbidden creates a CombinedApplicationsForbidden with default headers values
func NewCombinedApplicationsForbidden() *CombinedApplicationsForbidden {
	return &CombinedApplicationsForbidden{}
}

/*
CombinedApplicationsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CombinedApplicationsForbidden struct {

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

// IsSuccess returns true when this combined applications forbidden response has a 2xx status code
func (o *CombinedApplicationsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this combined applications forbidden response has a 3xx status code
func (o *CombinedApplicationsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this combined applications forbidden response has a 4xx status code
func (o *CombinedApplicationsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this combined applications forbidden response has a 5xx status code
func (o *CombinedApplicationsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this combined applications forbidden response a status code equal to that given
func (o *CombinedApplicationsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the combined applications forbidden response
func (o *CombinedApplicationsForbidden) Code() int {
	return 403
}

func (o *CombinedApplicationsForbidden) Error() string {
	return fmt.Sprintf("[GET /discover/combined/applications/v1][%d] combinedApplicationsForbidden  %+v", 403, o.Payload)
}

func (o *CombinedApplicationsForbidden) String() string {
	return fmt.Sprintf("[GET /discover/combined/applications/v1][%d] combinedApplicationsForbidden  %+v", 403, o.Payload)
}

func (o *CombinedApplicationsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CombinedApplicationsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCombinedApplicationsTooManyRequests creates a CombinedApplicationsTooManyRequests with default headers values
func NewCombinedApplicationsTooManyRequests() *CombinedApplicationsTooManyRequests {
	return &CombinedApplicationsTooManyRequests{}
}

/*
CombinedApplicationsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CombinedApplicationsTooManyRequests struct {

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

// IsSuccess returns true when this combined applications too many requests response has a 2xx status code
func (o *CombinedApplicationsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this combined applications too many requests response has a 3xx status code
func (o *CombinedApplicationsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this combined applications too many requests response has a 4xx status code
func (o *CombinedApplicationsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this combined applications too many requests response has a 5xx status code
func (o *CombinedApplicationsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this combined applications too many requests response a status code equal to that given
func (o *CombinedApplicationsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the combined applications too many requests response
func (o *CombinedApplicationsTooManyRequests) Code() int {
	return 429
}

func (o *CombinedApplicationsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /discover/combined/applications/v1][%d] combinedApplicationsTooManyRequests  %+v", 429, o.Payload)
}

func (o *CombinedApplicationsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /discover/combined/applications/v1][%d] combinedApplicationsTooManyRequests  %+v", 429, o.Payload)
}

func (o *CombinedApplicationsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CombinedApplicationsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCombinedApplicationsInternalServerError creates a CombinedApplicationsInternalServerError with default headers values
func NewCombinedApplicationsInternalServerError() *CombinedApplicationsInternalServerError {
	return &CombinedApplicationsInternalServerError{}
}

/*
CombinedApplicationsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CombinedApplicationsInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this combined applications internal server error response has a 2xx status code
func (o *CombinedApplicationsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this combined applications internal server error response has a 3xx status code
func (o *CombinedApplicationsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this combined applications internal server error response has a 4xx status code
func (o *CombinedApplicationsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this combined applications internal server error response has a 5xx status code
func (o *CombinedApplicationsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this combined applications internal server error response a status code equal to that given
func (o *CombinedApplicationsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the combined applications internal server error response
func (o *CombinedApplicationsInternalServerError) Code() int {
	return 500
}

func (o *CombinedApplicationsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /discover/combined/applications/v1][%d] combinedApplicationsInternalServerError  %+v", 500, o.Payload)
}

func (o *CombinedApplicationsInternalServerError) String() string {
	return fmt.Sprintf("[GET /discover/combined/applications/v1][%d] combinedApplicationsInternalServerError  %+v", 500, o.Payload)
}

func (o *CombinedApplicationsInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CombinedApplicationsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}