// Code generated by go-swagger; DO NOT EDIT.

package it_automation

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

// ITAutomationDeletePolicyReader is a Reader for the ITAutomationDeletePolicy structure.
type ITAutomationDeletePolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ITAutomationDeletePolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewITAutomationDeletePolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewITAutomationDeletePolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewITAutomationDeletePolicyForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewITAutomationDeletePolicyTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewITAutomationDeletePolicyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /it-automation/entities/policies/v1] ITAutomationDeletePolicy", response, response.Code())
	}
}

// NewITAutomationDeletePolicyOK creates a ITAutomationDeletePolicyOK with default headers values
func NewITAutomationDeletePolicyOK() *ITAutomationDeletePolicyOK {
	return &ITAutomationDeletePolicyOK{}
}

/*
ITAutomationDeletePolicyOK describes a response with status code 200, with default header values.

OK
*/
type ITAutomationDeletePolicyOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ItautomationDeletePolicyResponse
}

// IsSuccess returns true when this i t automation delete policy o k response has a 2xx status code
func (o *ITAutomationDeletePolicyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation delete policy o k response has a 3xx status code
func (o *ITAutomationDeletePolicyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete policy o k response has a 4xx status code
func (o *ITAutomationDeletePolicyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation delete policy o k response has a 5xx status code
func (o *ITAutomationDeletePolicyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation delete policy o k response a status code equal to that given
func (o *ITAutomationDeletePolicyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the i t automation delete policy o k response
func (o *ITAutomationDeletePolicyOK) Code() int {
	return 200
}

func (o *ITAutomationDeletePolicyOK) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/policies/v1][%d] iTAutomationDeletePolicyOK  %+v", 200, o.Payload)
}

func (o *ITAutomationDeletePolicyOK) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/policies/v1][%d] iTAutomationDeletePolicyOK  %+v", 200, o.Payload)
}

func (o *ITAutomationDeletePolicyOK) GetPayload() *models.ItautomationDeletePolicyResponse {
	return o.Payload
}

func (o *ITAutomationDeletePolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ItautomationDeletePolicyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewITAutomationDeletePolicyBadRequest creates a ITAutomationDeletePolicyBadRequest with default headers values
func NewITAutomationDeletePolicyBadRequest() *ITAutomationDeletePolicyBadRequest {
	return &ITAutomationDeletePolicyBadRequest{}
}

/*
ITAutomationDeletePolicyBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ITAutomationDeletePolicyBadRequest struct {

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

// IsSuccess returns true when this i t automation delete policy bad request response has a 2xx status code
func (o *ITAutomationDeletePolicyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation delete policy bad request response has a 3xx status code
func (o *ITAutomationDeletePolicyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete policy bad request response has a 4xx status code
func (o *ITAutomationDeletePolicyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation delete policy bad request response has a 5xx status code
func (o *ITAutomationDeletePolicyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation delete policy bad request response a status code equal to that given
func (o *ITAutomationDeletePolicyBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the i t automation delete policy bad request response
func (o *ITAutomationDeletePolicyBadRequest) Code() int {
	return 400
}

func (o *ITAutomationDeletePolicyBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/policies/v1][%d] iTAutomationDeletePolicyBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationDeletePolicyBadRequest) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/policies/v1][%d] iTAutomationDeletePolicyBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationDeletePolicyBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationDeletePolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationDeletePolicyForbidden creates a ITAutomationDeletePolicyForbidden with default headers values
func NewITAutomationDeletePolicyForbidden() *ITAutomationDeletePolicyForbidden {
	return &ITAutomationDeletePolicyForbidden{}
}

/*
ITAutomationDeletePolicyForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ITAutomationDeletePolicyForbidden struct {

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

// IsSuccess returns true when this i t automation delete policy forbidden response has a 2xx status code
func (o *ITAutomationDeletePolicyForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation delete policy forbidden response has a 3xx status code
func (o *ITAutomationDeletePolicyForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete policy forbidden response has a 4xx status code
func (o *ITAutomationDeletePolicyForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation delete policy forbidden response has a 5xx status code
func (o *ITAutomationDeletePolicyForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation delete policy forbidden response a status code equal to that given
func (o *ITAutomationDeletePolicyForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the i t automation delete policy forbidden response
func (o *ITAutomationDeletePolicyForbidden) Code() int {
	return 403
}

func (o *ITAutomationDeletePolicyForbidden) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/policies/v1][%d] iTAutomationDeletePolicyForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationDeletePolicyForbidden) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/policies/v1][%d] iTAutomationDeletePolicyForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationDeletePolicyForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationDeletePolicyForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationDeletePolicyTooManyRequests creates a ITAutomationDeletePolicyTooManyRequests with default headers values
func NewITAutomationDeletePolicyTooManyRequests() *ITAutomationDeletePolicyTooManyRequests {
	return &ITAutomationDeletePolicyTooManyRequests{}
}

/*
ITAutomationDeletePolicyTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ITAutomationDeletePolicyTooManyRequests struct {

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

// IsSuccess returns true when this i t automation delete policy too many requests response has a 2xx status code
func (o *ITAutomationDeletePolicyTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation delete policy too many requests response has a 3xx status code
func (o *ITAutomationDeletePolicyTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete policy too many requests response has a 4xx status code
func (o *ITAutomationDeletePolicyTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation delete policy too many requests response has a 5xx status code
func (o *ITAutomationDeletePolicyTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation delete policy too many requests response a status code equal to that given
func (o *ITAutomationDeletePolicyTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the i t automation delete policy too many requests response
func (o *ITAutomationDeletePolicyTooManyRequests) Code() int {
	return 429
}

func (o *ITAutomationDeletePolicyTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/policies/v1][%d] iTAutomationDeletePolicyTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationDeletePolicyTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/policies/v1][%d] iTAutomationDeletePolicyTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationDeletePolicyTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationDeletePolicyTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationDeletePolicyInternalServerError creates a ITAutomationDeletePolicyInternalServerError with default headers values
func NewITAutomationDeletePolicyInternalServerError() *ITAutomationDeletePolicyInternalServerError {
	return &ITAutomationDeletePolicyInternalServerError{}
}

/*
ITAutomationDeletePolicyInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ITAutomationDeletePolicyInternalServerError struct {

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

// IsSuccess returns true when this i t automation delete policy internal server error response has a 2xx status code
func (o *ITAutomationDeletePolicyInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation delete policy internal server error response has a 3xx status code
func (o *ITAutomationDeletePolicyInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete policy internal server error response has a 4xx status code
func (o *ITAutomationDeletePolicyInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation delete policy internal server error response has a 5xx status code
func (o *ITAutomationDeletePolicyInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this i t automation delete policy internal server error response a status code equal to that given
func (o *ITAutomationDeletePolicyInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the i t automation delete policy internal server error response
func (o *ITAutomationDeletePolicyInternalServerError) Code() int {
	return 500
}

func (o *ITAutomationDeletePolicyInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/policies/v1][%d] iTAutomationDeletePolicyInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationDeletePolicyInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/policies/v1][%d] iTAutomationDeletePolicyInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationDeletePolicyInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationDeletePolicyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
