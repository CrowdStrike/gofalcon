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

// ITAutomationUpdatePoliciesPrecedenceReader is a Reader for the ITAutomationUpdatePoliciesPrecedence structure.
type ITAutomationUpdatePoliciesPrecedenceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ITAutomationUpdatePoliciesPrecedenceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewITAutomationUpdatePoliciesPrecedenceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewITAutomationUpdatePoliciesPrecedenceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewITAutomationUpdatePoliciesPrecedenceForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewITAutomationUpdatePoliciesPrecedenceNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewITAutomationUpdatePoliciesPrecedenceConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewITAutomationUpdatePoliciesPrecedenceTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewITAutomationUpdatePoliciesPrecedenceInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /it-automation/entities/policies-precedence/v1] ITAutomationUpdatePoliciesPrecedence", response, response.Code())
	}
}

// NewITAutomationUpdatePoliciesPrecedenceOK creates a ITAutomationUpdatePoliciesPrecedenceOK with default headers values
func NewITAutomationUpdatePoliciesPrecedenceOK() *ITAutomationUpdatePoliciesPrecedenceOK {
	return &ITAutomationUpdatePoliciesPrecedenceOK{}
}

/*
ITAutomationUpdatePoliciesPrecedenceOK describes a response with status code 200, with default header values.

Policy Precedence Updated.
*/
type ITAutomationUpdatePoliciesPrecedenceOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ItautomationUpdatePoliciesPrecedenceResponse
}

// IsSuccess returns true when this i t automation update policies precedence o k response has a 2xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation update policies precedence o k response has a 3xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies precedence o k response has a 4xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation update policies precedence o k response has a 5xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceOK) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policies precedence o k response a status code equal to that given
func (o *ITAutomationUpdatePoliciesPrecedenceOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the i t automation update policies precedence o k response
func (o *ITAutomationUpdatePoliciesPrecedenceOK) Code() int {
	return 200
}

func (o *ITAutomationUpdatePoliciesPrecedenceOK) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceOK  %+v", 200, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceOK) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceOK  %+v", 200, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceOK) GetPayload() *models.ItautomationUpdatePoliciesPrecedenceResponse {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesPrecedenceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ItautomationUpdatePoliciesPrecedenceResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewITAutomationUpdatePoliciesPrecedenceBadRequest creates a ITAutomationUpdatePoliciesPrecedenceBadRequest with default headers values
func NewITAutomationUpdatePoliciesPrecedenceBadRequest() *ITAutomationUpdatePoliciesPrecedenceBadRequest {
	return &ITAutomationUpdatePoliciesPrecedenceBadRequest{}
}

/*
ITAutomationUpdatePoliciesPrecedenceBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ITAutomationUpdatePoliciesPrecedenceBadRequest struct {

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

// IsSuccess returns true when this i t automation update policies precedence bad request response has a 2xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policies precedence bad request response has a 3xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies precedence bad request response has a 4xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policies precedence bad request response has a 5xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policies precedence bad request response a status code equal to that given
func (o *ITAutomationUpdatePoliciesPrecedenceBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the i t automation update policies precedence bad request response
func (o *ITAutomationUpdatePoliciesPrecedenceBadRequest) Code() int {
	return 400
}

func (o *ITAutomationUpdatePoliciesPrecedenceBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceBadRequest) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesPrecedenceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePoliciesPrecedenceForbidden creates a ITAutomationUpdatePoliciesPrecedenceForbidden with default headers values
func NewITAutomationUpdatePoliciesPrecedenceForbidden() *ITAutomationUpdatePoliciesPrecedenceForbidden {
	return &ITAutomationUpdatePoliciesPrecedenceForbidden{}
}

/*
ITAutomationUpdatePoliciesPrecedenceForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ITAutomationUpdatePoliciesPrecedenceForbidden struct {

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

// IsSuccess returns true when this i t automation update policies precedence forbidden response has a 2xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policies precedence forbidden response has a 3xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies precedence forbidden response has a 4xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policies precedence forbidden response has a 5xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policies precedence forbidden response a status code equal to that given
func (o *ITAutomationUpdatePoliciesPrecedenceForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the i t automation update policies precedence forbidden response
func (o *ITAutomationUpdatePoliciesPrecedenceForbidden) Code() int {
	return 403
}

func (o *ITAutomationUpdatePoliciesPrecedenceForbidden) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceForbidden) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesPrecedenceForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePoliciesPrecedenceNotFound creates a ITAutomationUpdatePoliciesPrecedenceNotFound with default headers values
func NewITAutomationUpdatePoliciesPrecedenceNotFound() *ITAutomationUpdatePoliciesPrecedenceNotFound {
	return &ITAutomationUpdatePoliciesPrecedenceNotFound{}
}

/*
ITAutomationUpdatePoliciesPrecedenceNotFound describes a response with status code 404, with default header values.

Not Found
*/
type ITAutomationUpdatePoliciesPrecedenceNotFound struct {

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

// IsSuccess returns true when this i t automation update policies precedence not found response has a 2xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policies precedence not found response has a 3xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies precedence not found response has a 4xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policies precedence not found response has a 5xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policies precedence not found response a status code equal to that given
func (o *ITAutomationUpdatePoliciesPrecedenceNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the i t automation update policies precedence not found response
func (o *ITAutomationUpdatePoliciesPrecedenceNotFound) Code() int {
	return 404
}

func (o *ITAutomationUpdatePoliciesPrecedenceNotFound) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceNotFound  %+v", 404, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceNotFound) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceNotFound  %+v", 404, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesPrecedenceNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePoliciesPrecedenceConflict creates a ITAutomationUpdatePoliciesPrecedenceConflict with default headers values
func NewITAutomationUpdatePoliciesPrecedenceConflict() *ITAutomationUpdatePoliciesPrecedenceConflict {
	return &ITAutomationUpdatePoliciesPrecedenceConflict{}
}

/*
ITAutomationUpdatePoliciesPrecedenceConflict describes a response with status code 409, with default header values.

Conflict
*/
type ITAutomationUpdatePoliciesPrecedenceConflict struct {

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

// IsSuccess returns true when this i t automation update policies precedence conflict response has a 2xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policies precedence conflict response has a 3xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies precedence conflict response has a 4xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policies precedence conflict response has a 5xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policies precedence conflict response a status code equal to that given
func (o *ITAutomationUpdatePoliciesPrecedenceConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the i t automation update policies precedence conflict response
func (o *ITAutomationUpdatePoliciesPrecedenceConflict) Code() int {
	return 409
}

func (o *ITAutomationUpdatePoliciesPrecedenceConflict) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceConflict  %+v", 409, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceConflict) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceConflict  %+v", 409, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceConflict) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesPrecedenceConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePoliciesPrecedenceTooManyRequests creates a ITAutomationUpdatePoliciesPrecedenceTooManyRequests with default headers values
func NewITAutomationUpdatePoliciesPrecedenceTooManyRequests() *ITAutomationUpdatePoliciesPrecedenceTooManyRequests {
	return &ITAutomationUpdatePoliciesPrecedenceTooManyRequests{}
}

/*
ITAutomationUpdatePoliciesPrecedenceTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ITAutomationUpdatePoliciesPrecedenceTooManyRequests struct {

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

// IsSuccess returns true when this i t automation update policies precedence too many requests response has a 2xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policies precedence too many requests response has a 3xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies precedence too many requests response has a 4xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policies precedence too many requests response has a 5xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policies precedence too many requests response a status code equal to that given
func (o *ITAutomationUpdatePoliciesPrecedenceTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the i t automation update policies precedence too many requests response
func (o *ITAutomationUpdatePoliciesPrecedenceTooManyRequests) Code() int {
	return 429
}

func (o *ITAutomationUpdatePoliciesPrecedenceTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesPrecedenceTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePoliciesPrecedenceInternalServerError creates a ITAutomationUpdatePoliciesPrecedenceInternalServerError with default headers values
func NewITAutomationUpdatePoliciesPrecedenceInternalServerError() *ITAutomationUpdatePoliciesPrecedenceInternalServerError {
	return &ITAutomationUpdatePoliciesPrecedenceInternalServerError{}
}

/*
ITAutomationUpdatePoliciesPrecedenceInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ITAutomationUpdatePoliciesPrecedenceInternalServerError struct {

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

// IsSuccess returns true when this i t automation update policies precedence internal server error response has a 2xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policies precedence internal server error response has a 3xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies precedence internal server error response has a 4xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation update policies precedence internal server error response has a 5xx status code
func (o *ITAutomationUpdatePoliciesPrecedenceInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this i t automation update policies precedence internal server error response a status code equal to that given
func (o *ITAutomationUpdatePoliciesPrecedenceInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the i t automation update policies precedence internal server error response
func (o *ITAutomationUpdatePoliciesPrecedenceInternalServerError) Code() int {
	return 500
}

func (o *ITAutomationUpdatePoliciesPrecedenceInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-precedence/v1][%d] iTAutomationUpdatePoliciesPrecedenceInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationUpdatePoliciesPrecedenceInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesPrecedenceInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
