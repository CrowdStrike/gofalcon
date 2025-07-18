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

// ITAutomationUpdatePoliciesReader is a Reader for the ITAutomationUpdatePolicies structure.
type ITAutomationUpdatePoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ITAutomationUpdatePoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewITAutomationUpdatePoliciesCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewITAutomationUpdatePoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewITAutomationUpdatePoliciesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewITAutomationUpdatePoliciesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewITAutomationUpdatePoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /it-automation/entities/policies/v1] ITAutomationUpdatePolicies", response, response.Code())
	}
}

// NewITAutomationUpdatePoliciesCreated creates a ITAutomationUpdatePoliciesCreated with default headers values
func NewITAutomationUpdatePoliciesCreated() *ITAutomationUpdatePoliciesCreated {
	return &ITAutomationUpdatePoliciesCreated{}
}

/*
ITAutomationUpdatePoliciesCreated describes a response with status code 201, with default header values.

Created
*/
type ITAutomationUpdatePoliciesCreated struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ItautomationUpdatePolicyResponse
}

// IsSuccess returns true when this i t automation update policies created response has a 2xx status code
func (o *ITAutomationUpdatePoliciesCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation update policies created response has a 3xx status code
func (o *ITAutomationUpdatePoliciesCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies created response has a 4xx status code
func (o *ITAutomationUpdatePoliciesCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation update policies created response has a 5xx status code
func (o *ITAutomationUpdatePoliciesCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policies created response a status code equal to that given
func (o *ITAutomationUpdatePoliciesCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the i t automation update policies created response
func (o *ITAutomationUpdatePoliciesCreated) Code() int {
	return 201
}

func (o *ITAutomationUpdatePoliciesCreated) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies/v1][%d] iTAutomationUpdatePoliciesCreated  %+v", 201, o.Payload)
}

func (o *ITAutomationUpdatePoliciesCreated) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies/v1][%d] iTAutomationUpdatePoliciesCreated  %+v", 201, o.Payload)
}

func (o *ITAutomationUpdatePoliciesCreated) GetPayload() *models.ItautomationUpdatePolicyResponse {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ItautomationUpdatePolicyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewITAutomationUpdatePoliciesBadRequest creates a ITAutomationUpdatePoliciesBadRequest with default headers values
func NewITAutomationUpdatePoliciesBadRequest() *ITAutomationUpdatePoliciesBadRequest {
	return &ITAutomationUpdatePoliciesBadRequest{}
}

/*
ITAutomationUpdatePoliciesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ITAutomationUpdatePoliciesBadRequest struct {

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

// IsSuccess returns true when this i t automation update policies bad request response has a 2xx status code
func (o *ITAutomationUpdatePoliciesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policies bad request response has a 3xx status code
func (o *ITAutomationUpdatePoliciesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies bad request response has a 4xx status code
func (o *ITAutomationUpdatePoliciesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policies bad request response has a 5xx status code
func (o *ITAutomationUpdatePoliciesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policies bad request response a status code equal to that given
func (o *ITAutomationUpdatePoliciesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the i t automation update policies bad request response
func (o *ITAutomationUpdatePoliciesBadRequest) Code() int {
	return 400
}

func (o *ITAutomationUpdatePoliciesBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies/v1][%d] iTAutomationUpdatePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationUpdatePoliciesBadRequest) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies/v1][%d] iTAutomationUpdatePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationUpdatePoliciesBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePoliciesForbidden creates a ITAutomationUpdatePoliciesForbidden with default headers values
func NewITAutomationUpdatePoliciesForbidden() *ITAutomationUpdatePoliciesForbidden {
	return &ITAutomationUpdatePoliciesForbidden{}
}

/*
ITAutomationUpdatePoliciesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ITAutomationUpdatePoliciesForbidden struct {

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

// IsSuccess returns true when this i t automation update policies forbidden response has a 2xx status code
func (o *ITAutomationUpdatePoliciesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policies forbidden response has a 3xx status code
func (o *ITAutomationUpdatePoliciesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies forbidden response has a 4xx status code
func (o *ITAutomationUpdatePoliciesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policies forbidden response has a 5xx status code
func (o *ITAutomationUpdatePoliciesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policies forbidden response a status code equal to that given
func (o *ITAutomationUpdatePoliciesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the i t automation update policies forbidden response
func (o *ITAutomationUpdatePoliciesForbidden) Code() int {
	return 403
}

func (o *ITAutomationUpdatePoliciesForbidden) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies/v1][%d] iTAutomationUpdatePoliciesForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationUpdatePoliciesForbidden) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies/v1][%d] iTAutomationUpdatePoliciesForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationUpdatePoliciesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePoliciesTooManyRequests creates a ITAutomationUpdatePoliciesTooManyRequests with default headers values
func NewITAutomationUpdatePoliciesTooManyRequests() *ITAutomationUpdatePoliciesTooManyRequests {
	return &ITAutomationUpdatePoliciesTooManyRequests{}
}

/*
ITAutomationUpdatePoliciesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ITAutomationUpdatePoliciesTooManyRequests struct {

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

// IsSuccess returns true when this i t automation update policies too many requests response has a 2xx status code
func (o *ITAutomationUpdatePoliciesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policies too many requests response has a 3xx status code
func (o *ITAutomationUpdatePoliciesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies too many requests response has a 4xx status code
func (o *ITAutomationUpdatePoliciesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policies too many requests response has a 5xx status code
func (o *ITAutomationUpdatePoliciesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policies too many requests response a status code equal to that given
func (o *ITAutomationUpdatePoliciesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the i t automation update policies too many requests response
func (o *ITAutomationUpdatePoliciesTooManyRequests) Code() int {
	return 429
}

func (o *ITAutomationUpdatePoliciesTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies/v1][%d] iTAutomationUpdatePoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationUpdatePoliciesTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies/v1][%d] iTAutomationUpdatePoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationUpdatePoliciesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePoliciesInternalServerError creates a ITAutomationUpdatePoliciesInternalServerError with default headers values
func NewITAutomationUpdatePoliciesInternalServerError() *ITAutomationUpdatePoliciesInternalServerError {
	return &ITAutomationUpdatePoliciesInternalServerError{}
}

/*
ITAutomationUpdatePoliciesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ITAutomationUpdatePoliciesInternalServerError struct {

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

// IsSuccess returns true when this i t automation update policies internal server error response has a 2xx status code
func (o *ITAutomationUpdatePoliciesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policies internal server error response has a 3xx status code
func (o *ITAutomationUpdatePoliciesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policies internal server error response has a 4xx status code
func (o *ITAutomationUpdatePoliciesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation update policies internal server error response has a 5xx status code
func (o *ITAutomationUpdatePoliciesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this i t automation update policies internal server error response a status code equal to that given
func (o *ITAutomationUpdatePoliciesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the i t automation update policies internal server error response
func (o *ITAutomationUpdatePoliciesInternalServerError) Code() int {
	return 500
}

func (o *ITAutomationUpdatePoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies/v1][%d] iTAutomationUpdatePoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationUpdatePoliciesInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies/v1][%d] iTAutomationUpdatePoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationUpdatePoliciesInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationUpdatePoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
