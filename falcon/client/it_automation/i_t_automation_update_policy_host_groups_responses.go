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

// ITAutomationUpdatePolicyHostGroupsReader is a Reader for the ITAutomationUpdatePolicyHostGroups structure.
type ITAutomationUpdatePolicyHostGroupsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ITAutomationUpdatePolicyHostGroupsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewITAutomationUpdatePolicyHostGroupsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewITAutomationUpdatePolicyHostGroupsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewITAutomationUpdatePolicyHostGroupsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewITAutomationUpdatePolicyHostGroupsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewITAutomationUpdatePolicyHostGroupsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewITAutomationUpdatePolicyHostGroupsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /it-automation/entities/policies-host-groups/v1] ITAutomationUpdatePolicyHostGroups", response, response.Code())
	}
}

// NewITAutomationUpdatePolicyHostGroupsOK creates a ITAutomationUpdatePolicyHostGroupsOK with default headers values
func NewITAutomationUpdatePolicyHostGroupsOK() *ITAutomationUpdatePolicyHostGroupsOK {
	return &ITAutomationUpdatePolicyHostGroupsOK{}
}

/*
ITAutomationUpdatePolicyHostGroupsOK describes a response with status code 200, with default header values.

OK
*/
type ITAutomationUpdatePolicyHostGroupsOK struct {

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

// IsSuccess returns true when this i t automation update policy host groups o k response has a 2xx status code
func (o *ITAutomationUpdatePolicyHostGroupsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation update policy host groups o k response has a 3xx status code
func (o *ITAutomationUpdatePolicyHostGroupsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policy host groups o k response has a 4xx status code
func (o *ITAutomationUpdatePolicyHostGroupsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation update policy host groups o k response has a 5xx status code
func (o *ITAutomationUpdatePolicyHostGroupsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policy host groups o k response a status code equal to that given
func (o *ITAutomationUpdatePolicyHostGroupsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the i t automation update policy host groups o k response
func (o *ITAutomationUpdatePolicyHostGroupsOK) Code() int {
	return 200
}

func (o *ITAutomationUpdatePolicyHostGroupsOK) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsOK  %+v", 200, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsOK) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsOK  %+v", 200, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsOK) GetPayload() *models.ItautomationUpdatePolicyResponse {
	return o.Payload
}

func (o *ITAutomationUpdatePolicyHostGroupsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePolicyHostGroupsBadRequest creates a ITAutomationUpdatePolicyHostGroupsBadRequest with default headers values
func NewITAutomationUpdatePolicyHostGroupsBadRequest() *ITAutomationUpdatePolicyHostGroupsBadRequest {
	return &ITAutomationUpdatePolicyHostGroupsBadRequest{}
}

/*
ITAutomationUpdatePolicyHostGroupsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ITAutomationUpdatePolicyHostGroupsBadRequest struct {

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

// IsSuccess returns true when this i t automation update policy host groups bad request response has a 2xx status code
func (o *ITAutomationUpdatePolicyHostGroupsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policy host groups bad request response has a 3xx status code
func (o *ITAutomationUpdatePolicyHostGroupsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policy host groups bad request response has a 4xx status code
func (o *ITAutomationUpdatePolicyHostGroupsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policy host groups bad request response has a 5xx status code
func (o *ITAutomationUpdatePolicyHostGroupsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policy host groups bad request response a status code equal to that given
func (o *ITAutomationUpdatePolicyHostGroupsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the i t automation update policy host groups bad request response
func (o *ITAutomationUpdatePolicyHostGroupsBadRequest) Code() int {
	return 400
}

func (o *ITAutomationUpdatePolicyHostGroupsBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsBadRequest) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationUpdatePolicyHostGroupsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePolicyHostGroupsForbidden creates a ITAutomationUpdatePolicyHostGroupsForbidden with default headers values
func NewITAutomationUpdatePolicyHostGroupsForbidden() *ITAutomationUpdatePolicyHostGroupsForbidden {
	return &ITAutomationUpdatePolicyHostGroupsForbidden{}
}

/*
ITAutomationUpdatePolicyHostGroupsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ITAutomationUpdatePolicyHostGroupsForbidden struct {

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

// IsSuccess returns true when this i t automation update policy host groups forbidden response has a 2xx status code
func (o *ITAutomationUpdatePolicyHostGroupsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policy host groups forbidden response has a 3xx status code
func (o *ITAutomationUpdatePolicyHostGroupsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policy host groups forbidden response has a 4xx status code
func (o *ITAutomationUpdatePolicyHostGroupsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policy host groups forbidden response has a 5xx status code
func (o *ITAutomationUpdatePolicyHostGroupsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policy host groups forbidden response a status code equal to that given
func (o *ITAutomationUpdatePolicyHostGroupsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the i t automation update policy host groups forbidden response
func (o *ITAutomationUpdatePolicyHostGroupsForbidden) Code() int {
	return 403
}

func (o *ITAutomationUpdatePolicyHostGroupsForbidden) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsForbidden) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationUpdatePolicyHostGroupsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePolicyHostGroupsNotFound creates a ITAutomationUpdatePolicyHostGroupsNotFound with default headers values
func NewITAutomationUpdatePolicyHostGroupsNotFound() *ITAutomationUpdatePolicyHostGroupsNotFound {
	return &ITAutomationUpdatePolicyHostGroupsNotFound{}
}

/*
ITAutomationUpdatePolicyHostGroupsNotFound describes a response with status code 404, with default header values.

Not Found
*/
type ITAutomationUpdatePolicyHostGroupsNotFound struct {

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

// IsSuccess returns true when this i t automation update policy host groups not found response has a 2xx status code
func (o *ITAutomationUpdatePolicyHostGroupsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policy host groups not found response has a 3xx status code
func (o *ITAutomationUpdatePolicyHostGroupsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policy host groups not found response has a 4xx status code
func (o *ITAutomationUpdatePolicyHostGroupsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policy host groups not found response has a 5xx status code
func (o *ITAutomationUpdatePolicyHostGroupsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policy host groups not found response a status code equal to that given
func (o *ITAutomationUpdatePolicyHostGroupsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the i t automation update policy host groups not found response
func (o *ITAutomationUpdatePolicyHostGroupsNotFound) Code() int {
	return 404
}

func (o *ITAutomationUpdatePolicyHostGroupsNotFound) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsNotFound  %+v", 404, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsNotFound) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsNotFound  %+v", 404, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationUpdatePolicyHostGroupsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePolicyHostGroupsTooManyRequests creates a ITAutomationUpdatePolicyHostGroupsTooManyRequests with default headers values
func NewITAutomationUpdatePolicyHostGroupsTooManyRequests() *ITAutomationUpdatePolicyHostGroupsTooManyRequests {
	return &ITAutomationUpdatePolicyHostGroupsTooManyRequests{}
}

/*
ITAutomationUpdatePolicyHostGroupsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ITAutomationUpdatePolicyHostGroupsTooManyRequests struct {

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

// IsSuccess returns true when this i t automation update policy host groups too many requests response has a 2xx status code
func (o *ITAutomationUpdatePolicyHostGroupsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policy host groups too many requests response has a 3xx status code
func (o *ITAutomationUpdatePolicyHostGroupsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policy host groups too many requests response has a 4xx status code
func (o *ITAutomationUpdatePolicyHostGroupsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update policy host groups too many requests response has a 5xx status code
func (o *ITAutomationUpdatePolicyHostGroupsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update policy host groups too many requests response a status code equal to that given
func (o *ITAutomationUpdatePolicyHostGroupsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the i t automation update policy host groups too many requests response
func (o *ITAutomationUpdatePolicyHostGroupsTooManyRequests) Code() int {
	return 429
}

func (o *ITAutomationUpdatePolicyHostGroupsTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationUpdatePolicyHostGroupsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdatePolicyHostGroupsInternalServerError creates a ITAutomationUpdatePolicyHostGroupsInternalServerError with default headers values
func NewITAutomationUpdatePolicyHostGroupsInternalServerError() *ITAutomationUpdatePolicyHostGroupsInternalServerError {
	return &ITAutomationUpdatePolicyHostGroupsInternalServerError{}
}

/*
ITAutomationUpdatePolicyHostGroupsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ITAutomationUpdatePolicyHostGroupsInternalServerError struct {

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

// IsSuccess returns true when this i t automation update policy host groups internal server error response has a 2xx status code
func (o *ITAutomationUpdatePolicyHostGroupsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update policy host groups internal server error response has a 3xx status code
func (o *ITAutomationUpdatePolicyHostGroupsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update policy host groups internal server error response has a 4xx status code
func (o *ITAutomationUpdatePolicyHostGroupsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation update policy host groups internal server error response has a 5xx status code
func (o *ITAutomationUpdatePolicyHostGroupsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this i t automation update policy host groups internal server error response a status code equal to that given
func (o *ITAutomationUpdatePolicyHostGroupsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the i t automation update policy host groups internal server error response
func (o *ITAutomationUpdatePolicyHostGroupsInternalServerError) Code() int {
	return 500
}

func (o *ITAutomationUpdatePolicyHostGroupsInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/policies-host-groups/v1][%d] iTAutomationUpdatePolicyHostGroupsInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationUpdatePolicyHostGroupsInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationUpdatePolicyHostGroupsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
