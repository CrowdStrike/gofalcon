// Code generated by go-swagger; DO NOT EDIT.

package identity_protection

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

// APIPreemptProxyGetPolicyRulesReader is a Reader for the APIPreemptProxyGetPolicyRules structure.
type APIPreemptProxyGetPolicyRulesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *APIPreemptProxyGetPolicyRulesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAPIPreemptProxyGetPolicyRulesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewAPIPreemptProxyGetPolicyRulesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAPIPreemptProxyGetPolicyRulesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewAPIPreemptProxyGetPolicyRulesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /identity-protection/entities/policy-rules/v1] api.preempt.proxy.get.policy-rules", response, response.Code())
	}
}

// NewAPIPreemptProxyGetPolicyRulesOK creates a APIPreemptProxyGetPolicyRulesOK with default headers values
func NewAPIPreemptProxyGetPolicyRulesOK() *APIPreemptProxyGetPolicyRulesOK {
	return &APIPreemptProxyGetPolicyRulesOK{}
}

/*
APIPreemptProxyGetPolicyRulesOK describes a response with status code 200, with default header values.

OK
*/
type APIPreemptProxyGetPolicyRulesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64
}

// IsSuccess returns true when this api preempt proxy get policy rules o k response has a 2xx status code
func (o *APIPreemptProxyGetPolicyRulesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this api preempt proxy get policy rules o k response has a 3xx status code
func (o *APIPreemptProxyGetPolicyRulesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this api preempt proxy get policy rules o k response has a 4xx status code
func (o *APIPreemptProxyGetPolicyRulesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this api preempt proxy get policy rules o k response has a 5xx status code
func (o *APIPreemptProxyGetPolicyRulesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this api preempt proxy get policy rules o k response a status code equal to that given
func (o *APIPreemptProxyGetPolicyRulesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the api preempt proxy get policy rules o k response
func (o *APIPreemptProxyGetPolicyRulesOK) Code() int {
	return 200
}

func (o *APIPreemptProxyGetPolicyRulesOK) Error() string {
	return fmt.Sprintf("[GET /identity-protection/entities/policy-rules/v1][%d] apiPreemptProxyGetPolicyRulesOK ", 200)
}

func (o *APIPreemptProxyGetPolicyRulesOK) String() string {
	return fmt.Sprintf("[GET /identity-protection/entities/policy-rules/v1][%d] apiPreemptProxyGetPolicyRulesOK ", 200)
}

func (o *APIPreemptProxyGetPolicyRulesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	return nil
}

// NewAPIPreemptProxyGetPolicyRulesForbidden creates a APIPreemptProxyGetPolicyRulesForbidden with default headers values
func NewAPIPreemptProxyGetPolicyRulesForbidden() *APIPreemptProxyGetPolicyRulesForbidden {
	return &APIPreemptProxyGetPolicyRulesForbidden{}
}

/*
APIPreemptProxyGetPolicyRulesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type APIPreemptProxyGetPolicyRulesForbidden struct {

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

// IsSuccess returns true when this api preempt proxy get policy rules forbidden response has a 2xx status code
func (o *APIPreemptProxyGetPolicyRulesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this api preempt proxy get policy rules forbidden response has a 3xx status code
func (o *APIPreemptProxyGetPolicyRulesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this api preempt proxy get policy rules forbidden response has a 4xx status code
func (o *APIPreemptProxyGetPolicyRulesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this api preempt proxy get policy rules forbidden response has a 5xx status code
func (o *APIPreemptProxyGetPolicyRulesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this api preempt proxy get policy rules forbidden response a status code equal to that given
func (o *APIPreemptProxyGetPolicyRulesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the api preempt proxy get policy rules forbidden response
func (o *APIPreemptProxyGetPolicyRulesForbidden) Code() int {
	return 403
}

func (o *APIPreemptProxyGetPolicyRulesForbidden) Error() string {
	return fmt.Sprintf("[GET /identity-protection/entities/policy-rules/v1][%d] apiPreemptProxyGetPolicyRulesForbidden  %+v", 403, o.Payload)
}

func (o *APIPreemptProxyGetPolicyRulesForbidden) String() string {
	return fmt.Sprintf("[GET /identity-protection/entities/policy-rules/v1][%d] apiPreemptProxyGetPolicyRulesForbidden  %+v", 403, o.Payload)
}

func (o *APIPreemptProxyGetPolicyRulesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *APIPreemptProxyGetPolicyRulesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewAPIPreemptProxyGetPolicyRulesTooManyRequests creates a APIPreemptProxyGetPolicyRulesTooManyRequests with default headers values
func NewAPIPreemptProxyGetPolicyRulesTooManyRequests() *APIPreemptProxyGetPolicyRulesTooManyRequests {
	return &APIPreemptProxyGetPolicyRulesTooManyRequests{}
}

/*
APIPreemptProxyGetPolicyRulesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type APIPreemptProxyGetPolicyRulesTooManyRequests struct {

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

// IsSuccess returns true when this api preempt proxy get policy rules too many requests response has a 2xx status code
func (o *APIPreemptProxyGetPolicyRulesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this api preempt proxy get policy rules too many requests response has a 3xx status code
func (o *APIPreemptProxyGetPolicyRulesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this api preempt proxy get policy rules too many requests response has a 4xx status code
func (o *APIPreemptProxyGetPolicyRulesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this api preempt proxy get policy rules too many requests response has a 5xx status code
func (o *APIPreemptProxyGetPolicyRulesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this api preempt proxy get policy rules too many requests response a status code equal to that given
func (o *APIPreemptProxyGetPolicyRulesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the api preempt proxy get policy rules too many requests response
func (o *APIPreemptProxyGetPolicyRulesTooManyRequests) Code() int {
	return 429
}

func (o *APIPreemptProxyGetPolicyRulesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /identity-protection/entities/policy-rules/v1][%d] apiPreemptProxyGetPolicyRulesTooManyRequests  %+v", 429, o.Payload)
}

func (o *APIPreemptProxyGetPolicyRulesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /identity-protection/entities/policy-rules/v1][%d] apiPreemptProxyGetPolicyRulesTooManyRequests  %+v", 429, o.Payload)
}

func (o *APIPreemptProxyGetPolicyRulesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *APIPreemptProxyGetPolicyRulesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewAPIPreemptProxyGetPolicyRulesInternalServerError creates a APIPreemptProxyGetPolicyRulesInternalServerError with default headers values
func NewAPIPreemptProxyGetPolicyRulesInternalServerError() *APIPreemptProxyGetPolicyRulesInternalServerError {
	return &APIPreemptProxyGetPolicyRulesInternalServerError{}
}

/*
APIPreemptProxyGetPolicyRulesInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type APIPreemptProxyGetPolicyRulesInternalServerError struct {

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

// IsSuccess returns true when this api preempt proxy get policy rules internal server error response has a 2xx status code
func (o *APIPreemptProxyGetPolicyRulesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this api preempt proxy get policy rules internal server error response has a 3xx status code
func (o *APIPreemptProxyGetPolicyRulesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this api preempt proxy get policy rules internal server error response has a 4xx status code
func (o *APIPreemptProxyGetPolicyRulesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this api preempt proxy get policy rules internal server error response has a 5xx status code
func (o *APIPreemptProxyGetPolicyRulesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this api preempt proxy get policy rules internal server error response a status code equal to that given
func (o *APIPreemptProxyGetPolicyRulesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the api preempt proxy get policy rules internal server error response
func (o *APIPreemptProxyGetPolicyRulesInternalServerError) Code() int {
	return 500
}

func (o *APIPreemptProxyGetPolicyRulesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /identity-protection/entities/policy-rules/v1][%d] apiPreemptProxyGetPolicyRulesInternalServerError  %+v", 500, o.Payload)
}

func (o *APIPreemptProxyGetPolicyRulesInternalServerError) String() string {
	return fmt.Sprintf("[GET /identity-protection/entities/policy-rules/v1][%d] apiPreemptProxyGetPolicyRulesInternalServerError  %+v", 500, o.Payload)
}

func (o *APIPreemptProxyGetPolicyRulesInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *APIPreemptProxyGetPolicyRulesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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