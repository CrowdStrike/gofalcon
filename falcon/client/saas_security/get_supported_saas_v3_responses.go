// Code generated by go-swagger; DO NOT EDIT.

package saas_security

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

// GetSupportedSaasV3Reader is a Reader for the GetSupportedSaasV3 structure.
type GetSupportedSaasV3Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetSupportedSaasV3Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetSupportedSaasV3OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewGetSupportedSaasV3Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetSupportedSaasV3TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetSupportedSaasV3InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /saas-security/entities/supported-saas/v3] GetSupportedSaasV3", response, response.Code())
	}
}

// NewGetSupportedSaasV3OK creates a GetSupportedSaasV3OK with default headers values
func NewGetSupportedSaasV3OK() *GetSupportedSaasV3OK {
	return &GetSupportedSaasV3OK{}
}

/*
GetSupportedSaasV3OK describes a response with status code 200, with default header values.

GetSupportedSaasV3OK get supported saas v3 o k
*/
type GetSupportedSaasV3OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.GetSupportedSaas
}

// IsSuccess returns true when this get supported saas v3 o k response has a 2xx status code
func (o *GetSupportedSaasV3OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get supported saas v3 o k response has a 3xx status code
func (o *GetSupportedSaasV3OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get supported saas v3 o k response has a 4xx status code
func (o *GetSupportedSaasV3OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get supported saas v3 o k response has a 5xx status code
func (o *GetSupportedSaasV3OK) IsServerError() bool {
	return false
}

// IsCode returns true when this get supported saas v3 o k response a status code equal to that given
func (o *GetSupportedSaasV3OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get supported saas v3 o k response
func (o *GetSupportedSaasV3OK) Code() int {
	return 200
}

func (o *GetSupportedSaasV3OK) Error() string {
	return fmt.Sprintf("[GET /saas-security/entities/supported-saas/v3][%d] getSupportedSaasV3OK  %+v", 200, o.Payload)
}

func (o *GetSupportedSaasV3OK) String() string {
	return fmt.Sprintf("[GET /saas-security/entities/supported-saas/v3][%d] getSupportedSaasV3OK  %+v", 200, o.Payload)
}

func (o *GetSupportedSaasV3OK) GetPayload() *models.GetSupportedSaas {
	return o.Payload
}

func (o *GetSupportedSaasV3OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.GetSupportedSaas)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSupportedSaasV3Forbidden creates a GetSupportedSaasV3Forbidden with default headers values
func NewGetSupportedSaasV3Forbidden() *GetSupportedSaasV3Forbidden {
	return &GetSupportedSaasV3Forbidden{}
}

/*
GetSupportedSaasV3Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetSupportedSaasV3Forbidden struct {

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

// IsSuccess returns true when this get supported saas v3 forbidden response has a 2xx status code
func (o *GetSupportedSaasV3Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get supported saas v3 forbidden response has a 3xx status code
func (o *GetSupportedSaasV3Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get supported saas v3 forbidden response has a 4xx status code
func (o *GetSupportedSaasV3Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get supported saas v3 forbidden response has a 5xx status code
func (o *GetSupportedSaasV3Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get supported saas v3 forbidden response a status code equal to that given
func (o *GetSupportedSaasV3Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get supported saas v3 forbidden response
func (o *GetSupportedSaasV3Forbidden) Code() int {
	return 403
}

func (o *GetSupportedSaasV3Forbidden) Error() string {
	return fmt.Sprintf("[GET /saas-security/entities/supported-saas/v3][%d] getSupportedSaasV3Forbidden  %+v", 403, o.Payload)
}

func (o *GetSupportedSaasV3Forbidden) String() string {
	return fmt.Sprintf("[GET /saas-security/entities/supported-saas/v3][%d] getSupportedSaasV3Forbidden  %+v", 403, o.Payload)
}

func (o *GetSupportedSaasV3Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetSupportedSaasV3Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetSupportedSaasV3TooManyRequests creates a GetSupportedSaasV3TooManyRequests with default headers values
func NewGetSupportedSaasV3TooManyRequests() *GetSupportedSaasV3TooManyRequests {
	return &GetSupportedSaasV3TooManyRequests{}
}

/*
GetSupportedSaasV3TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetSupportedSaasV3TooManyRequests struct {

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

// IsSuccess returns true when this get supported saas v3 too many requests response has a 2xx status code
func (o *GetSupportedSaasV3TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get supported saas v3 too many requests response has a 3xx status code
func (o *GetSupportedSaasV3TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get supported saas v3 too many requests response has a 4xx status code
func (o *GetSupportedSaasV3TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get supported saas v3 too many requests response has a 5xx status code
func (o *GetSupportedSaasV3TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get supported saas v3 too many requests response a status code equal to that given
func (o *GetSupportedSaasV3TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get supported saas v3 too many requests response
func (o *GetSupportedSaasV3TooManyRequests) Code() int {
	return 429
}

func (o *GetSupportedSaasV3TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /saas-security/entities/supported-saas/v3][%d] getSupportedSaasV3TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetSupportedSaasV3TooManyRequests) String() string {
	return fmt.Sprintf("[GET /saas-security/entities/supported-saas/v3][%d] getSupportedSaasV3TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetSupportedSaasV3TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetSupportedSaasV3TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetSupportedSaasV3InternalServerError creates a GetSupportedSaasV3InternalServerError with default headers values
func NewGetSupportedSaasV3InternalServerError() *GetSupportedSaasV3InternalServerError {
	return &GetSupportedSaasV3InternalServerError{}
}

/*
GetSupportedSaasV3InternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type GetSupportedSaasV3InternalServerError struct {

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

// IsSuccess returns true when this get supported saas v3 internal server error response has a 2xx status code
func (o *GetSupportedSaasV3InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get supported saas v3 internal server error response has a 3xx status code
func (o *GetSupportedSaasV3InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get supported saas v3 internal server error response has a 4xx status code
func (o *GetSupportedSaasV3InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get supported saas v3 internal server error response has a 5xx status code
func (o *GetSupportedSaasV3InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get supported saas v3 internal server error response a status code equal to that given
func (o *GetSupportedSaasV3InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get supported saas v3 internal server error response
func (o *GetSupportedSaasV3InternalServerError) Code() int {
	return 500
}

func (o *GetSupportedSaasV3InternalServerError) Error() string {
	return fmt.Sprintf("[GET /saas-security/entities/supported-saas/v3][%d] getSupportedSaasV3InternalServerError  %+v", 500, o.Payload)
}

func (o *GetSupportedSaasV3InternalServerError) String() string {
	return fmt.Sprintf("[GET /saas-security/entities/supported-saas/v3][%d] getSupportedSaasV3InternalServerError  %+v", 500, o.Payload)
}

func (o *GetSupportedSaasV3InternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetSupportedSaasV3InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
