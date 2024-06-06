// Code generated by go-swagger; DO NOT EDIT.

package prevention_policies

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

// SetPreventionPoliciesPrecedenceReader is a Reader for the SetPreventionPoliciesPrecedence structure.
type SetPreventionPoliciesPrecedenceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetPreventionPoliciesPrecedenceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSetPreventionPoliciesPrecedenceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSetPreventionPoliciesPrecedenceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSetPreventionPoliciesPrecedenceForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSetPreventionPoliciesPrecedenceTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewSetPreventionPoliciesPrecedenceInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /policy/entities/prevention-precedence/v1] setPreventionPoliciesPrecedence", response, response.Code())
	}
}

// NewSetPreventionPoliciesPrecedenceOK creates a SetPreventionPoliciesPrecedenceOK with default headers values
func NewSetPreventionPoliciesPrecedenceOK() *SetPreventionPoliciesPrecedenceOK {
	return &SetPreventionPoliciesPrecedenceOK{}
}

/*
SetPreventionPoliciesPrecedenceOK describes a response with status code 200, with default header values.

OK
*/
type SetPreventionPoliciesPrecedenceOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaQueryResponse
}

// IsSuccess returns true when this set prevention policies precedence o k response has a 2xx status code
func (o *SetPreventionPoliciesPrecedenceOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this set prevention policies precedence o k response has a 3xx status code
func (o *SetPreventionPoliciesPrecedenceOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set prevention policies precedence o k response has a 4xx status code
func (o *SetPreventionPoliciesPrecedenceOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this set prevention policies precedence o k response has a 5xx status code
func (o *SetPreventionPoliciesPrecedenceOK) IsServerError() bool {
	return false
}

// IsCode returns true when this set prevention policies precedence o k response a status code equal to that given
func (o *SetPreventionPoliciesPrecedenceOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the set prevention policies precedence o k response
func (o *SetPreventionPoliciesPrecedenceOK) Code() int {
	return 200
}

func (o *SetPreventionPoliciesPrecedenceOK) Error() string {
	return fmt.Sprintf("[POST /policy/entities/prevention-precedence/v1][%d] setPreventionPoliciesPrecedenceOK  %+v", 200, o.Payload)
}

func (o *SetPreventionPoliciesPrecedenceOK) String() string {
	return fmt.Sprintf("[POST /policy/entities/prevention-precedence/v1][%d] setPreventionPoliciesPrecedenceOK  %+v", 200, o.Payload)
}

func (o *SetPreventionPoliciesPrecedenceOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *SetPreventionPoliciesPrecedenceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetPreventionPoliciesPrecedenceBadRequest creates a SetPreventionPoliciesPrecedenceBadRequest with default headers values
func NewSetPreventionPoliciesPrecedenceBadRequest() *SetPreventionPoliciesPrecedenceBadRequest {
	return &SetPreventionPoliciesPrecedenceBadRequest{}
}

/*
SetPreventionPoliciesPrecedenceBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type SetPreventionPoliciesPrecedenceBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaQueryResponse
}

// IsSuccess returns true when this set prevention policies precedence bad request response has a 2xx status code
func (o *SetPreventionPoliciesPrecedenceBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set prevention policies precedence bad request response has a 3xx status code
func (o *SetPreventionPoliciesPrecedenceBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set prevention policies precedence bad request response has a 4xx status code
func (o *SetPreventionPoliciesPrecedenceBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this set prevention policies precedence bad request response has a 5xx status code
func (o *SetPreventionPoliciesPrecedenceBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this set prevention policies precedence bad request response a status code equal to that given
func (o *SetPreventionPoliciesPrecedenceBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the set prevention policies precedence bad request response
func (o *SetPreventionPoliciesPrecedenceBadRequest) Code() int {
	return 400
}

func (o *SetPreventionPoliciesPrecedenceBadRequest) Error() string {
	return fmt.Sprintf("[POST /policy/entities/prevention-precedence/v1][%d] setPreventionPoliciesPrecedenceBadRequest  %+v", 400, o.Payload)
}

func (o *SetPreventionPoliciesPrecedenceBadRequest) String() string {
	return fmt.Sprintf("[POST /policy/entities/prevention-precedence/v1][%d] setPreventionPoliciesPrecedenceBadRequest  %+v", 400, o.Payload)
}

func (o *SetPreventionPoliciesPrecedenceBadRequest) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *SetPreventionPoliciesPrecedenceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetPreventionPoliciesPrecedenceForbidden creates a SetPreventionPoliciesPrecedenceForbidden with default headers values
func NewSetPreventionPoliciesPrecedenceForbidden() *SetPreventionPoliciesPrecedenceForbidden {
	return &SetPreventionPoliciesPrecedenceForbidden{}
}

/*
SetPreventionPoliciesPrecedenceForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SetPreventionPoliciesPrecedenceForbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this set prevention policies precedence forbidden response has a 2xx status code
func (o *SetPreventionPoliciesPrecedenceForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set prevention policies precedence forbidden response has a 3xx status code
func (o *SetPreventionPoliciesPrecedenceForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set prevention policies precedence forbidden response has a 4xx status code
func (o *SetPreventionPoliciesPrecedenceForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this set prevention policies precedence forbidden response has a 5xx status code
func (o *SetPreventionPoliciesPrecedenceForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this set prevention policies precedence forbidden response a status code equal to that given
func (o *SetPreventionPoliciesPrecedenceForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the set prevention policies precedence forbidden response
func (o *SetPreventionPoliciesPrecedenceForbidden) Code() int {
	return 403
}

func (o *SetPreventionPoliciesPrecedenceForbidden) Error() string {
	return fmt.Sprintf("[POST /policy/entities/prevention-precedence/v1][%d] setPreventionPoliciesPrecedenceForbidden  %+v", 403, o.Payload)
}

func (o *SetPreventionPoliciesPrecedenceForbidden) String() string {
	return fmt.Sprintf("[POST /policy/entities/prevention-precedence/v1][%d] setPreventionPoliciesPrecedenceForbidden  %+v", 403, o.Payload)
}

func (o *SetPreventionPoliciesPrecedenceForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *SetPreventionPoliciesPrecedenceForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetPreventionPoliciesPrecedenceTooManyRequests creates a SetPreventionPoliciesPrecedenceTooManyRequests with default headers values
func NewSetPreventionPoliciesPrecedenceTooManyRequests() *SetPreventionPoliciesPrecedenceTooManyRequests {
	return &SetPreventionPoliciesPrecedenceTooManyRequests{}
}

/*
SetPreventionPoliciesPrecedenceTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type SetPreventionPoliciesPrecedenceTooManyRequests struct {

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

// IsSuccess returns true when this set prevention policies precedence too many requests response has a 2xx status code
func (o *SetPreventionPoliciesPrecedenceTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set prevention policies precedence too many requests response has a 3xx status code
func (o *SetPreventionPoliciesPrecedenceTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set prevention policies precedence too many requests response has a 4xx status code
func (o *SetPreventionPoliciesPrecedenceTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this set prevention policies precedence too many requests response has a 5xx status code
func (o *SetPreventionPoliciesPrecedenceTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this set prevention policies precedence too many requests response a status code equal to that given
func (o *SetPreventionPoliciesPrecedenceTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the set prevention policies precedence too many requests response
func (o *SetPreventionPoliciesPrecedenceTooManyRequests) Code() int {
	return 429
}

func (o *SetPreventionPoliciesPrecedenceTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /policy/entities/prevention-precedence/v1][%d] setPreventionPoliciesPrecedenceTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetPreventionPoliciesPrecedenceTooManyRequests) String() string {
	return fmt.Sprintf("[POST /policy/entities/prevention-precedence/v1][%d] setPreventionPoliciesPrecedenceTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetPreventionPoliciesPrecedenceTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *SetPreventionPoliciesPrecedenceTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSetPreventionPoliciesPrecedenceInternalServerError creates a SetPreventionPoliciesPrecedenceInternalServerError with default headers values
func NewSetPreventionPoliciesPrecedenceInternalServerError() *SetPreventionPoliciesPrecedenceInternalServerError {
	return &SetPreventionPoliciesPrecedenceInternalServerError{}
}

/*
SetPreventionPoliciesPrecedenceInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type SetPreventionPoliciesPrecedenceInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaQueryResponse
}

// IsSuccess returns true when this set prevention policies precedence internal server error response has a 2xx status code
func (o *SetPreventionPoliciesPrecedenceInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set prevention policies precedence internal server error response has a 3xx status code
func (o *SetPreventionPoliciesPrecedenceInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set prevention policies precedence internal server error response has a 4xx status code
func (o *SetPreventionPoliciesPrecedenceInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this set prevention policies precedence internal server error response has a 5xx status code
func (o *SetPreventionPoliciesPrecedenceInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this set prevention policies precedence internal server error response a status code equal to that given
func (o *SetPreventionPoliciesPrecedenceInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the set prevention policies precedence internal server error response
func (o *SetPreventionPoliciesPrecedenceInternalServerError) Code() int {
	return 500
}

func (o *SetPreventionPoliciesPrecedenceInternalServerError) Error() string {
	return fmt.Sprintf("[POST /policy/entities/prevention-precedence/v1][%d] setPreventionPoliciesPrecedenceInternalServerError  %+v", 500, o.Payload)
}

func (o *SetPreventionPoliciesPrecedenceInternalServerError) String() string {
	return fmt.Sprintf("[POST /policy/entities/prevention-precedence/v1][%d] setPreventionPoliciesPrecedenceInternalServerError  %+v", 500, o.Payload)
}

func (o *SetPreventionPoliciesPrecedenceInternalServerError) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *SetPreventionPoliciesPrecedenceInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
