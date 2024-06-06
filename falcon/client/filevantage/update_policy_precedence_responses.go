// Code generated by go-swagger; DO NOT EDIT.

package filevantage

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

// UpdatePolicyPrecedenceReader is a Reader for the UpdatePolicyPrecedence structure.
type UpdatePolicyPrecedenceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdatePolicyPrecedenceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdatePolicyPrecedenceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdatePolicyPrecedenceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdatePolicyPrecedenceForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewUpdatePolicyPrecedenceConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdatePolicyPrecedenceTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpdatePolicyPrecedenceInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /filevantage/entities/policies-precedence/v1] updatePolicyPrecedence", response, response.Code())
	}
}

// NewUpdatePolicyPrecedenceOK creates a UpdatePolicyPrecedenceOK with default headers values
func NewUpdatePolicyPrecedenceOK() *UpdatePolicyPrecedenceOK {
	return &UpdatePolicyPrecedenceOK{}
}

/*
UpdatePolicyPrecedenceOK describes a response with status code 200, with default header values.

Policy Precedence Updated.
*/
type UpdatePolicyPrecedenceOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.PoliciesPrecedenceResponse
}

// IsSuccess returns true when this update policy precedence o k response has a 2xx status code
func (o *UpdatePolicyPrecedenceOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update policy precedence o k response has a 3xx status code
func (o *UpdatePolicyPrecedenceOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy precedence o k response has a 4xx status code
func (o *UpdatePolicyPrecedenceOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update policy precedence o k response has a 5xx status code
func (o *UpdatePolicyPrecedenceOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy precedence o k response a status code equal to that given
func (o *UpdatePolicyPrecedenceOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update policy precedence o k response
func (o *UpdatePolicyPrecedenceOK) Code() int {
	return 200
}

func (o *UpdatePolicyPrecedenceOK) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceOK  %+v", 200, o.Payload)
}

func (o *UpdatePolicyPrecedenceOK) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceOK  %+v", 200, o.Payload)
}

func (o *UpdatePolicyPrecedenceOK) GetPayload() *models.PoliciesPrecedenceResponse {
	return o.Payload
}

func (o *UpdatePolicyPrecedenceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.PoliciesPrecedenceResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePolicyPrecedenceBadRequest creates a UpdatePolicyPrecedenceBadRequest with default headers values
func NewUpdatePolicyPrecedenceBadRequest() *UpdatePolicyPrecedenceBadRequest {
	return &UpdatePolicyPrecedenceBadRequest{}
}

/*
UpdatePolicyPrecedenceBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type UpdatePolicyPrecedenceBadRequest struct {

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

// IsSuccess returns true when this update policy precedence bad request response has a 2xx status code
func (o *UpdatePolicyPrecedenceBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy precedence bad request response has a 3xx status code
func (o *UpdatePolicyPrecedenceBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy precedence bad request response has a 4xx status code
func (o *UpdatePolicyPrecedenceBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy precedence bad request response has a 5xx status code
func (o *UpdatePolicyPrecedenceBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy precedence bad request response a status code equal to that given
func (o *UpdatePolicyPrecedenceBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update policy precedence bad request response
func (o *UpdatePolicyPrecedenceBadRequest) Code() int {
	return 400
}

func (o *UpdatePolicyPrecedenceBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceBadRequest  %+v", 400, o.Payload)
}

func (o *UpdatePolicyPrecedenceBadRequest) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceBadRequest  %+v", 400, o.Payload)
}

func (o *UpdatePolicyPrecedenceBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdatePolicyPrecedenceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePolicyPrecedenceForbidden creates a UpdatePolicyPrecedenceForbidden with default headers values
func NewUpdatePolicyPrecedenceForbidden() *UpdatePolicyPrecedenceForbidden {
	return &UpdatePolicyPrecedenceForbidden{}
}

/*
UpdatePolicyPrecedenceForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdatePolicyPrecedenceForbidden struct {

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

// IsSuccess returns true when this update policy precedence forbidden response has a 2xx status code
func (o *UpdatePolicyPrecedenceForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy precedence forbidden response has a 3xx status code
func (o *UpdatePolicyPrecedenceForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy precedence forbidden response has a 4xx status code
func (o *UpdatePolicyPrecedenceForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy precedence forbidden response has a 5xx status code
func (o *UpdatePolicyPrecedenceForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy precedence forbidden response a status code equal to that given
func (o *UpdatePolicyPrecedenceForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update policy precedence forbidden response
func (o *UpdatePolicyPrecedenceForbidden) Code() int {
	return 403
}

func (o *UpdatePolicyPrecedenceForbidden) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceForbidden  %+v", 403, o.Payload)
}

func (o *UpdatePolicyPrecedenceForbidden) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceForbidden  %+v", 403, o.Payload)
}

func (o *UpdatePolicyPrecedenceForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdatePolicyPrecedenceForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePolicyPrecedenceConflict creates a UpdatePolicyPrecedenceConflict with default headers values
func NewUpdatePolicyPrecedenceConflict() *UpdatePolicyPrecedenceConflict {
	return &UpdatePolicyPrecedenceConflict{}
}

/*
UpdatePolicyPrecedenceConflict describes a response with status code 409, with default header values.

Conflict
*/
type UpdatePolicyPrecedenceConflict struct {

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

// IsSuccess returns true when this update policy precedence conflict response has a 2xx status code
func (o *UpdatePolicyPrecedenceConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy precedence conflict response has a 3xx status code
func (o *UpdatePolicyPrecedenceConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy precedence conflict response has a 4xx status code
func (o *UpdatePolicyPrecedenceConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy precedence conflict response has a 5xx status code
func (o *UpdatePolicyPrecedenceConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy precedence conflict response a status code equal to that given
func (o *UpdatePolicyPrecedenceConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the update policy precedence conflict response
func (o *UpdatePolicyPrecedenceConflict) Code() int {
	return 409
}

func (o *UpdatePolicyPrecedenceConflict) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceConflict  %+v", 409, o.Payload)
}

func (o *UpdatePolicyPrecedenceConflict) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceConflict  %+v", 409, o.Payload)
}

func (o *UpdatePolicyPrecedenceConflict) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdatePolicyPrecedenceConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePolicyPrecedenceTooManyRequests creates a UpdatePolicyPrecedenceTooManyRequests with default headers values
func NewUpdatePolicyPrecedenceTooManyRequests() *UpdatePolicyPrecedenceTooManyRequests {
	return &UpdatePolicyPrecedenceTooManyRequests{}
}

/*
UpdatePolicyPrecedenceTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type UpdatePolicyPrecedenceTooManyRequests struct {

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

// IsSuccess returns true when this update policy precedence too many requests response has a 2xx status code
func (o *UpdatePolicyPrecedenceTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy precedence too many requests response has a 3xx status code
func (o *UpdatePolicyPrecedenceTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy precedence too many requests response has a 4xx status code
func (o *UpdatePolicyPrecedenceTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy precedence too many requests response has a 5xx status code
func (o *UpdatePolicyPrecedenceTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy precedence too many requests response a status code equal to that given
func (o *UpdatePolicyPrecedenceTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update policy precedence too many requests response
func (o *UpdatePolicyPrecedenceTooManyRequests) Code() int {
	return 429
}

func (o *UpdatePolicyPrecedenceTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdatePolicyPrecedenceTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdatePolicyPrecedenceTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdatePolicyPrecedenceTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePolicyPrecedenceInternalServerError creates a UpdatePolicyPrecedenceInternalServerError with default headers values
func NewUpdatePolicyPrecedenceInternalServerError() *UpdatePolicyPrecedenceInternalServerError {
	return &UpdatePolicyPrecedenceInternalServerError{}
}

/*
UpdatePolicyPrecedenceInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type UpdatePolicyPrecedenceInternalServerError struct {

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

// IsSuccess returns true when this update policy precedence internal server error response has a 2xx status code
func (o *UpdatePolicyPrecedenceInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy precedence internal server error response has a 3xx status code
func (o *UpdatePolicyPrecedenceInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy precedence internal server error response has a 4xx status code
func (o *UpdatePolicyPrecedenceInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this update policy precedence internal server error response has a 5xx status code
func (o *UpdatePolicyPrecedenceInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this update policy precedence internal server error response a status code equal to that given
func (o *UpdatePolicyPrecedenceInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the update policy precedence internal server error response
func (o *UpdatePolicyPrecedenceInternalServerError) Code() int {
	return 500
}

func (o *UpdatePolicyPrecedenceInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdatePolicyPrecedenceInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-precedence/v1][%d] updatePolicyPrecedenceInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdatePolicyPrecedenceInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdatePolicyPrecedenceInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
