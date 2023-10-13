// Code generated by go-swagger; DO NOT EDIT.

package workflows

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

// DeprovisionSystemDefinitionReader is a Reader for the DeprovisionSystemDefinition structure.
type DeprovisionSystemDefinitionReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeprovisionSystemDefinitionReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeprovisionSystemDefinitionOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeprovisionSystemDefinitionBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeprovisionSystemDefinitionForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeprovisionSystemDefinitionNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeprovisionSystemDefinitionTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeprovisionSystemDefinitionInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /workflows/system-definitions/deprovision/v1] deprovision.system-definition", response, response.Code())
	}
}

// NewDeprovisionSystemDefinitionOK creates a DeprovisionSystemDefinitionOK with default headers values
func NewDeprovisionSystemDefinitionOK() *DeprovisionSystemDefinitionOK {
	return &DeprovisionSystemDefinitionOK{}
}

/* DeprovisionSystemDefinitionOK describes a response with status code 200, with default header values.

OK
*/
type DeprovisionSystemDefinitionOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientSystemDefinitionCreateResponse
}

// IsSuccess returns true when this deprovision system definition o k response has a 2xx status code
func (o *DeprovisionSystemDefinitionOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this deprovision system definition o k response has a 3xx status code
func (o *DeprovisionSystemDefinitionOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprovision system definition o k response has a 4xx status code
func (o *DeprovisionSystemDefinitionOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this deprovision system definition o k response has a 5xx status code
func (o *DeprovisionSystemDefinitionOK) IsServerError() bool {
	return false
}

// IsCode returns true when this deprovision system definition o k response a status code equal to that given
func (o *DeprovisionSystemDefinitionOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the deprovision system definition o k response
func (o *DeprovisionSystemDefinitionOK) Code() int {
	return 200
}

func (o *DeprovisionSystemDefinitionOK) Error() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionOK  %+v", 200, o.Payload)
}

func (o *DeprovisionSystemDefinitionOK) String() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionOK  %+v", 200, o.Payload)
}

func (o *DeprovisionSystemDefinitionOK) GetPayload() *models.ClientSystemDefinitionCreateResponse {
	return o.Payload
}

func (o *DeprovisionSystemDefinitionOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientSystemDefinitionCreateResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeprovisionSystemDefinitionBadRequest creates a DeprovisionSystemDefinitionBadRequest with default headers values
func NewDeprovisionSystemDefinitionBadRequest() *DeprovisionSystemDefinitionBadRequest {
	return &DeprovisionSystemDefinitionBadRequest{}
}

/* DeprovisionSystemDefinitionBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DeprovisionSystemDefinitionBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientSystemDefinitionCreateResponse
}

// IsSuccess returns true when this deprovision system definition bad request response has a 2xx status code
func (o *DeprovisionSystemDefinitionBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprovision system definition bad request response has a 3xx status code
func (o *DeprovisionSystemDefinitionBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprovision system definition bad request response has a 4xx status code
func (o *DeprovisionSystemDefinitionBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprovision system definition bad request response has a 5xx status code
func (o *DeprovisionSystemDefinitionBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this deprovision system definition bad request response a status code equal to that given
func (o *DeprovisionSystemDefinitionBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the deprovision system definition bad request response
func (o *DeprovisionSystemDefinitionBadRequest) Code() int {
	return 400
}

func (o *DeprovisionSystemDefinitionBadRequest) Error() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionBadRequest  %+v", 400, o.Payload)
}

func (o *DeprovisionSystemDefinitionBadRequest) String() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionBadRequest  %+v", 400, o.Payload)
}

func (o *DeprovisionSystemDefinitionBadRequest) GetPayload() *models.ClientSystemDefinitionCreateResponse {
	return o.Payload
}

func (o *DeprovisionSystemDefinitionBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientSystemDefinitionCreateResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeprovisionSystemDefinitionForbidden creates a DeprovisionSystemDefinitionForbidden with default headers values
func NewDeprovisionSystemDefinitionForbidden() *DeprovisionSystemDefinitionForbidden {
	return &DeprovisionSystemDefinitionForbidden{}
}

/* DeprovisionSystemDefinitionForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeprovisionSystemDefinitionForbidden struct {

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

// IsSuccess returns true when this deprovision system definition forbidden response has a 2xx status code
func (o *DeprovisionSystemDefinitionForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprovision system definition forbidden response has a 3xx status code
func (o *DeprovisionSystemDefinitionForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprovision system definition forbidden response has a 4xx status code
func (o *DeprovisionSystemDefinitionForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprovision system definition forbidden response has a 5xx status code
func (o *DeprovisionSystemDefinitionForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this deprovision system definition forbidden response a status code equal to that given
func (o *DeprovisionSystemDefinitionForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the deprovision system definition forbidden response
func (o *DeprovisionSystemDefinitionForbidden) Code() int {
	return 403
}

func (o *DeprovisionSystemDefinitionForbidden) Error() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionForbidden  %+v", 403, o.Payload)
}

func (o *DeprovisionSystemDefinitionForbidden) String() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionForbidden  %+v", 403, o.Payload)
}

func (o *DeprovisionSystemDefinitionForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeprovisionSystemDefinitionForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeprovisionSystemDefinitionNotFound creates a DeprovisionSystemDefinitionNotFound with default headers values
func NewDeprovisionSystemDefinitionNotFound() *DeprovisionSystemDefinitionNotFound {
	return &DeprovisionSystemDefinitionNotFound{}
}

/* DeprovisionSystemDefinitionNotFound describes a response with status code 404, with default header values.

Not Found
*/
type DeprovisionSystemDefinitionNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientSystemDefinitionCreateResponse
}

// IsSuccess returns true when this deprovision system definition not found response has a 2xx status code
func (o *DeprovisionSystemDefinitionNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprovision system definition not found response has a 3xx status code
func (o *DeprovisionSystemDefinitionNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprovision system definition not found response has a 4xx status code
func (o *DeprovisionSystemDefinitionNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprovision system definition not found response has a 5xx status code
func (o *DeprovisionSystemDefinitionNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this deprovision system definition not found response a status code equal to that given
func (o *DeprovisionSystemDefinitionNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the deprovision system definition not found response
func (o *DeprovisionSystemDefinitionNotFound) Code() int {
	return 404
}

func (o *DeprovisionSystemDefinitionNotFound) Error() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionNotFound  %+v", 404, o.Payload)
}

func (o *DeprovisionSystemDefinitionNotFound) String() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionNotFound  %+v", 404, o.Payload)
}

func (o *DeprovisionSystemDefinitionNotFound) GetPayload() *models.ClientSystemDefinitionCreateResponse {
	return o.Payload
}

func (o *DeprovisionSystemDefinitionNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientSystemDefinitionCreateResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeprovisionSystemDefinitionTooManyRequests creates a DeprovisionSystemDefinitionTooManyRequests with default headers values
func NewDeprovisionSystemDefinitionTooManyRequests() *DeprovisionSystemDefinitionTooManyRequests {
	return &DeprovisionSystemDefinitionTooManyRequests{}
}

/* DeprovisionSystemDefinitionTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type DeprovisionSystemDefinitionTooManyRequests struct {

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

// IsSuccess returns true when this deprovision system definition too many requests response has a 2xx status code
func (o *DeprovisionSystemDefinitionTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprovision system definition too many requests response has a 3xx status code
func (o *DeprovisionSystemDefinitionTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprovision system definition too many requests response has a 4xx status code
func (o *DeprovisionSystemDefinitionTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprovision system definition too many requests response has a 5xx status code
func (o *DeprovisionSystemDefinitionTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this deprovision system definition too many requests response a status code equal to that given
func (o *DeprovisionSystemDefinitionTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the deprovision system definition too many requests response
func (o *DeprovisionSystemDefinitionTooManyRequests) Code() int {
	return 429
}

func (o *DeprovisionSystemDefinitionTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeprovisionSystemDefinitionTooManyRequests) String() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeprovisionSystemDefinitionTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeprovisionSystemDefinitionTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeprovisionSystemDefinitionInternalServerError creates a DeprovisionSystemDefinitionInternalServerError with default headers values
func NewDeprovisionSystemDefinitionInternalServerError() *DeprovisionSystemDefinitionInternalServerError {
	return &DeprovisionSystemDefinitionInternalServerError{}
}

/* DeprovisionSystemDefinitionInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type DeprovisionSystemDefinitionInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientSystemDefinitionCreateResponse
}

// IsSuccess returns true when this deprovision system definition internal server error response has a 2xx status code
func (o *DeprovisionSystemDefinitionInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprovision system definition internal server error response has a 3xx status code
func (o *DeprovisionSystemDefinitionInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprovision system definition internal server error response has a 4xx status code
func (o *DeprovisionSystemDefinitionInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this deprovision system definition internal server error response has a 5xx status code
func (o *DeprovisionSystemDefinitionInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this deprovision system definition internal server error response a status code equal to that given
func (o *DeprovisionSystemDefinitionInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the deprovision system definition internal server error response
func (o *DeprovisionSystemDefinitionInternalServerError) Code() int {
	return 500
}

func (o *DeprovisionSystemDefinitionInternalServerError) Error() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionInternalServerError  %+v", 500, o.Payload)
}

func (o *DeprovisionSystemDefinitionInternalServerError) String() string {
	return fmt.Sprintf("[POST /workflows/system-definitions/deprovision/v1][%d] deprovisionSystemDefinitionInternalServerError  %+v", 500, o.Payload)
}

func (o *DeprovisionSystemDefinitionInternalServerError) GetPayload() *models.ClientSystemDefinitionCreateResponse {
	return o.Payload
}

func (o *DeprovisionSystemDefinitionInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientSystemDefinitionCreateResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
