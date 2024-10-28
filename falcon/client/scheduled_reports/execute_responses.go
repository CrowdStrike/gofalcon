// Code generated by go-swagger; DO NOT EDIT.

package scheduled_reports

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

// ExecuteReader is a Reader for the Execute structure.
type ExecuteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ExecuteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewExecuteOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewExecuteBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewExecuteForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewExecuteTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewExecuteInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /reports/entities/scheduled-reports/execution/v1] Execute", response, response.Code())
	}
}

// NewExecuteOK creates a ExecuteOK with default headers values
func NewExecuteOK() *ExecuteOK {
	return &ExecuteOK{}
}

/*
ExecuteOK describes a response with status code 200, with default header values.

OK
*/
type ExecuteOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainReportExecutionsResponseV1
}

// IsSuccess returns true when this execute o k response has a 2xx status code
func (o *ExecuteOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this execute o k response has a 3xx status code
func (o *ExecuteOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this execute o k response has a 4xx status code
func (o *ExecuteOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this execute o k response has a 5xx status code
func (o *ExecuteOK) IsServerError() bool {
	return false
}

// IsCode returns true when this execute o k response a status code equal to that given
func (o *ExecuteOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the execute o k response
func (o *ExecuteOK) Code() int {
	return 200
}

func (o *ExecuteOK) Error() string {
	return fmt.Sprintf("[POST /reports/entities/scheduled-reports/execution/v1][%d] executeOK  %+v", 200, o.Payload)
}

func (o *ExecuteOK) String() string {
	return fmt.Sprintf("[POST /reports/entities/scheduled-reports/execution/v1][%d] executeOK  %+v", 200, o.Payload)
}

func (o *ExecuteOK) GetPayload() *models.DomainReportExecutionsResponseV1 {
	return o.Payload
}

func (o *ExecuteOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainReportExecutionsResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExecuteBadRequest creates a ExecuteBadRequest with default headers values
func NewExecuteBadRequest() *ExecuteBadRequest {
	return &ExecuteBadRequest{}
}

/*
ExecuteBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ExecuteBadRequest struct {

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

// IsSuccess returns true when this execute bad request response has a 2xx status code
func (o *ExecuteBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this execute bad request response has a 3xx status code
func (o *ExecuteBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this execute bad request response has a 4xx status code
func (o *ExecuteBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this execute bad request response has a 5xx status code
func (o *ExecuteBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this execute bad request response a status code equal to that given
func (o *ExecuteBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the execute bad request response
func (o *ExecuteBadRequest) Code() int {
	return 400
}

func (o *ExecuteBadRequest) Error() string {
	return fmt.Sprintf("[POST /reports/entities/scheduled-reports/execution/v1][%d] executeBadRequest  %+v", 400, o.Payload)
}

func (o *ExecuteBadRequest) String() string {
	return fmt.Sprintf("[POST /reports/entities/scheduled-reports/execution/v1][%d] executeBadRequest  %+v", 400, o.Payload)
}

func (o *ExecuteBadRequest) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ExecuteBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewExecuteForbidden creates a ExecuteForbidden with default headers values
func NewExecuteForbidden() *ExecuteForbidden {
	return &ExecuteForbidden{}
}

/*
ExecuteForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ExecuteForbidden struct {

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

// IsSuccess returns true when this execute forbidden response has a 2xx status code
func (o *ExecuteForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this execute forbidden response has a 3xx status code
func (o *ExecuteForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this execute forbidden response has a 4xx status code
func (o *ExecuteForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this execute forbidden response has a 5xx status code
func (o *ExecuteForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this execute forbidden response a status code equal to that given
func (o *ExecuteForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the execute forbidden response
func (o *ExecuteForbidden) Code() int {
	return 403
}

func (o *ExecuteForbidden) Error() string {
	return fmt.Sprintf("[POST /reports/entities/scheduled-reports/execution/v1][%d] executeForbidden  %+v", 403, o.Payload)
}

func (o *ExecuteForbidden) String() string {
	return fmt.Sprintf("[POST /reports/entities/scheduled-reports/execution/v1][%d] executeForbidden  %+v", 403, o.Payload)
}

func (o *ExecuteForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ExecuteForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewExecuteTooManyRequests creates a ExecuteTooManyRequests with default headers values
func NewExecuteTooManyRequests() *ExecuteTooManyRequests {
	return &ExecuteTooManyRequests{}
}

/*
ExecuteTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ExecuteTooManyRequests struct {

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

// IsSuccess returns true when this execute too many requests response has a 2xx status code
func (o *ExecuteTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this execute too many requests response has a 3xx status code
func (o *ExecuteTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this execute too many requests response has a 4xx status code
func (o *ExecuteTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this execute too many requests response has a 5xx status code
func (o *ExecuteTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this execute too many requests response a status code equal to that given
func (o *ExecuteTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the execute too many requests response
func (o *ExecuteTooManyRequests) Code() int {
	return 429
}

func (o *ExecuteTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /reports/entities/scheduled-reports/execution/v1][%d] executeTooManyRequests  %+v", 429, o.Payload)
}

func (o *ExecuteTooManyRequests) String() string {
	return fmt.Sprintf("[POST /reports/entities/scheduled-reports/execution/v1][%d] executeTooManyRequests  %+v", 429, o.Payload)
}

func (o *ExecuteTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ExecuteTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewExecuteInternalServerError creates a ExecuteInternalServerError with default headers values
func NewExecuteInternalServerError() *ExecuteInternalServerError {
	return &ExecuteInternalServerError{}
}

/*
ExecuteInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type ExecuteInternalServerError struct {

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

// IsSuccess returns true when this execute internal server error response has a 2xx status code
func (o *ExecuteInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this execute internal server error response has a 3xx status code
func (o *ExecuteInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this execute internal server error response has a 4xx status code
func (o *ExecuteInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this execute internal server error response has a 5xx status code
func (o *ExecuteInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this execute internal server error response a status code equal to that given
func (o *ExecuteInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the execute internal server error response
func (o *ExecuteInternalServerError) Code() int {
	return 500
}

func (o *ExecuteInternalServerError) Error() string {
	return fmt.Sprintf("[POST /reports/entities/scheduled-reports/execution/v1][%d] executeInternalServerError  %+v", 500, o.Payload)
}

func (o *ExecuteInternalServerError) String() string {
	return fmt.Sprintf("[POST /reports/entities/scheduled-reports/execution/v1][%d] executeInternalServerError  %+v", 500, o.Payload)
}

func (o *ExecuteInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ExecuteInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
