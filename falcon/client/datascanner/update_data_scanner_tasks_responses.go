// Code generated by go-swagger; DO NOT EDIT.

package datascanner

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

// UpdateDataScannerTasksReader is a Reader for the UpdateDataScannerTasks structure.
type UpdateDataScannerTasksReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateDataScannerTasksReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateDataScannerTasksOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewUpdateDataScannerTasksForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateDataScannerTasksTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpdateDataScannerTasksInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /data-security-dspm/entities/scanner-tasks/v1] update-data-scanner-tasks", response, response.Code())
	}
}

// NewUpdateDataScannerTasksOK creates a UpdateDataScannerTasksOK with default headers values
func NewUpdateDataScannerTasksOK() *UpdateDataScannerTasksOK {
	return &UpdateDataScannerTasksOK{}
}

/*
UpdateDataScannerTasksOK describes a response with status code 200, with default header values.

OK
*/
type UpdateDataScannerTasksOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload map[string]string
}

// IsSuccess returns true when this update data scanner tasks o k response has a 2xx status code
func (o *UpdateDataScannerTasksOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update data scanner tasks o k response has a 3xx status code
func (o *UpdateDataScannerTasksOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update data scanner tasks o k response has a 4xx status code
func (o *UpdateDataScannerTasksOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update data scanner tasks o k response has a 5xx status code
func (o *UpdateDataScannerTasksOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update data scanner tasks o k response a status code equal to that given
func (o *UpdateDataScannerTasksOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update data scanner tasks o k response
func (o *UpdateDataScannerTasksOK) Code() int {
	return 200
}

func (o *UpdateDataScannerTasksOK) Error() string {
	return fmt.Sprintf("[PATCH /data-security-dspm/entities/scanner-tasks/v1][%d] updateDataScannerTasksOK  %+v", 200, o.Payload)
}

func (o *UpdateDataScannerTasksOK) String() string {
	return fmt.Sprintf("[PATCH /data-security-dspm/entities/scanner-tasks/v1][%d] updateDataScannerTasksOK  %+v", 200, o.Payload)
}

func (o *UpdateDataScannerTasksOK) GetPayload() map[string]string {
	return o.Payload
}

func (o *UpdateDataScannerTasksOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateDataScannerTasksForbidden creates a UpdateDataScannerTasksForbidden with default headers values
func NewUpdateDataScannerTasksForbidden() *UpdateDataScannerTasksForbidden {
	return &UpdateDataScannerTasksForbidden{}
}

/*
UpdateDataScannerTasksForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateDataScannerTasksForbidden struct {

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

// IsSuccess returns true when this update data scanner tasks forbidden response has a 2xx status code
func (o *UpdateDataScannerTasksForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update data scanner tasks forbidden response has a 3xx status code
func (o *UpdateDataScannerTasksForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update data scanner tasks forbidden response has a 4xx status code
func (o *UpdateDataScannerTasksForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update data scanner tasks forbidden response has a 5xx status code
func (o *UpdateDataScannerTasksForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update data scanner tasks forbidden response a status code equal to that given
func (o *UpdateDataScannerTasksForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update data scanner tasks forbidden response
func (o *UpdateDataScannerTasksForbidden) Code() int {
	return 403
}

func (o *UpdateDataScannerTasksForbidden) Error() string {
	return fmt.Sprintf("[PATCH /data-security-dspm/entities/scanner-tasks/v1][%d] updateDataScannerTasksForbidden  %+v", 403, o.Payload)
}

func (o *UpdateDataScannerTasksForbidden) String() string {
	return fmt.Sprintf("[PATCH /data-security-dspm/entities/scanner-tasks/v1][%d] updateDataScannerTasksForbidden  %+v", 403, o.Payload)
}

func (o *UpdateDataScannerTasksForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdateDataScannerTasksForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateDataScannerTasksTooManyRequests creates a UpdateDataScannerTasksTooManyRequests with default headers values
func NewUpdateDataScannerTasksTooManyRequests() *UpdateDataScannerTasksTooManyRequests {
	return &UpdateDataScannerTasksTooManyRequests{}
}

/*
UpdateDataScannerTasksTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type UpdateDataScannerTasksTooManyRequests struct {

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

// IsSuccess returns true when this update data scanner tasks too many requests response has a 2xx status code
func (o *UpdateDataScannerTasksTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update data scanner tasks too many requests response has a 3xx status code
func (o *UpdateDataScannerTasksTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update data scanner tasks too many requests response has a 4xx status code
func (o *UpdateDataScannerTasksTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update data scanner tasks too many requests response has a 5xx status code
func (o *UpdateDataScannerTasksTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update data scanner tasks too many requests response a status code equal to that given
func (o *UpdateDataScannerTasksTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update data scanner tasks too many requests response
func (o *UpdateDataScannerTasksTooManyRequests) Code() int {
	return 429
}

func (o *UpdateDataScannerTasksTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /data-security-dspm/entities/scanner-tasks/v1][%d] updateDataScannerTasksTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateDataScannerTasksTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /data-security-dspm/entities/scanner-tasks/v1][%d] updateDataScannerTasksTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateDataScannerTasksTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdateDataScannerTasksTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateDataScannerTasksInternalServerError creates a UpdateDataScannerTasksInternalServerError with default headers values
func NewUpdateDataScannerTasksInternalServerError() *UpdateDataScannerTasksInternalServerError {
	return &UpdateDataScannerTasksInternalServerError{}
}

/*
UpdateDataScannerTasksInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type UpdateDataScannerTasksInternalServerError struct {

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

// IsSuccess returns true when this update data scanner tasks internal server error response has a 2xx status code
func (o *UpdateDataScannerTasksInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update data scanner tasks internal server error response has a 3xx status code
func (o *UpdateDataScannerTasksInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update data scanner tasks internal server error response has a 4xx status code
func (o *UpdateDataScannerTasksInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this update data scanner tasks internal server error response has a 5xx status code
func (o *UpdateDataScannerTasksInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this update data scanner tasks internal server error response a status code equal to that given
func (o *UpdateDataScannerTasksInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the update data scanner tasks internal server error response
func (o *UpdateDataScannerTasksInternalServerError) Code() int {
	return 500
}

func (o *UpdateDataScannerTasksInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /data-security-dspm/entities/scanner-tasks/v1][%d] updateDataScannerTasksInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateDataScannerTasksInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /data-security-dspm/entities/scanner-tasks/v1][%d] updateDataScannerTasksInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateDataScannerTasksInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdateDataScannerTasksInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
