// Code generated by go-swagger; DO NOT EDIT.

package ods

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

// CancelScansReader is a Reader for the CancelScans structure.
type CancelScansReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CancelScansReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCancelScansOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewCancelScansForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCancelScansNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCancelScansTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCancelScansInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /ods/entities/scan-control-actions/cancel/v1] cancel-scans", response, response.Code())
	}
}

// NewCancelScansOK creates a CancelScansOK with default headers values
func NewCancelScansOK() *CancelScansOK {
	return &CancelScansOK{}
}

/*
CancelScansOK describes a response with status code 200, with default header values.

OK
*/
type CancelScansOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecQueryResponse
}

// IsSuccess returns true when this cancel scans o k response has a 2xx status code
func (o *CancelScansOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cancel scans o k response has a 3xx status code
func (o *CancelScansOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cancel scans o k response has a 4xx status code
func (o *CancelScansOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cancel scans o k response has a 5xx status code
func (o *CancelScansOK) IsServerError() bool {
	return false
}

// IsCode returns true when this cancel scans o k response a status code equal to that given
func (o *CancelScansOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the cancel scans o k response
func (o *CancelScansOK) Code() int {
	return 200
}

func (o *CancelScansOK) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scan-control-actions/cancel/v1][%d] cancelScansOK  %+v", 200, o.Payload)
}

func (o *CancelScansOK) String() string {
	return fmt.Sprintf("[POST /ods/entities/scan-control-actions/cancel/v1][%d] cancelScansOK  %+v", 200, o.Payload)
}

func (o *CancelScansOK) GetPayload() *models.MsaspecQueryResponse {
	return o.Payload
}

func (o *CancelScansOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCancelScansForbidden creates a CancelScansForbidden with default headers values
func NewCancelScansForbidden() *CancelScansForbidden {
	return &CancelScansForbidden{}
}

/*
CancelScansForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CancelScansForbidden struct {

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

// IsSuccess returns true when this cancel scans forbidden response has a 2xx status code
func (o *CancelScansForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cancel scans forbidden response has a 3xx status code
func (o *CancelScansForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cancel scans forbidden response has a 4xx status code
func (o *CancelScansForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this cancel scans forbidden response has a 5xx status code
func (o *CancelScansForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this cancel scans forbidden response a status code equal to that given
func (o *CancelScansForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the cancel scans forbidden response
func (o *CancelScansForbidden) Code() int {
	return 403
}

func (o *CancelScansForbidden) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scan-control-actions/cancel/v1][%d] cancelScansForbidden  %+v", 403, o.Payload)
}

func (o *CancelScansForbidden) String() string {
	return fmt.Sprintf("[POST /ods/entities/scan-control-actions/cancel/v1][%d] cancelScansForbidden  %+v", 403, o.Payload)
}

func (o *CancelScansForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CancelScansForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCancelScansNotFound creates a CancelScansNotFound with default headers values
func NewCancelScansNotFound() *CancelScansNotFound {
	return &CancelScansNotFound{}
}

/*
CancelScansNotFound describes a response with status code 404, with default header values.

Not Found
*/
type CancelScansNotFound struct {

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

// IsSuccess returns true when this cancel scans not found response has a 2xx status code
func (o *CancelScansNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cancel scans not found response has a 3xx status code
func (o *CancelScansNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cancel scans not found response has a 4xx status code
func (o *CancelScansNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this cancel scans not found response has a 5xx status code
func (o *CancelScansNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this cancel scans not found response a status code equal to that given
func (o *CancelScansNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the cancel scans not found response
func (o *CancelScansNotFound) Code() int {
	return 404
}

func (o *CancelScansNotFound) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scan-control-actions/cancel/v1][%d] cancelScansNotFound  %+v", 404, o.Payload)
}

func (o *CancelScansNotFound) String() string {
	return fmt.Sprintf("[POST /ods/entities/scan-control-actions/cancel/v1][%d] cancelScansNotFound  %+v", 404, o.Payload)
}

func (o *CancelScansNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CancelScansNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCancelScansTooManyRequests creates a CancelScansTooManyRequests with default headers values
func NewCancelScansTooManyRequests() *CancelScansTooManyRequests {
	return &CancelScansTooManyRequests{}
}

/*
CancelScansTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CancelScansTooManyRequests struct {

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

// IsSuccess returns true when this cancel scans too many requests response has a 2xx status code
func (o *CancelScansTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cancel scans too many requests response has a 3xx status code
func (o *CancelScansTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cancel scans too many requests response has a 4xx status code
func (o *CancelScansTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this cancel scans too many requests response has a 5xx status code
func (o *CancelScansTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this cancel scans too many requests response a status code equal to that given
func (o *CancelScansTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the cancel scans too many requests response
func (o *CancelScansTooManyRequests) Code() int {
	return 429
}

func (o *CancelScansTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scan-control-actions/cancel/v1][%d] cancelScansTooManyRequests  %+v", 429, o.Payload)
}

func (o *CancelScansTooManyRequests) String() string {
	return fmt.Sprintf("[POST /ods/entities/scan-control-actions/cancel/v1][%d] cancelScansTooManyRequests  %+v", 429, o.Payload)
}

func (o *CancelScansTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CancelScansTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCancelScansInternalServerError creates a CancelScansInternalServerError with default headers values
func NewCancelScansInternalServerError() *CancelScansInternalServerError {
	return &CancelScansInternalServerError{}
}

/*
CancelScansInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type CancelScansInternalServerError struct {

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

// IsSuccess returns true when this cancel scans internal server error response has a 2xx status code
func (o *CancelScansInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cancel scans internal server error response has a 3xx status code
func (o *CancelScansInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cancel scans internal server error response has a 4xx status code
func (o *CancelScansInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this cancel scans internal server error response has a 5xx status code
func (o *CancelScansInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this cancel scans internal server error response a status code equal to that given
func (o *CancelScansInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the cancel scans internal server error response
func (o *CancelScansInternalServerError) Code() int {
	return 500
}

func (o *CancelScansInternalServerError) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scan-control-actions/cancel/v1][%d] cancelScansInternalServerError  %+v", 500, o.Payload)
}

func (o *CancelScansInternalServerError) String() string {
	return fmt.Sprintf("[POST /ods/entities/scan-control-actions/cancel/v1][%d] cancelScansInternalServerError  %+v", 500, o.Payload)
}

func (o *CancelScansInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CancelScansInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
