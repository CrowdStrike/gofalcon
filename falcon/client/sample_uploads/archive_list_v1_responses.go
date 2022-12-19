// Code generated by go-swagger; DO NOT EDIT.

package sample_uploads

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

// ArchiveListV1Reader is a Reader for the ArchiveListV1 structure.
type ArchiveListV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArchiveListV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArchiveListV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewArchiveListV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewArchiveListV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewArchiveListV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewArchiveListV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewArchiveListV1Default(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArchiveListV1OK creates a ArchiveListV1OK with default headers values
func NewArchiveListV1OK() *ArchiveListV1OK {
	return &ArchiveListV1OK{}
}

/*
ArchiveListV1OK describes a response with status code 200, with default header values.

OK
*/
type ArchiveListV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientArchiveListFilesResponseV1
}

// IsSuccess returns true when this archive list v1 o k response has a 2xx status code
func (o *ArchiveListV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this archive list v1 o k response has a 3xx status code
func (o *ArchiveListV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive list v1 o k response has a 4xx status code
func (o *ArchiveListV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this archive list v1 o k response has a 5xx status code
func (o *ArchiveListV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this archive list v1 o k response a status code equal to that given
func (o *ArchiveListV1OK) IsCode(code int) bool {
	return code == 200
}

func (o *ArchiveListV1OK) Error() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] archiveListV1OK  %+v", 200, o.Payload)
}

func (o *ArchiveListV1OK) String() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] archiveListV1OK  %+v", 200, o.Payload)
}

func (o *ArchiveListV1OK) GetPayload() *models.ClientArchiveListFilesResponseV1 {
	return o.Payload
}

func (o *ArchiveListV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientArchiveListFilesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArchiveListV1BadRequest creates a ArchiveListV1BadRequest with default headers values
func NewArchiveListV1BadRequest() *ArchiveListV1BadRequest {
	return &ArchiveListV1BadRequest{}
}

/*
ArchiveListV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ArchiveListV1BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientArchiveListFilesResponseV1
}

// IsSuccess returns true when this archive list v1 bad request response has a 2xx status code
func (o *ArchiveListV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this archive list v1 bad request response has a 3xx status code
func (o *ArchiveListV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive list v1 bad request response has a 4xx status code
func (o *ArchiveListV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this archive list v1 bad request response has a 5xx status code
func (o *ArchiveListV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this archive list v1 bad request response a status code equal to that given
func (o *ArchiveListV1BadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *ArchiveListV1BadRequest) Error() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] archiveListV1BadRequest  %+v", 400, o.Payload)
}

func (o *ArchiveListV1BadRequest) String() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] archiveListV1BadRequest  %+v", 400, o.Payload)
}

func (o *ArchiveListV1BadRequest) GetPayload() *models.ClientArchiveListFilesResponseV1 {
	return o.Payload
}

func (o *ArchiveListV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientArchiveListFilesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArchiveListV1Forbidden creates a ArchiveListV1Forbidden with default headers values
func NewArchiveListV1Forbidden() *ArchiveListV1Forbidden {
	return &ArchiveListV1Forbidden{}
}

/*
ArchiveListV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ArchiveListV1Forbidden struct {

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

// IsSuccess returns true when this archive list v1 forbidden response has a 2xx status code
func (o *ArchiveListV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this archive list v1 forbidden response has a 3xx status code
func (o *ArchiveListV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive list v1 forbidden response has a 4xx status code
func (o *ArchiveListV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this archive list v1 forbidden response has a 5xx status code
func (o *ArchiveListV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this archive list v1 forbidden response a status code equal to that given
func (o *ArchiveListV1Forbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ArchiveListV1Forbidden) Error() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] archiveListV1Forbidden  %+v", 403, o.Payload)
}

func (o *ArchiveListV1Forbidden) String() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] archiveListV1Forbidden  %+v", 403, o.Payload)
}

func (o *ArchiveListV1Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ArchiveListV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewArchiveListV1TooManyRequests creates a ArchiveListV1TooManyRequests with default headers values
func NewArchiveListV1TooManyRequests() *ArchiveListV1TooManyRequests {
	return &ArchiveListV1TooManyRequests{}
}

/*
ArchiveListV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ArchiveListV1TooManyRequests struct {

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

// IsSuccess returns true when this archive list v1 too many requests response has a 2xx status code
func (o *ArchiveListV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this archive list v1 too many requests response has a 3xx status code
func (o *ArchiveListV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive list v1 too many requests response has a 4xx status code
func (o *ArchiveListV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this archive list v1 too many requests response has a 5xx status code
func (o *ArchiveListV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this archive list v1 too many requests response a status code equal to that given
func (o *ArchiveListV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ArchiveListV1TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] archiveListV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *ArchiveListV1TooManyRequests) String() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] archiveListV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *ArchiveListV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ArchiveListV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewArchiveListV1InternalServerError creates a ArchiveListV1InternalServerError with default headers values
func NewArchiveListV1InternalServerError() *ArchiveListV1InternalServerError {
	return &ArchiveListV1InternalServerError{}
}

/*
ArchiveListV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ArchiveListV1InternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientArchiveListFilesResponseV1
}

// IsSuccess returns true when this archive list v1 internal server error response has a 2xx status code
func (o *ArchiveListV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this archive list v1 internal server error response has a 3xx status code
func (o *ArchiveListV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive list v1 internal server error response has a 4xx status code
func (o *ArchiveListV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this archive list v1 internal server error response has a 5xx status code
func (o *ArchiveListV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this archive list v1 internal server error response a status code equal to that given
func (o *ArchiveListV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

func (o *ArchiveListV1InternalServerError) Error() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] archiveListV1InternalServerError  %+v", 500, o.Payload)
}

func (o *ArchiveListV1InternalServerError) String() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] archiveListV1InternalServerError  %+v", 500, o.Payload)
}

func (o *ArchiveListV1InternalServerError) GetPayload() *models.ClientArchiveListFilesResponseV1 {
	return o.Payload
}

func (o *ArchiveListV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientArchiveListFilesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArchiveListV1Default creates a ArchiveListV1Default with default headers values
func NewArchiveListV1Default(code int) *ArchiveListV1Default {
	return &ArchiveListV1Default{
		_statusCode: code,
	}
}

/*
ArchiveListV1Default describes a response with status code -1, with default header values.

OK
*/
type ArchiveListV1Default struct {
	_statusCode int

	Payload *models.ClientArchiveListFilesResponseV1
}

// Code gets the status code for the archive list v1 default response
func (o *ArchiveListV1Default) Code() int {
	return o._statusCode
}

// IsSuccess returns true when this archive list v1 default response has a 2xx status code
func (o *ArchiveListV1Default) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this archive list v1 default response has a 3xx status code
func (o *ArchiveListV1Default) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this archive list v1 default response has a 4xx status code
func (o *ArchiveListV1Default) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this archive list v1 default response has a 5xx status code
func (o *ArchiveListV1Default) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this archive list v1 default response a status code equal to that given
func (o *ArchiveListV1Default) IsCode(code int) bool {
	return o._statusCode == code
}

func (o *ArchiveListV1Default) Error() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] ArchiveListV1 default  %+v", o._statusCode, o.Payload)
}

func (o *ArchiveListV1Default) String() string {
	return fmt.Sprintf("[GET /archives/entities/archive-files/v1][%d] ArchiveListV1 default  %+v", o._statusCode, o.Payload)
}

func (o *ArchiveListV1Default) GetPayload() *models.ClientArchiveListFilesResponseV1 {
	return o.Payload
}

func (o *ArchiveListV1Default) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ClientArchiveListFilesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}