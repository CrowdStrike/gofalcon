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

	"github.com/aslape/gofalcon/falcon/models"
)

// ArchiveUploadV2Reader is a Reader for the ArchiveUploadV2 structure.
type ArchiveUploadV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArchiveUploadV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArchiveUploadV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 202:
		result := NewArchiveUploadV2Accepted()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewArchiveUploadV2BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewArchiveUploadV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewArchiveUploadV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewArchiveUploadV2InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /archives/entities/archives/v2] ArchiveUploadV2", response, response.Code())
	}
}

// NewArchiveUploadV2OK creates a ArchiveUploadV2OK with default headers values
func NewArchiveUploadV2OK() *ArchiveUploadV2OK {
	return &ArchiveUploadV2OK{}
}

/*
ArchiveUploadV2OK describes a response with status code 200, with default header values.

OK
*/
type ArchiveUploadV2OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientArchiveCreateResponseV1
}

// IsSuccess returns true when this archive upload v2 o k response has a 2xx status code
func (o *ArchiveUploadV2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this archive upload v2 o k response has a 3xx status code
func (o *ArchiveUploadV2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive upload v2 o k response has a 4xx status code
func (o *ArchiveUploadV2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this archive upload v2 o k response has a 5xx status code
func (o *ArchiveUploadV2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this archive upload v2 o k response a status code equal to that given
func (o *ArchiveUploadV2OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the archive upload v2 o k response
func (o *ArchiveUploadV2OK) Code() int {
	return 200
}

func (o *ArchiveUploadV2OK) Error() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2OK  %+v", 200, o.Payload)
}

func (o *ArchiveUploadV2OK) String() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2OK  %+v", 200, o.Payload)
}

func (o *ArchiveUploadV2OK) GetPayload() *models.ClientArchiveCreateResponseV1 {
	return o.Payload
}

func (o *ArchiveUploadV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientArchiveCreateResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArchiveUploadV2Accepted creates a ArchiveUploadV2Accepted with default headers values
func NewArchiveUploadV2Accepted() *ArchiveUploadV2Accepted {
	return &ArchiveUploadV2Accepted{}
}

/*
ArchiveUploadV2Accepted describes a response with status code 202, with default header values.

OK
*/
type ArchiveUploadV2Accepted struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientArchiveCreateResponseV1
}

// IsSuccess returns true when this archive upload v2 accepted response has a 2xx status code
func (o *ArchiveUploadV2Accepted) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this archive upload v2 accepted response has a 3xx status code
func (o *ArchiveUploadV2Accepted) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive upload v2 accepted response has a 4xx status code
func (o *ArchiveUploadV2Accepted) IsClientError() bool {
	return false
}

// IsServerError returns true when this archive upload v2 accepted response has a 5xx status code
func (o *ArchiveUploadV2Accepted) IsServerError() bool {
	return false
}

// IsCode returns true when this archive upload v2 accepted response a status code equal to that given
func (o *ArchiveUploadV2Accepted) IsCode(code int) bool {
	return code == 202
}

// Code gets the status code for the archive upload v2 accepted response
func (o *ArchiveUploadV2Accepted) Code() int {
	return 202
}

func (o *ArchiveUploadV2Accepted) Error() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2Accepted  %+v", 202, o.Payload)
}

func (o *ArchiveUploadV2Accepted) String() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2Accepted  %+v", 202, o.Payload)
}

func (o *ArchiveUploadV2Accepted) GetPayload() *models.ClientArchiveCreateResponseV1 {
	return o.Payload
}

func (o *ArchiveUploadV2Accepted) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientArchiveCreateResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArchiveUploadV2BadRequest creates a ArchiveUploadV2BadRequest with default headers values
func NewArchiveUploadV2BadRequest() *ArchiveUploadV2BadRequest {
	return &ArchiveUploadV2BadRequest{}
}

/*
ArchiveUploadV2BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ArchiveUploadV2BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientArchiveCreateResponseV1
}

// IsSuccess returns true when this archive upload v2 bad request response has a 2xx status code
func (o *ArchiveUploadV2BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this archive upload v2 bad request response has a 3xx status code
func (o *ArchiveUploadV2BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive upload v2 bad request response has a 4xx status code
func (o *ArchiveUploadV2BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this archive upload v2 bad request response has a 5xx status code
func (o *ArchiveUploadV2BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this archive upload v2 bad request response a status code equal to that given
func (o *ArchiveUploadV2BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the archive upload v2 bad request response
func (o *ArchiveUploadV2BadRequest) Code() int {
	return 400
}

func (o *ArchiveUploadV2BadRequest) Error() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2BadRequest  %+v", 400, o.Payload)
}

func (o *ArchiveUploadV2BadRequest) String() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2BadRequest  %+v", 400, o.Payload)
}

func (o *ArchiveUploadV2BadRequest) GetPayload() *models.ClientArchiveCreateResponseV1 {
	return o.Payload
}

func (o *ArchiveUploadV2BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientArchiveCreateResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArchiveUploadV2Forbidden creates a ArchiveUploadV2Forbidden with default headers values
func NewArchiveUploadV2Forbidden() *ArchiveUploadV2Forbidden {
	return &ArchiveUploadV2Forbidden{}
}

/*
ArchiveUploadV2Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ArchiveUploadV2Forbidden struct {

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

// IsSuccess returns true when this archive upload v2 forbidden response has a 2xx status code
func (o *ArchiveUploadV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this archive upload v2 forbidden response has a 3xx status code
func (o *ArchiveUploadV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive upload v2 forbidden response has a 4xx status code
func (o *ArchiveUploadV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this archive upload v2 forbidden response has a 5xx status code
func (o *ArchiveUploadV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this archive upload v2 forbidden response a status code equal to that given
func (o *ArchiveUploadV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the archive upload v2 forbidden response
func (o *ArchiveUploadV2Forbidden) Code() int {
	return 403
}

func (o *ArchiveUploadV2Forbidden) Error() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2Forbidden  %+v", 403, o.Payload)
}

func (o *ArchiveUploadV2Forbidden) String() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2Forbidden  %+v", 403, o.Payload)
}

func (o *ArchiveUploadV2Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ArchiveUploadV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewArchiveUploadV2TooManyRequests creates a ArchiveUploadV2TooManyRequests with default headers values
func NewArchiveUploadV2TooManyRequests() *ArchiveUploadV2TooManyRequests {
	return &ArchiveUploadV2TooManyRequests{}
}

/*
ArchiveUploadV2TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ArchiveUploadV2TooManyRequests struct {

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

// IsSuccess returns true when this archive upload v2 too many requests response has a 2xx status code
func (o *ArchiveUploadV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this archive upload v2 too many requests response has a 3xx status code
func (o *ArchiveUploadV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive upload v2 too many requests response has a 4xx status code
func (o *ArchiveUploadV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this archive upload v2 too many requests response has a 5xx status code
func (o *ArchiveUploadV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this archive upload v2 too many requests response a status code equal to that given
func (o *ArchiveUploadV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the archive upload v2 too many requests response
func (o *ArchiveUploadV2TooManyRequests) Code() int {
	return 429
}

func (o *ArchiveUploadV2TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *ArchiveUploadV2TooManyRequests) String() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *ArchiveUploadV2TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ArchiveUploadV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewArchiveUploadV2InternalServerError creates a ArchiveUploadV2InternalServerError with default headers values
func NewArchiveUploadV2InternalServerError() *ArchiveUploadV2InternalServerError {
	return &ArchiveUploadV2InternalServerError{}
}

/*
ArchiveUploadV2InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ArchiveUploadV2InternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientArchiveCreateResponseV1
}

// IsSuccess returns true when this archive upload v2 internal server error response has a 2xx status code
func (o *ArchiveUploadV2InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this archive upload v2 internal server error response has a 3xx status code
func (o *ArchiveUploadV2InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this archive upload v2 internal server error response has a 4xx status code
func (o *ArchiveUploadV2InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this archive upload v2 internal server error response has a 5xx status code
func (o *ArchiveUploadV2InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this archive upload v2 internal server error response a status code equal to that given
func (o *ArchiveUploadV2InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the archive upload v2 internal server error response
func (o *ArchiveUploadV2InternalServerError) Code() int {
	return 500
}

func (o *ArchiveUploadV2InternalServerError) Error() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2InternalServerError  %+v", 500, o.Payload)
}

func (o *ArchiveUploadV2InternalServerError) String() string {
	return fmt.Sprintf("[POST /archives/entities/archives/v2][%d] archiveUploadV2InternalServerError  %+v", 500, o.Payload)
}

func (o *ArchiveUploadV2InternalServerError) GetPayload() *models.ClientArchiveCreateResponseV1 {
	return o.Payload
}

func (o *ArchiveUploadV2InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientArchiveCreateResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
