// Code generated by go-swagger; DO NOT EDIT.

package falconx_sandbox

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

// GetMemoryDumpReader is a Reader for the GetMemoryDump structure.
type GetMemoryDumpReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetMemoryDumpReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetMemoryDumpOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetMemoryDumpBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetMemoryDumpForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetMemoryDumpNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetMemoryDumpTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetMemoryDumpInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /falconx/entities/memory-dump/v1] GetMemoryDump", response, response.Code())
	}
}

// NewGetMemoryDumpOK creates a GetMemoryDumpOK with default headers values
func NewGetMemoryDumpOK() *GetMemoryDumpOK {
	return &GetMemoryDumpOK{}
}

/*
GetMemoryDumpOK describes a response with status code 200, with default header values.

OK
*/
type GetMemoryDumpOK struct {

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

// IsSuccess returns true when this get memory dump o k response has a 2xx status code
func (o *GetMemoryDumpOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get memory dump o k response has a 3xx status code
func (o *GetMemoryDumpOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get memory dump o k response has a 4xx status code
func (o *GetMemoryDumpOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get memory dump o k response has a 5xx status code
func (o *GetMemoryDumpOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get memory dump o k response a status code equal to that given
func (o *GetMemoryDumpOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get memory dump o k response
func (o *GetMemoryDumpOK) Code() int {
	return 200
}

func (o *GetMemoryDumpOK) Error() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpOK  %+v", 200, o.Payload)
}

func (o *GetMemoryDumpOK) String() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpOK  %+v", 200, o.Payload)
}

func (o *GetMemoryDumpOK) GetPayload() *models.MsaspecQueryResponse {
	return o.Payload
}

func (o *GetMemoryDumpOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetMemoryDumpBadRequest creates a GetMemoryDumpBadRequest with default headers values
func NewGetMemoryDumpBadRequest() *GetMemoryDumpBadRequest {
	return &GetMemoryDumpBadRequest{}
}

/*
GetMemoryDumpBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetMemoryDumpBadRequest struct {

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

// IsSuccess returns true when this get memory dump bad request response has a 2xx status code
func (o *GetMemoryDumpBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get memory dump bad request response has a 3xx status code
func (o *GetMemoryDumpBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get memory dump bad request response has a 4xx status code
func (o *GetMemoryDumpBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get memory dump bad request response has a 5xx status code
func (o *GetMemoryDumpBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get memory dump bad request response a status code equal to that given
func (o *GetMemoryDumpBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get memory dump bad request response
func (o *GetMemoryDumpBadRequest) Code() int {
	return 400
}

func (o *GetMemoryDumpBadRequest) Error() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpBadRequest  %+v", 400, o.Payload)
}

func (o *GetMemoryDumpBadRequest) String() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpBadRequest  %+v", 400, o.Payload)
}

func (o *GetMemoryDumpBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *GetMemoryDumpBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetMemoryDumpForbidden creates a GetMemoryDumpForbidden with default headers values
func NewGetMemoryDumpForbidden() *GetMemoryDumpForbidden {
	return &GetMemoryDumpForbidden{}
}

/*
GetMemoryDumpForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetMemoryDumpForbidden struct {

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

// IsSuccess returns true when this get memory dump forbidden response has a 2xx status code
func (o *GetMemoryDumpForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get memory dump forbidden response has a 3xx status code
func (o *GetMemoryDumpForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get memory dump forbidden response has a 4xx status code
func (o *GetMemoryDumpForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get memory dump forbidden response has a 5xx status code
func (o *GetMemoryDumpForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get memory dump forbidden response a status code equal to that given
func (o *GetMemoryDumpForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get memory dump forbidden response
func (o *GetMemoryDumpForbidden) Code() int {
	return 403
}

func (o *GetMemoryDumpForbidden) Error() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpForbidden  %+v", 403, o.Payload)
}

func (o *GetMemoryDumpForbidden) String() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpForbidden  %+v", 403, o.Payload)
}

func (o *GetMemoryDumpForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetMemoryDumpForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetMemoryDumpNotFound creates a GetMemoryDumpNotFound with default headers values
func NewGetMemoryDumpNotFound() *GetMemoryDumpNotFound {
	return &GetMemoryDumpNotFound{}
}

/*
GetMemoryDumpNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetMemoryDumpNotFound struct {

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

// IsSuccess returns true when this get memory dump not found response has a 2xx status code
func (o *GetMemoryDumpNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get memory dump not found response has a 3xx status code
func (o *GetMemoryDumpNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get memory dump not found response has a 4xx status code
func (o *GetMemoryDumpNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get memory dump not found response has a 5xx status code
func (o *GetMemoryDumpNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get memory dump not found response a status code equal to that given
func (o *GetMemoryDumpNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get memory dump not found response
func (o *GetMemoryDumpNotFound) Code() int {
	return 404
}

func (o *GetMemoryDumpNotFound) Error() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpNotFound  %+v", 404, o.Payload)
}

func (o *GetMemoryDumpNotFound) String() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpNotFound  %+v", 404, o.Payload)
}

func (o *GetMemoryDumpNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *GetMemoryDumpNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetMemoryDumpTooManyRequests creates a GetMemoryDumpTooManyRequests with default headers values
func NewGetMemoryDumpTooManyRequests() *GetMemoryDumpTooManyRequests {
	return &GetMemoryDumpTooManyRequests{}
}

/*
GetMemoryDumpTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetMemoryDumpTooManyRequests struct {

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

// IsSuccess returns true when this get memory dump too many requests response has a 2xx status code
func (o *GetMemoryDumpTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get memory dump too many requests response has a 3xx status code
func (o *GetMemoryDumpTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get memory dump too many requests response has a 4xx status code
func (o *GetMemoryDumpTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get memory dump too many requests response has a 5xx status code
func (o *GetMemoryDumpTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get memory dump too many requests response a status code equal to that given
func (o *GetMemoryDumpTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get memory dump too many requests response
func (o *GetMemoryDumpTooManyRequests) Code() int {
	return 429
}

func (o *GetMemoryDumpTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetMemoryDumpTooManyRequests) String() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetMemoryDumpTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetMemoryDumpTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetMemoryDumpInternalServerError creates a GetMemoryDumpInternalServerError with default headers values
func NewGetMemoryDumpInternalServerError() *GetMemoryDumpInternalServerError {
	return &GetMemoryDumpInternalServerError{}
}

/*
GetMemoryDumpInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetMemoryDumpInternalServerError struct {

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

// IsSuccess returns true when this get memory dump internal server error response has a 2xx status code
func (o *GetMemoryDumpInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get memory dump internal server error response has a 3xx status code
func (o *GetMemoryDumpInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get memory dump internal server error response has a 4xx status code
func (o *GetMemoryDumpInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get memory dump internal server error response has a 5xx status code
func (o *GetMemoryDumpInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get memory dump internal server error response a status code equal to that given
func (o *GetMemoryDumpInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get memory dump internal server error response
func (o *GetMemoryDumpInternalServerError) Code() int {
	return 500
}

func (o *GetMemoryDumpInternalServerError) Error() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpInternalServerError  %+v", 500, o.Payload)
}

func (o *GetMemoryDumpInternalServerError) String() string {
	return fmt.Sprintf("[GET /falconx/entities/memory-dump/v1][%d] getMemoryDumpInternalServerError  %+v", 500, o.Payload)
}

func (o *GetMemoryDumpInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *GetMemoryDumpInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
