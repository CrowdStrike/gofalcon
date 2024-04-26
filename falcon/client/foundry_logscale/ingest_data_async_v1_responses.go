// Code generated by go-swagger; DO NOT EDIT.

package foundry_logscale

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

// IngestDataAsyncV1Reader is a Reader for the IngestDataAsyncV1 structure.
type IngestDataAsyncV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IngestDataAsyncV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIngestDataAsyncV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewIngestDataAsyncV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewIngestDataAsyncV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewIngestDataAsyncV1NotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewIngestDataAsyncV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewIngestDataAsyncV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /loggingapi/entities/data-ingestion/ingest-async/v1] IngestDataAsyncV1", response, response.Code())
	}
}

// NewIngestDataAsyncV1OK creates a IngestDataAsyncV1OK with default headers values
func NewIngestDataAsyncV1OK() *IngestDataAsyncV1OK {
	return &IngestDataAsyncV1OK{}
}

/*
IngestDataAsyncV1OK describes a response with status code 200, with default header values.

OK
*/
type IngestDataAsyncV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ClientDataIngestResponseWrapperV1
}

// IsSuccess returns true when this ingest data async v1 o k response has a 2xx status code
func (o *IngestDataAsyncV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ingest data async v1 o k response has a 3xx status code
func (o *IngestDataAsyncV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data async v1 o k response has a 4xx status code
func (o *IngestDataAsyncV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ingest data async v1 o k response has a 5xx status code
func (o *IngestDataAsyncV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this ingest data async v1 o k response a status code equal to that given
func (o *IngestDataAsyncV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ingest data async v1 o k response
func (o *IngestDataAsyncV1OK) Code() int {
	return 200
}

func (o *IngestDataAsyncV1OK) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1OK  %+v", 200, o.Payload)
}

func (o *IngestDataAsyncV1OK) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1OK  %+v", 200, o.Payload)
}

func (o *IngestDataAsyncV1OK) GetPayload() *models.ClientDataIngestResponseWrapperV1 {
	return o.Payload
}

func (o *IngestDataAsyncV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ClientDataIngestResponseWrapperV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIngestDataAsyncV1BadRequest creates a IngestDataAsyncV1BadRequest with default headers values
func NewIngestDataAsyncV1BadRequest() *IngestDataAsyncV1BadRequest {
	return &IngestDataAsyncV1BadRequest{}
}

/*
IngestDataAsyncV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type IngestDataAsyncV1BadRequest struct {

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

// IsSuccess returns true when this ingest data async v1 bad request response has a 2xx status code
func (o *IngestDataAsyncV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this ingest data async v1 bad request response has a 3xx status code
func (o *IngestDataAsyncV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data async v1 bad request response has a 4xx status code
func (o *IngestDataAsyncV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this ingest data async v1 bad request response has a 5xx status code
func (o *IngestDataAsyncV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this ingest data async v1 bad request response a status code equal to that given
func (o *IngestDataAsyncV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the ingest data async v1 bad request response
func (o *IngestDataAsyncV1BadRequest) Code() int {
	return 400
}

func (o *IngestDataAsyncV1BadRequest) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1BadRequest  %+v", 400, o.Payload)
}

func (o *IngestDataAsyncV1BadRequest) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1BadRequest  %+v", 400, o.Payload)
}

func (o *IngestDataAsyncV1BadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *IngestDataAsyncV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIngestDataAsyncV1Forbidden creates a IngestDataAsyncV1Forbidden with default headers values
func NewIngestDataAsyncV1Forbidden() *IngestDataAsyncV1Forbidden {
	return &IngestDataAsyncV1Forbidden{}
}

/*
IngestDataAsyncV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type IngestDataAsyncV1Forbidden struct {

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

// IsSuccess returns true when this ingest data async v1 forbidden response has a 2xx status code
func (o *IngestDataAsyncV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this ingest data async v1 forbidden response has a 3xx status code
func (o *IngestDataAsyncV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data async v1 forbidden response has a 4xx status code
func (o *IngestDataAsyncV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this ingest data async v1 forbidden response has a 5xx status code
func (o *IngestDataAsyncV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this ingest data async v1 forbidden response a status code equal to that given
func (o *IngestDataAsyncV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the ingest data async v1 forbidden response
func (o *IngestDataAsyncV1Forbidden) Code() int {
	return 403
}

func (o *IngestDataAsyncV1Forbidden) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1Forbidden  %+v", 403, o.Payload)
}

func (o *IngestDataAsyncV1Forbidden) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1Forbidden  %+v", 403, o.Payload)
}

func (o *IngestDataAsyncV1Forbidden) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *IngestDataAsyncV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIngestDataAsyncV1NotFound creates a IngestDataAsyncV1NotFound with default headers values
func NewIngestDataAsyncV1NotFound() *IngestDataAsyncV1NotFound {
	return &IngestDataAsyncV1NotFound{}
}

/*
IngestDataAsyncV1NotFound describes a response with status code 404, with default header values.

Not Found
*/
type IngestDataAsyncV1NotFound struct {

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

// IsSuccess returns true when this ingest data async v1 not found response has a 2xx status code
func (o *IngestDataAsyncV1NotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this ingest data async v1 not found response has a 3xx status code
func (o *IngestDataAsyncV1NotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data async v1 not found response has a 4xx status code
func (o *IngestDataAsyncV1NotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this ingest data async v1 not found response has a 5xx status code
func (o *IngestDataAsyncV1NotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this ingest data async v1 not found response a status code equal to that given
func (o *IngestDataAsyncV1NotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the ingest data async v1 not found response
func (o *IngestDataAsyncV1NotFound) Code() int {
	return 404
}

func (o *IngestDataAsyncV1NotFound) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1NotFound  %+v", 404, o.Payload)
}

func (o *IngestDataAsyncV1NotFound) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1NotFound  %+v", 404, o.Payload)
}

func (o *IngestDataAsyncV1NotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *IngestDataAsyncV1NotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIngestDataAsyncV1TooManyRequests creates a IngestDataAsyncV1TooManyRequests with default headers values
func NewIngestDataAsyncV1TooManyRequests() *IngestDataAsyncV1TooManyRequests {
	return &IngestDataAsyncV1TooManyRequests{}
}

/*
IngestDataAsyncV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type IngestDataAsyncV1TooManyRequests struct {

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

// IsSuccess returns true when this ingest data async v1 too many requests response has a 2xx status code
func (o *IngestDataAsyncV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this ingest data async v1 too many requests response has a 3xx status code
func (o *IngestDataAsyncV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data async v1 too many requests response has a 4xx status code
func (o *IngestDataAsyncV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this ingest data async v1 too many requests response has a 5xx status code
func (o *IngestDataAsyncV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this ingest data async v1 too many requests response a status code equal to that given
func (o *IngestDataAsyncV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the ingest data async v1 too many requests response
func (o *IngestDataAsyncV1TooManyRequests) Code() int {
	return 429
}

func (o *IngestDataAsyncV1TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *IngestDataAsyncV1TooManyRequests) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *IngestDataAsyncV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *IngestDataAsyncV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIngestDataAsyncV1InternalServerError creates a IngestDataAsyncV1InternalServerError with default headers values
func NewIngestDataAsyncV1InternalServerError() *IngestDataAsyncV1InternalServerError {
	return &IngestDataAsyncV1InternalServerError{}
}

/*
IngestDataAsyncV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type IngestDataAsyncV1InternalServerError struct {

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

// IsSuccess returns true when this ingest data async v1 internal server error response has a 2xx status code
func (o *IngestDataAsyncV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this ingest data async v1 internal server error response has a 3xx status code
func (o *IngestDataAsyncV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data async v1 internal server error response has a 4xx status code
func (o *IngestDataAsyncV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this ingest data async v1 internal server error response has a 5xx status code
func (o *IngestDataAsyncV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this ingest data async v1 internal server error response a status code equal to that given
func (o *IngestDataAsyncV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the ingest data async v1 internal server error response
func (o *IngestDataAsyncV1InternalServerError) Code() int {
	return 500
}

func (o *IngestDataAsyncV1InternalServerError) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1InternalServerError  %+v", 500, o.Payload)
}

func (o *IngestDataAsyncV1InternalServerError) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest-async/v1][%d] ingestDataAsyncV1InternalServerError  %+v", 500, o.Payload)
}

func (o *IngestDataAsyncV1InternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *IngestDataAsyncV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
