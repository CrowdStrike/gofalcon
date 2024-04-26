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

// IngestDataReader is a Reader for the IngestData structure.
type IngestDataReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IngestDataReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIngestDataOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewIngestDataBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewIngestDataForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewIngestDataNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewIngestDataTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewIngestDataInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /loggingapi/entities/data-ingestion/ingest/v1] IngestData", response, response.Code())
	}
}

// NewIngestDataOK creates a IngestDataOK with default headers values
func NewIngestDataOK() *IngestDataOK {
	return &IngestDataOK{}
}

/*
IngestDataOK describes a response with status code 200, with default header values.

OK
*/
type IngestDataOK struct {

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

// IsSuccess returns true when this ingest data o k response has a 2xx status code
func (o *IngestDataOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ingest data o k response has a 3xx status code
func (o *IngestDataOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data o k response has a 4xx status code
func (o *IngestDataOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ingest data o k response has a 5xx status code
func (o *IngestDataOK) IsServerError() bool {
	return false
}

// IsCode returns true when this ingest data o k response a status code equal to that given
func (o *IngestDataOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ingest data o k response
func (o *IngestDataOK) Code() int {
	return 200
}

func (o *IngestDataOK) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataOK  %+v", 200, o.Payload)
}

func (o *IngestDataOK) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataOK  %+v", 200, o.Payload)
}

func (o *IngestDataOK) GetPayload() *models.ClientDataIngestResponseWrapperV1 {
	return o.Payload
}

func (o *IngestDataOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIngestDataBadRequest creates a IngestDataBadRequest with default headers values
func NewIngestDataBadRequest() *IngestDataBadRequest {
	return &IngestDataBadRequest{}
}

/*
IngestDataBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type IngestDataBadRequest struct {

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

// IsSuccess returns true when this ingest data bad request response has a 2xx status code
func (o *IngestDataBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this ingest data bad request response has a 3xx status code
func (o *IngestDataBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data bad request response has a 4xx status code
func (o *IngestDataBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this ingest data bad request response has a 5xx status code
func (o *IngestDataBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this ingest data bad request response a status code equal to that given
func (o *IngestDataBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the ingest data bad request response
func (o *IngestDataBadRequest) Code() int {
	return 400
}

func (o *IngestDataBadRequest) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataBadRequest  %+v", 400, o.Payload)
}

func (o *IngestDataBadRequest) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataBadRequest  %+v", 400, o.Payload)
}

func (o *IngestDataBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *IngestDataBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIngestDataForbidden creates a IngestDataForbidden with default headers values
func NewIngestDataForbidden() *IngestDataForbidden {
	return &IngestDataForbidden{}
}

/*
IngestDataForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type IngestDataForbidden struct {

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

// IsSuccess returns true when this ingest data forbidden response has a 2xx status code
func (o *IngestDataForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this ingest data forbidden response has a 3xx status code
func (o *IngestDataForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data forbidden response has a 4xx status code
func (o *IngestDataForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this ingest data forbidden response has a 5xx status code
func (o *IngestDataForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this ingest data forbidden response a status code equal to that given
func (o *IngestDataForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the ingest data forbidden response
func (o *IngestDataForbidden) Code() int {
	return 403
}

func (o *IngestDataForbidden) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataForbidden  %+v", 403, o.Payload)
}

func (o *IngestDataForbidden) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataForbidden  %+v", 403, o.Payload)
}

func (o *IngestDataForbidden) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *IngestDataForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIngestDataNotFound creates a IngestDataNotFound with default headers values
func NewIngestDataNotFound() *IngestDataNotFound {
	return &IngestDataNotFound{}
}

/*
IngestDataNotFound describes a response with status code 404, with default header values.

Not Found
*/
type IngestDataNotFound struct {

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

// IsSuccess returns true when this ingest data not found response has a 2xx status code
func (o *IngestDataNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this ingest data not found response has a 3xx status code
func (o *IngestDataNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data not found response has a 4xx status code
func (o *IngestDataNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this ingest data not found response has a 5xx status code
func (o *IngestDataNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this ingest data not found response a status code equal to that given
func (o *IngestDataNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the ingest data not found response
func (o *IngestDataNotFound) Code() int {
	return 404
}

func (o *IngestDataNotFound) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataNotFound  %+v", 404, o.Payload)
}

func (o *IngestDataNotFound) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataNotFound  %+v", 404, o.Payload)
}

func (o *IngestDataNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *IngestDataNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIngestDataTooManyRequests creates a IngestDataTooManyRequests with default headers values
func NewIngestDataTooManyRequests() *IngestDataTooManyRequests {
	return &IngestDataTooManyRequests{}
}

/*
IngestDataTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type IngestDataTooManyRequests struct {

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

// IsSuccess returns true when this ingest data too many requests response has a 2xx status code
func (o *IngestDataTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this ingest data too many requests response has a 3xx status code
func (o *IngestDataTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data too many requests response has a 4xx status code
func (o *IngestDataTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this ingest data too many requests response has a 5xx status code
func (o *IngestDataTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this ingest data too many requests response a status code equal to that given
func (o *IngestDataTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the ingest data too many requests response
func (o *IngestDataTooManyRequests) Code() int {
	return 429
}

func (o *IngestDataTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataTooManyRequests  %+v", 429, o.Payload)
}

func (o *IngestDataTooManyRequests) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataTooManyRequests  %+v", 429, o.Payload)
}

func (o *IngestDataTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *IngestDataTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIngestDataInternalServerError creates a IngestDataInternalServerError with default headers values
func NewIngestDataInternalServerError() *IngestDataInternalServerError {
	return &IngestDataInternalServerError{}
}

/*
IngestDataInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type IngestDataInternalServerError struct {

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

// IsSuccess returns true when this ingest data internal server error response has a 2xx status code
func (o *IngestDataInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this ingest data internal server error response has a 3xx status code
func (o *IngestDataInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ingest data internal server error response has a 4xx status code
func (o *IngestDataInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this ingest data internal server error response has a 5xx status code
func (o *IngestDataInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this ingest data internal server error response a status code equal to that given
func (o *IngestDataInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the ingest data internal server error response
func (o *IngestDataInternalServerError) Code() int {
	return 500
}

func (o *IngestDataInternalServerError) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataInternalServerError  %+v", 500, o.Payload)
}

func (o *IngestDataInternalServerError) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/data-ingestion/ingest/v1][%d] ingestDataInternalServerError  %+v", 500, o.Payload)
}

func (o *IngestDataInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *IngestDataInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
