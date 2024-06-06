// Code generated by go-swagger; DO NOT EDIT.

package recon

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

// AggregateNotificationsExposedDataRecordsV1Reader is a Reader for the AggregateNotificationsExposedDataRecordsV1 structure.
type AggregateNotificationsExposedDataRecordsV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AggregateNotificationsExposedDataRecordsV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAggregateNotificationsExposedDataRecordsV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewAggregateNotificationsExposedDataRecordsV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewAggregateNotificationsExposedDataRecordsV1Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAggregateNotificationsExposedDataRecordsV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAggregateNotificationsExposedDataRecordsV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewAggregateNotificationsExposedDataRecordsV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1] AggregateNotificationsExposedDataRecordsV1", response, response.Code())
	}
}

// NewAggregateNotificationsExposedDataRecordsV1OK creates a AggregateNotificationsExposedDataRecordsV1OK with default headers values
func NewAggregateNotificationsExposedDataRecordsV1OK() *AggregateNotificationsExposedDataRecordsV1OK {
	return &AggregateNotificationsExposedDataRecordsV1OK{}
}

/*
AggregateNotificationsExposedDataRecordsV1OK describes a response with status code 200, with default header values.

OK
*/
type AggregateNotificationsExposedDataRecordsV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainAggregatesResponse
}

// IsSuccess returns true when this aggregate notifications exposed data records v1 o k response has a 2xx status code
func (o *AggregateNotificationsExposedDataRecordsV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this aggregate notifications exposed data records v1 o k response has a 3xx status code
func (o *AggregateNotificationsExposedDataRecordsV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate notifications exposed data records v1 o k response has a 4xx status code
func (o *AggregateNotificationsExposedDataRecordsV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this aggregate notifications exposed data records v1 o k response has a 5xx status code
func (o *AggregateNotificationsExposedDataRecordsV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate notifications exposed data records v1 o k response a status code equal to that given
func (o *AggregateNotificationsExposedDataRecordsV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the aggregate notifications exposed data records v1 o k response
func (o *AggregateNotificationsExposedDataRecordsV1OK) Code() int {
	return 200
}

func (o *AggregateNotificationsExposedDataRecordsV1OK) Error() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1OK  %+v", 200, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1OK) String() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1OK  %+v", 200, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1OK) GetPayload() *models.DomainAggregatesResponse {
	return o.Payload
}

func (o *AggregateNotificationsExposedDataRecordsV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainAggregatesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAggregateNotificationsExposedDataRecordsV1BadRequest creates a AggregateNotificationsExposedDataRecordsV1BadRequest with default headers values
func NewAggregateNotificationsExposedDataRecordsV1BadRequest() *AggregateNotificationsExposedDataRecordsV1BadRequest {
	return &AggregateNotificationsExposedDataRecordsV1BadRequest{}
}

/*
AggregateNotificationsExposedDataRecordsV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type AggregateNotificationsExposedDataRecordsV1BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this aggregate notifications exposed data records v1 bad request response has a 2xx status code
func (o *AggregateNotificationsExposedDataRecordsV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate notifications exposed data records v1 bad request response has a 3xx status code
func (o *AggregateNotificationsExposedDataRecordsV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate notifications exposed data records v1 bad request response has a 4xx status code
func (o *AggregateNotificationsExposedDataRecordsV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate notifications exposed data records v1 bad request response has a 5xx status code
func (o *AggregateNotificationsExposedDataRecordsV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate notifications exposed data records v1 bad request response a status code equal to that given
func (o *AggregateNotificationsExposedDataRecordsV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the aggregate notifications exposed data records v1 bad request response
func (o *AggregateNotificationsExposedDataRecordsV1BadRequest) Code() int {
	return 400
}

func (o *AggregateNotificationsExposedDataRecordsV1BadRequest) Error() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1BadRequest  %+v", 400, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1BadRequest) String() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1BadRequest  %+v", 400, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1BadRequest) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *AggregateNotificationsExposedDataRecordsV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAggregateNotificationsExposedDataRecordsV1Unauthorized creates a AggregateNotificationsExposedDataRecordsV1Unauthorized with default headers values
func NewAggregateNotificationsExposedDataRecordsV1Unauthorized() *AggregateNotificationsExposedDataRecordsV1Unauthorized {
	return &AggregateNotificationsExposedDataRecordsV1Unauthorized{}
}

/*
AggregateNotificationsExposedDataRecordsV1Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type AggregateNotificationsExposedDataRecordsV1Unauthorized struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this aggregate notifications exposed data records v1 unauthorized response has a 2xx status code
func (o *AggregateNotificationsExposedDataRecordsV1Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate notifications exposed data records v1 unauthorized response has a 3xx status code
func (o *AggregateNotificationsExposedDataRecordsV1Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate notifications exposed data records v1 unauthorized response has a 4xx status code
func (o *AggregateNotificationsExposedDataRecordsV1Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate notifications exposed data records v1 unauthorized response has a 5xx status code
func (o *AggregateNotificationsExposedDataRecordsV1Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate notifications exposed data records v1 unauthorized response a status code equal to that given
func (o *AggregateNotificationsExposedDataRecordsV1Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the aggregate notifications exposed data records v1 unauthorized response
func (o *AggregateNotificationsExposedDataRecordsV1Unauthorized) Code() int {
	return 401
}

func (o *AggregateNotificationsExposedDataRecordsV1Unauthorized) Error() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1Unauthorized  %+v", 401, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1Unauthorized) String() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1Unauthorized  %+v", 401, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1Unauthorized) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *AggregateNotificationsExposedDataRecordsV1Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAggregateNotificationsExposedDataRecordsV1Forbidden creates a AggregateNotificationsExposedDataRecordsV1Forbidden with default headers values
func NewAggregateNotificationsExposedDataRecordsV1Forbidden() *AggregateNotificationsExposedDataRecordsV1Forbidden {
	return &AggregateNotificationsExposedDataRecordsV1Forbidden{}
}

/*
AggregateNotificationsExposedDataRecordsV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AggregateNotificationsExposedDataRecordsV1Forbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this aggregate notifications exposed data records v1 forbidden response has a 2xx status code
func (o *AggregateNotificationsExposedDataRecordsV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate notifications exposed data records v1 forbidden response has a 3xx status code
func (o *AggregateNotificationsExposedDataRecordsV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate notifications exposed data records v1 forbidden response has a 4xx status code
func (o *AggregateNotificationsExposedDataRecordsV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate notifications exposed data records v1 forbidden response has a 5xx status code
func (o *AggregateNotificationsExposedDataRecordsV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate notifications exposed data records v1 forbidden response a status code equal to that given
func (o *AggregateNotificationsExposedDataRecordsV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the aggregate notifications exposed data records v1 forbidden response
func (o *AggregateNotificationsExposedDataRecordsV1Forbidden) Code() int {
	return 403
}

func (o *AggregateNotificationsExposedDataRecordsV1Forbidden) Error() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1Forbidden  %+v", 403, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1Forbidden) String() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1Forbidden  %+v", 403, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1Forbidden) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *AggregateNotificationsExposedDataRecordsV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAggregateNotificationsExposedDataRecordsV1TooManyRequests creates a AggregateNotificationsExposedDataRecordsV1TooManyRequests with default headers values
func NewAggregateNotificationsExposedDataRecordsV1TooManyRequests() *AggregateNotificationsExposedDataRecordsV1TooManyRequests {
	return &AggregateNotificationsExposedDataRecordsV1TooManyRequests{}
}

/*
AggregateNotificationsExposedDataRecordsV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type AggregateNotificationsExposedDataRecordsV1TooManyRequests struct {

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

// IsSuccess returns true when this aggregate notifications exposed data records v1 too many requests response has a 2xx status code
func (o *AggregateNotificationsExposedDataRecordsV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate notifications exposed data records v1 too many requests response has a 3xx status code
func (o *AggregateNotificationsExposedDataRecordsV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate notifications exposed data records v1 too many requests response has a 4xx status code
func (o *AggregateNotificationsExposedDataRecordsV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate notifications exposed data records v1 too many requests response has a 5xx status code
func (o *AggregateNotificationsExposedDataRecordsV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate notifications exposed data records v1 too many requests response a status code equal to that given
func (o *AggregateNotificationsExposedDataRecordsV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the aggregate notifications exposed data records v1 too many requests response
func (o *AggregateNotificationsExposedDataRecordsV1TooManyRequests) Code() int {
	return 429
}

func (o *AggregateNotificationsExposedDataRecordsV1TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1TooManyRequests) String() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *AggregateNotificationsExposedDataRecordsV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewAggregateNotificationsExposedDataRecordsV1InternalServerError creates a AggregateNotificationsExposedDataRecordsV1InternalServerError with default headers values
func NewAggregateNotificationsExposedDataRecordsV1InternalServerError() *AggregateNotificationsExposedDataRecordsV1InternalServerError {
	return &AggregateNotificationsExposedDataRecordsV1InternalServerError{}
}

/*
AggregateNotificationsExposedDataRecordsV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type AggregateNotificationsExposedDataRecordsV1InternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this aggregate notifications exposed data records v1 internal server error response has a 2xx status code
func (o *AggregateNotificationsExposedDataRecordsV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate notifications exposed data records v1 internal server error response has a 3xx status code
func (o *AggregateNotificationsExposedDataRecordsV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate notifications exposed data records v1 internal server error response has a 4xx status code
func (o *AggregateNotificationsExposedDataRecordsV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this aggregate notifications exposed data records v1 internal server error response has a 5xx status code
func (o *AggregateNotificationsExposedDataRecordsV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this aggregate notifications exposed data records v1 internal server error response a status code equal to that given
func (o *AggregateNotificationsExposedDataRecordsV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the aggregate notifications exposed data records v1 internal server error response
func (o *AggregateNotificationsExposedDataRecordsV1InternalServerError) Code() int {
	return 500
}

func (o *AggregateNotificationsExposedDataRecordsV1InternalServerError) Error() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1InternalServerError  %+v", 500, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1InternalServerError) String() string {
	return fmt.Sprintf("[POST /recon/aggregates/notifications-exposed-data-records/GET/v1][%d] aggregateNotificationsExposedDataRecordsV1InternalServerError  %+v", 500, o.Payload)
}

func (o *AggregateNotificationsExposedDataRecordsV1InternalServerError) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *AggregateNotificationsExposedDataRecordsV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
