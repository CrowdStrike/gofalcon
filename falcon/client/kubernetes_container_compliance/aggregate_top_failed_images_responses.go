// Code generated by go-swagger; DO NOT EDIT.

package kubernetes_container_compliance

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

// AggregateTopFailedImagesReader is a Reader for the AggregateTopFailedImages structure.
type AggregateTopFailedImagesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AggregateTopFailedImagesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAggregateTopFailedImagesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewAggregateTopFailedImagesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAggregateTopFailedImagesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAggregateTopFailedImagesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewAggregateTopFailedImagesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-compliance/aggregates/top-failed-images/v2] AggregateTopFailedImages", response, response.Code())
	}
}

// NewAggregateTopFailedImagesOK creates a AggregateTopFailedImagesOK with default headers values
func NewAggregateTopFailedImagesOK() *AggregateTopFailedImagesOK {
	return &AggregateTopFailedImagesOK{}
}

/*
AggregateTopFailedImagesOK describes a response with status code 200, with default header values.

OK
*/
type AggregateTopFailedImagesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainAPIAggregateResponseTopFailedImagesV1
}

// IsSuccess returns true when this aggregate top failed images o k response has a 2xx status code
func (o *AggregateTopFailedImagesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this aggregate top failed images o k response has a 3xx status code
func (o *AggregateTopFailedImagesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate top failed images o k response has a 4xx status code
func (o *AggregateTopFailedImagesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this aggregate top failed images o k response has a 5xx status code
func (o *AggregateTopFailedImagesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate top failed images o k response a status code equal to that given
func (o *AggregateTopFailedImagesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the aggregate top failed images o k response
func (o *AggregateTopFailedImagesOK) Code() int {
	return 200
}

func (o *AggregateTopFailedImagesOK) Error() string {
	return fmt.Sprintf("[GET /container-compliance/aggregates/top-failed-images/v2][%d] aggregateTopFailedImagesOK  %+v", 200, o.Payload)
}

func (o *AggregateTopFailedImagesOK) String() string {
	return fmt.Sprintf("[GET /container-compliance/aggregates/top-failed-images/v2][%d] aggregateTopFailedImagesOK  %+v", 200, o.Payload)
}

func (o *AggregateTopFailedImagesOK) GetPayload() *models.DomainAPIAggregateResponseTopFailedImagesV1 {
	return o.Payload
}

func (o *AggregateTopFailedImagesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainAPIAggregateResponseTopFailedImagesV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAggregateTopFailedImagesBadRequest creates a AggregateTopFailedImagesBadRequest with default headers values
func NewAggregateTopFailedImagesBadRequest() *AggregateTopFailedImagesBadRequest {
	return &AggregateTopFailedImagesBadRequest{}
}

/*
AggregateTopFailedImagesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type AggregateTopFailedImagesBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainAPIAggregateResponseTopFailedImagesV1
}

// IsSuccess returns true when this aggregate top failed images bad request response has a 2xx status code
func (o *AggregateTopFailedImagesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate top failed images bad request response has a 3xx status code
func (o *AggregateTopFailedImagesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate top failed images bad request response has a 4xx status code
func (o *AggregateTopFailedImagesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate top failed images bad request response has a 5xx status code
func (o *AggregateTopFailedImagesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate top failed images bad request response a status code equal to that given
func (o *AggregateTopFailedImagesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the aggregate top failed images bad request response
func (o *AggregateTopFailedImagesBadRequest) Code() int {
	return 400
}

func (o *AggregateTopFailedImagesBadRequest) Error() string {
	return fmt.Sprintf("[GET /container-compliance/aggregates/top-failed-images/v2][%d] aggregateTopFailedImagesBadRequest  %+v", 400, o.Payload)
}

func (o *AggregateTopFailedImagesBadRequest) String() string {
	return fmt.Sprintf("[GET /container-compliance/aggregates/top-failed-images/v2][%d] aggregateTopFailedImagesBadRequest  %+v", 400, o.Payload)
}

func (o *AggregateTopFailedImagesBadRequest) GetPayload() *models.DomainAPIAggregateResponseTopFailedImagesV1 {
	return o.Payload
}

func (o *AggregateTopFailedImagesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainAPIAggregateResponseTopFailedImagesV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAggregateTopFailedImagesForbidden creates a AggregateTopFailedImagesForbidden with default headers values
func NewAggregateTopFailedImagesForbidden() *AggregateTopFailedImagesForbidden {
	return &AggregateTopFailedImagesForbidden{}
}

/*
AggregateTopFailedImagesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AggregateTopFailedImagesForbidden struct {

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

// IsSuccess returns true when this aggregate top failed images forbidden response has a 2xx status code
func (o *AggregateTopFailedImagesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate top failed images forbidden response has a 3xx status code
func (o *AggregateTopFailedImagesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate top failed images forbidden response has a 4xx status code
func (o *AggregateTopFailedImagesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate top failed images forbidden response has a 5xx status code
func (o *AggregateTopFailedImagesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate top failed images forbidden response a status code equal to that given
func (o *AggregateTopFailedImagesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the aggregate top failed images forbidden response
func (o *AggregateTopFailedImagesForbidden) Code() int {
	return 403
}

func (o *AggregateTopFailedImagesForbidden) Error() string {
	return fmt.Sprintf("[GET /container-compliance/aggregates/top-failed-images/v2][%d] aggregateTopFailedImagesForbidden  %+v", 403, o.Payload)
}

func (o *AggregateTopFailedImagesForbidden) String() string {
	return fmt.Sprintf("[GET /container-compliance/aggregates/top-failed-images/v2][%d] aggregateTopFailedImagesForbidden  %+v", 403, o.Payload)
}

func (o *AggregateTopFailedImagesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *AggregateTopFailedImagesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewAggregateTopFailedImagesTooManyRequests creates a AggregateTopFailedImagesTooManyRequests with default headers values
func NewAggregateTopFailedImagesTooManyRequests() *AggregateTopFailedImagesTooManyRequests {
	return &AggregateTopFailedImagesTooManyRequests{}
}

/*
AggregateTopFailedImagesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type AggregateTopFailedImagesTooManyRequests struct {

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

// IsSuccess returns true when this aggregate top failed images too many requests response has a 2xx status code
func (o *AggregateTopFailedImagesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate top failed images too many requests response has a 3xx status code
func (o *AggregateTopFailedImagesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate top failed images too many requests response has a 4xx status code
func (o *AggregateTopFailedImagesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate top failed images too many requests response has a 5xx status code
func (o *AggregateTopFailedImagesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate top failed images too many requests response a status code equal to that given
func (o *AggregateTopFailedImagesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the aggregate top failed images too many requests response
func (o *AggregateTopFailedImagesTooManyRequests) Code() int {
	return 429
}

func (o *AggregateTopFailedImagesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-compliance/aggregates/top-failed-images/v2][%d] aggregateTopFailedImagesTooManyRequests  %+v", 429, o.Payload)
}

func (o *AggregateTopFailedImagesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-compliance/aggregates/top-failed-images/v2][%d] aggregateTopFailedImagesTooManyRequests  %+v", 429, o.Payload)
}

func (o *AggregateTopFailedImagesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *AggregateTopFailedImagesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewAggregateTopFailedImagesInternalServerError creates a AggregateTopFailedImagesInternalServerError with default headers values
func NewAggregateTopFailedImagesInternalServerError() *AggregateTopFailedImagesInternalServerError {
	return &AggregateTopFailedImagesInternalServerError{}
}

/*
AggregateTopFailedImagesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type AggregateTopFailedImagesInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainAPIAggregateResponseTopFailedImagesV1
}

// IsSuccess returns true when this aggregate top failed images internal server error response has a 2xx status code
func (o *AggregateTopFailedImagesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate top failed images internal server error response has a 3xx status code
func (o *AggregateTopFailedImagesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate top failed images internal server error response has a 4xx status code
func (o *AggregateTopFailedImagesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this aggregate top failed images internal server error response has a 5xx status code
func (o *AggregateTopFailedImagesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this aggregate top failed images internal server error response a status code equal to that given
func (o *AggregateTopFailedImagesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the aggregate top failed images internal server error response
func (o *AggregateTopFailedImagesInternalServerError) Code() int {
	return 500
}

func (o *AggregateTopFailedImagesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-compliance/aggregates/top-failed-images/v2][%d] aggregateTopFailedImagesInternalServerError  %+v", 500, o.Payload)
}

func (o *AggregateTopFailedImagesInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-compliance/aggregates/top-failed-images/v2][%d] aggregateTopFailedImagesInternalServerError  %+v", 500, o.Payload)
}

func (o *AggregateTopFailedImagesInternalServerError) GetPayload() *models.DomainAPIAggregateResponseTopFailedImagesV1 {
	return o.Payload
}

func (o *AggregateTopFailedImagesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainAPIAggregateResponseTopFailedImagesV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
