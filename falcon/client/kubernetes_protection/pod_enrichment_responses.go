// Code generated by go-swagger; DO NOT EDIT.

package kubernetes_protection

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

// PodEnrichmentReader is a Reader for the PodEnrichment structure.
type PodEnrichmentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PodEnrichmentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPodEnrichmentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewPodEnrichmentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPodEnrichmentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPodEnrichmentInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/aggregates/enrichment/pods/entities/v1] PodEnrichment", response, response.Code())
	}
}

// NewPodEnrichmentOK creates a PodEnrichmentOK with default headers values
func NewPodEnrichmentOK() *PodEnrichmentOK {
	return &PodEnrichmentOK{}
}

/*
PodEnrichmentOK describes a response with status code 200, with default header values.

OK
*/
type PodEnrichmentOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.K8sassetsPodEnrichmentResponse
}

// IsSuccess returns true when this pod enrichment o k response has a 2xx status code
func (o *PodEnrichmentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pod enrichment o k response has a 3xx status code
func (o *PodEnrichmentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pod enrichment o k response has a 4xx status code
func (o *PodEnrichmentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this pod enrichment o k response has a 5xx status code
func (o *PodEnrichmentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this pod enrichment o k response a status code equal to that given
func (o *PodEnrichmentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the pod enrichment o k response
func (o *PodEnrichmentOK) Code() int {
	return 200
}

func (o *PodEnrichmentOK) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/pods/entities/v1][%d] podEnrichmentOK  %+v", 200, o.Payload)
}

func (o *PodEnrichmentOK) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/pods/entities/v1][%d] podEnrichmentOK  %+v", 200, o.Payload)
}

func (o *PodEnrichmentOK) GetPayload() *models.K8sassetsPodEnrichmentResponse {
	return o.Payload
}

func (o *PodEnrichmentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.K8sassetsPodEnrichmentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPodEnrichmentForbidden creates a PodEnrichmentForbidden with default headers values
func NewPodEnrichmentForbidden() *PodEnrichmentForbidden {
	return &PodEnrichmentForbidden{}
}

/*
PodEnrichmentForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PodEnrichmentForbidden struct {

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

// IsSuccess returns true when this pod enrichment forbidden response has a 2xx status code
func (o *PodEnrichmentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this pod enrichment forbidden response has a 3xx status code
func (o *PodEnrichmentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pod enrichment forbidden response has a 4xx status code
func (o *PodEnrichmentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this pod enrichment forbidden response has a 5xx status code
func (o *PodEnrichmentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this pod enrichment forbidden response a status code equal to that given
func (o *PodEnrichmentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the pod enrichment forbidden response
func (o *PodEnrichmentForbidden) Code() int {
	return 403
}

func (o *PodEnrichmentForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/pods/entities/v1][%d] podEnrichmentForbidden  %+v", 403, o.Payload)
}

func (o *PodEnrichmentForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/pods/entities/v1][%d] podEnrichmentForbidden  %+v", 403, o.Payload)
}

func (o *PodEnrichmentForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *PodEnrichmentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewPodEnrichmentTooManyRequests creates a PodEnrichmentTooManyRequests with default headers values
func NewPodEnrichmentTooManyRequests() *PodEnrichmentTooManyRequests {
	return &PodEnrichmentTooManyRequests{}
}

/*
PodEnrichmentTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type PodEnrichmentTooManyRequests struct {

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

// IsSuccess returns true when this pod enrichment too many requests response has a 2xx status code
func (o *PodEnrichmentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this pod enrichment too many requests response has a 3xx status code
func (o *PodEnrichmentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pod enrichment too many requests response has a 4xx status code
func (o *PodEnrichmentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this pod enrichment too many requests response has a 5xx status code
func (o *PodEnrichmentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this pod enrichment too many requests response a status code equal to that given
func (o *PodEnrichmentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the pod enrichment too many requests response
func (o *PodEnrichmentTooManyRequests) Code() int {
	return 429
}

func (o *PodEnrichmentTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/pods/entities/v1][%d] podEnrichmentTooManyRequests  %+v", 429, o.Payload)
}

func (o *PodEnrichmentTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/pods/entities/v1][%d] podEnrichmentTooManyRequests  %+v", 429, o.Payload)
}

func (o *PodEnrichmentTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *PodEnrichmentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewPodEnrichmentInternalServerError creates a PodEnrichmentInternalServerError with default headers values
func NewPodEnrichmentInternalServerError() *PodEnrichmentInternalServerError {
	return &PodEnrichmentInternalServerError{}
}

/*
PodEnrichmentInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PodEnrichmentInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.CoreEntitiesResponse
}

// IsSuccess returns true when this pod enrichment internal server error response has a 2xx status code
func (o *PodEnrichmentInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this pod enrichment internal server error response has a 3xx status code
func (o *PodEnrichmentInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pod enrichment internal server error response has a 4xx status code
func (o *PodEnrichmentInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this pod enrichment internal server error response has a 5xx status code
func (o *PodEnrichmentInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this pod enrichment internal server error response a status code equal to that given
func (o *PodEnrichmentInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the pod enrichment internal server error response
func (o *PodEnrichmentInternalServerError) Code() int {
	return 500
}

func (o *PodEnrichmentInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/pods/entities/v1][%d] podEnrichmentInternalServerError  %+v", 500, o.Payload)
}

func (o *PodEnrichmentInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/pods/entities/v1][%d] podEnrichmentInternalServerError  %+v", 500, o.Payload)
}

func (o *PodEnrichmentInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *PodEnrichmentInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.CoreEntitiesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
