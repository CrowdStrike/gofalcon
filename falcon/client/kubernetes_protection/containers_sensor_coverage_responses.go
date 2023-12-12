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

// ContainersSensorCoverageReader is a Reader for the ContainersSensorCoverage structure.
type ContainersSensorCoverageReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ContainersSensorCoverageReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewContainersSensorCoverageOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewContainersSensorCoverageForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewContainersSensorCoverageTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewContainersSensorCoverageInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/aggregates/containers/sensor-coverage/v1] ContainersSensorCoverage", response, response.Code())
	}
}

// NewContainersSensorCoverageOK creates a ContainersSensorCoverageOK with default headers values
func NewContainersSensorCoverageOK() *ContainersSensorCoverageOK {
	return &ContainersSensorCoverageOK{}
}

/*
ContainersSensorCoverageOK describes a response with status code 200, with default header values.

OK
*/
type ContainersSensorCoverageOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ModelsAggregateValuesByFieldResponse
}

// IsSuccess returns true when this containers sensor coverage o k response has a 2xx status code
func (o *ContainersSensorCoverageOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this containers sensor coverage o k response has a 3xx status code
func (o *ContainersSensorCoverageOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this containers sensor coverage o k response has a 4xx status code
func (o *ContainersSensorCoverageOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this containers sensor coverage o k response has a 5xx status code
func (o *ContainersSensorCoverageOK) IsServerError() bool {
	return false
}

// IsCode returns true when this containers sensor coverage o k response a status code equal to that given
func (o *ContainersSensorCoverageOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the containers sensor coverage o k response
func (o *ContainersSensorCoverageOK) Code() int {
	return 200
}

func (o *ContainersSensorCoverageOK) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/containers/sensor-coverage/v1][%d] containersSensorCoverageOK  %+v", 200, o.Payload)
}

func (o *ContainersSensorCoverageOK) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/containers/sensor-coverage/v1][%d] containersSensorCoverageOK  %+v", 200, o.Payload)
}

func (o *ContainersSensorCoverageOK) GetPayload() *models.ModelsAggregateValuesByFieldResponse {
	return o.Payload
}

func (o *ContainersSensorCoverageOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ModelsAggregateValuesByFieldResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewContainersSensorCoverageForbidden creates a ContainersSensorCoverageForbidden with default headers values
func NewContainersSensorCoverageForbidden() *ContainersSensorCoverageForbidden {
	return &ContainersSensorCoverageForbidden{}
}

/*
ContainersSensorCoverageForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ContainersSensorCoverageForbidden struct {

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

// IsSuccess returns true when this containers sensor coverage forbidden response has a 2xx status code
func (o *ContainersSensorCoverageForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this containers sensor coverage forbidden response has a 3xx status code
func (o *ContainersSensorCoverageForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this containers sensor coverage forbidden response has a 4xx status code
func (o *ContainersSensorCoverageForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this containers sensor coverage forbidden response has a 5xx status code
func (o *ContainersSensorCoverageForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this containers sensor coverage forbidden response a status code equal to that given
func (o *ContainersSensorCoverageForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the containers sensor coverage forbidden response
func (o *ContainersSensorCoverageForbidden) Code() int {
	return 403
}

func (o *ContainersSensorCoverageForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/containers/sensor-coverage/v1][%d] containersSensorCoverageForbidden  %+v", 403, o.Payload)
}

func (o *ContainersSensorCoverageForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/containers/sensor-coverage/v1][%d] containersSensorCoverageForbidden  %+v", 403, o.Payload)
}

func (o *ContainersSensorCoverageForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ContainersSensorCoverageForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewContainersSensorCoverageTooManyRequests creates a ContainersSensorCoverageTooManyRequests with default headers values
func NewContainersSensorCoverageTooManyRequests() *ContainersSensorCoverageTooManyRequests {
	return &ContainersSensorCoverageTooManyRequests{}
}

/*
ContainersSensorCoverageTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ContainersSensorCoverageTooManyRequests struct {

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

// IsSuccess returns true when this containers sensor coverage too many requests response has a 2xx status code
func (o *ContainersSensorCoverageTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this containers sensor coverage too many requests response has a 3xx status code
func (o *ContainersSensorCoverageTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this containers sensor coverage too many requests response has a 4xx status code
func (o *ContainersSensorCoverageTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this containers sensor coverage too many requests response has a 5xx status code
func (o *ContainersSensorCoverageTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this containers sensor coverage too many requests response a status code equal to that given
func (o *ContainersSensorCoverageTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the containers sensor coverage too many requests response
func (o *ContainersSensorCoverageTooManyRequests) Code() int {
	return 429
}

func (o *ContainersSensorCoverageTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/containers/sensor-coverage/v1][%d] containersSensorCoverageTooManyRequests  %+v", 429, o.Payload)
}

func (o *ContainersSensorCoverageTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/containers/sensor-coverage/v1][%d] containersSensorCoverageTooManyRequests  %+v", 429, o.Payload)
}

func (o *ContainersSensorCoverageTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ContainersSensorCoverageTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewContainersSensorCoverageInternalServerError creates a ContainersSensorCoverageInternalServerError with default headers values
func NewContainersSensorCoverageInternalServerError() *ContainersSensorCoverageInternalServerError {
	return &ContainersSensorCoverageInternalServerError{}
}

/*
ContainersSensorCoverageInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ContainersSensorCoverageInternalServerError struct {

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

// IsSuccess returns true when this containers sensor coverage internal server error response has a 2xx status code
func (o *ContainersSensorCoverageInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this containers sensor coverage internal server error response has a 3xx status code
func (o *ContainersSensorCoverageInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this containers sensor coverage internal server error response has a 4xx status code
func (o *ContainersSensorCoverageInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this containers sensor coverage internal server error response has a 5xx status code
func (o *ContainersSensorCoverageInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this containers sensor coverage internal server error response a status code equal to that given
func (o *ContainersSensorCoverageInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the containers sensor coverage internal server error response
func (o *ContainersSensorCoverageInternalServerError) Code() int {
	return 500
}

func (o *ContainersSensorCoverageInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/containers/sensor-coverage/v1][%d] containersSensorCoverageInternalServerError  %+v", 500, o.Payload)
}

func (o *ContainersSensorCoverageInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/containers/sensor-coverage/v1][%d] containersSensorCoverageInternalServerError  %+v", 500, o.Payload)
}

func (o *ContainersSensorCoverageInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *ContainersSensorCoverageInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
