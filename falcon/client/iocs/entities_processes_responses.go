// Code generated by go-swagger; DO NOT EDIT.

package iocs

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

// EntitiesProcessesReader is a Reader for the EntitiesProcesses structure.
type EntitiesProcessesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *EntitiesProcessesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewEntitiesProcessesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewEntitiesProcessesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewEntitiesProcessesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /processes/entities/processes/v1] entities.processes", response, response.Code())
	}
}

// NewEntitiesProcessesOK creates a EntitiesProcessesOK with default headers values
func NewEntitiesProcessesOK() *EntitiesProcessesOK {
	return &EntitiesProcessesOK{}
}

/* EntitiesProcessesOK describes a response with status code 200, with default header values.

OK
*/
type EntitiesProcessesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ProcessesapiMsaProcessDetailResponse
}

// IsSuccess returns true when this entities processes o k response has a 2xx status code
func (o *EntitiesProcessesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this entities processes o k response has a 3xx status code
func (o *EntitiesProcessesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities processes o k response has a 4xx status code
func (o *EntitiesProcessesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this entities processes o k response has a 5xx status code
func (o *EntitiesProcessesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this entities processes o k response a status code equal to that given
func (o *EntitiesProcessesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the entities processes o k response
func (o *EntitiesProcessesOK) Code() int {
	return 200
}

func (o *EntitiesProcessesOK) Error() string {
	return fmt.Sprintf("[GET /processes/entities/processes/v1][%d] entitiesProcessesOK  %+v", 200, o.Payload)
}

func (o *EntitiesProcessesOK) String() string {
	return fmt.Sprintf("[GET /processes/entities/processes/v1][%d] entitiesProcessesOK  %+v", 200, o.Payload)
}

func (o *EntitiesProcessesOK) GetPayload() *models.ProcessesapiMsaProcessDetailResponse {
	return o.Payload
}

func (o *EntitiesProcessesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ProcessesapiMsaProcessDetailResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEntitiesProcessesForbidden creates a EntitiesProcessesForbidden with default headers values
func NewEntitiesProcessesForbidden() *EntitiesProcessesForbidden {
	return &EntitiesProcessesForbidden{}
}

/* EntitiesProcessesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type EntitiesProcessesForbidden struct {

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

// IsSuccess returns true when this entities processes forbidden response has a 2xx status code
func (o *EntitiesProcessesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities processes forbidden response has a 3xx status code
func (o *EntitiesProcessesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities processes forbidden response has a 4xx status code
func (o *EntitiesProcessesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities processes forbidden response has a 5xx status code
func (o *EntitiesProcessesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this entities processes forbidden response a status code equal to that given
func (o *EntitiesProcessesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the entities processes forbidden response
func (o *EntitiesProcessesForbidden) Code() int {
	return 403
}

func (o *EntitiesProcessesForbidden) Error() string {
	return fmt.Sprintf("[GET /processes/entities/processes/v1][%d] entitiesProcessesForbidden  %+v", 403, o.Payload)
}

func (o *EntitiesProcessesForbidden) String() string {
	return fmt.Sprintf("[GET /processes/entities/processes/v1][%d] entitiesProcessesForbidden  %+v", 403, o.Payload)
}

func (o *EntitiesProcessesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *EntitiesProcessesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewEntitiesProcessesTooManyRequests creates a EntitiesProcessesTooManyRequests with default headers values
func NewEntitiesProcessesTooManyRequests() *EntitiesProcessesTooManyRequests {
	return &EntitiesProcessesTooManyRequests{}
}

/* EntitiesProcessesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type EntitiesProcessesTooManyRequests struct {

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

// IsSuccess returns true when this entities processes too many requests response has a 2xx status code
func (o *EntitiesProcessesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities processes too many requests response has a 3xx status code
func (o *EntitiesProcessesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities processes too many requests response has a 4xx status code
func (o *EntitiesProcessesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities processes too many requests response has a 5xx status code
func (o *EntitiesProcessesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this entities processes too many requests response a status code equal to that given
func (o *EntitiesProcessesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the entities processes too many requests response
func (o *EntitiesProcessesTooManyRequests) Code() int {
	return 429
}

func (o *EntitiesProcessesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /processes/entities/processes/v1][%d] entitiesProcessesTooManyRequests  %+v", 429, o.Payload)
}

func (o *EntitiesProcessesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /processes/entities/processes/v1][%d] entitiesProcessesTooManyRequests  %+v", 429, o.Payload)
}

func (o *EntitiesProcessesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *EntitiesProcessesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
