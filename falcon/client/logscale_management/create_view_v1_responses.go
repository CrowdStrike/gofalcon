// Code generated by go-swagger; DO NOT EDIT.

package logscale_management

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

// CreateViewV1Reader is a Reader for the CreateViewV1 structure.
type CreateViewV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateViewV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateViewV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewCreateViewV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateViewV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /loggingapi/entities/views/v1] CreateViewV1", response, response.Code())
	}
}

// NewCreateViewV1OK creates a CreateViewV1OK with default headers values
func NewCreateViewV1OK() *CreateViewV1OK {
	return &CreateViewV1OK{}
}

/*
CreateViewV1OK describes a response with status code 200, with default header values.

OK
*/
type CreateViewV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.HumioViewWrapper
}

// IsSuccess returns true when this create view v1 o k response has a 2xx status code
func (o *CreateViewV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create view v1 o k response has a 3xx status code
func (o *CreateViewV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create view v1 o k response has a 4xx status code
func (o *CreateViewV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create view v1 o k response has a 5xx status code
func (o *CreateViewV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this create view v1 o k response a status code equal to that given
func (o *CreateViewV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create view v1 o k response
func (o *CreateViewV1OK) Code() int {
	return 200
}

func (o *CreateViewV1OK) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewV1OK  %+v", 200, o.Payload)
}

func (o *CreateViewV1OK) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewV1OK  %+v", 200, o.Payload)
}

func (o *CreateViewV1OK) GetPayload() *models.HumioViewWrapper {
	return o.Payload
}

func (o *CreateViewV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.HumioViewWrapper)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateViewV1Forbidden creates a CreateViewV1Forbidden with default headers values
func NewCreateViewV1Forbidden() *CreateViewV1Forbidden {
	return &CreateViewV1Forbidden{}
}

/*
CreateViewV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateViewV1Forbidden struct {

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

// IsSuccess returns true when this create view v1 forbidden response has a 2xx status code
func (o *CreateViewV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create view v1 forbidden response has a 3xx status code
func (o *CreateViewV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create view v1 forbidden response has a 4xx status code
func (o *CreateViewV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create view v1 forbidden response has a 5xx status code
func (o *CreateViewV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create view v1 forbidden response a status code equal to that given
func (o *CreateViewV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create view v1 forbidden response
func (o *CreateViewV1Forbidden) Code() int {
	return 403
}

func (o *CreateViewV1Forbidden) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewV1Forbidden  %+v", 403, o.Payload)
}

func (o *CreateViewV1Forbidden) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewV1Forbidden  %+v", 403, o.Payload)
}

func (o *CreateViewV1Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateViewV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateViewV1TooManyRequests creates a CreateViewV1TooManyRequests with default headers values
func NewCreateViewV1TooManyRequests() *CreateViewV1TooManyRequests {
	return &CreateViewV1TooManyRequests{}
}

/*
CreateViewV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateViewV1TooManyRequests struct {

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

// IsSuccess returns true when this create view v1 too many requests response has a 2xx status code
func (o *CreateViewV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create view v1 too many requests response has a 3xx status code
func (o *CreateViewV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create view v1 too many requests response has a 4xx status code
func (o *CreateViewV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create view v1 too many requests response has a 5xx status code
func (o *CreateViewV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create view v1 too many requests response a status code equal to that given
func (o *CreateViewV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create view v1 too many requests response
func (o *CreateViewV1TooManyRequests) Code() int {
	return 429
}

func (o *CreateViewV1TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateViewV1TooManyRequests) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateViewV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateViewV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
