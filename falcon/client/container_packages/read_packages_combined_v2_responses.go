// Code generated by go-swagger; DO NOT EDIT.

package container_packages

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

// ReadPackagesCombinedV2Reader is a Reader for the ReadPackagesCombinedV2 structure.
type ReadPackagesCombinedV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReadPackagesCombinedV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewReadPackagesCombinedV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewReadPackagesCombinedV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewReadPackagesCombinedV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewReadPackagesCombinedV2InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/combined/packages/v2] ReadPackagesCombinedV2", response, response.Code())
	}
}

// NewReadPackagesCombinedV2OK creates a ReadPackagesCombinedV2OK with default headers values
func NewReadPackagesCombinedV2OK() *ReadPackagesCombinedV2OK {
	return &ReadPackagesCombinedV2OK{}
}

/*
ReadPackagesCombinedV2OK describes a response with status code 200, with default header values.

OK
*/
type ReadPackagesCombinedV2OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.PackagesAPICombinedPackageV2
}

// IsSuccess returns true when this read packages combined v2 o k response has a 2xx status code
func (o *ReadPackagesCombinedV2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this read packages combined v2 o k response has a 3xx status code
func (o *ReadPackagesCombinedV2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read packages combined v2 o k response has a 4xx status code
func (o *ReadPackagesCombinedV2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this read packages combined v2 o k response has a 5xx status code
func (o *ReadPackagesCombinedV2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this read packages combined v2 o k response a status code equal to that given
func (o *ReadPackagesCombinedV2OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the read packages combined v2 o k response
func (o *ReadPackagesCombinedV2OK) Code() int {
	return 200
}

func (o *ReadPackagesCombinedV2OK) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/packages/v2][%d] readPackagesCombinedV2OK  %+v", 200, o.Payload)
}

func (o *ReadPackagesCombinedV2OK) String() string {
	return fmt.Sprintf("[GET /container-security/combined/packages/v2][%d] readPackagesCombinedV2OK  %+v", 200, o.Payload)
}

func (o *ReadPackagesCombinedV2OK) GetPayload() *models.PackagesAPICombinedPackageV2 {
	return o.Payload
}

func (o *ReadPackagesCombinedV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.PackagesAPICombinedPackageV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewReadPackagesCombinedV2Forbidden creates a ReadPackagesCombinedV2Forbidden with default headers values
func NewReadPackagesCombinedV2Forbidden() *ReadPackagesCombinedV2Forbidden {
	return &ReadPackagesCombinedV2Forbidden{}
}

/*
ReadPackagesCombinedV2Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ReadPackagesCombinedV2Forbidden struct {

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

// IsSuccess returns true when this read packages combined v2 forbidden response has a 2xx status code
func (o *ReadPackagesCombinedV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read packages combined v2 forbidden response has a 3xx status code
func (o *ReadPackagesCombinedV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read packages combined v2 forbidden response has a 4xx status code
func (o *ReadPackagesCombinedV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this read packages combined v2 forbidden response has a 5xx status code
func (o *ReadPackagesCombinedV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this read packages combined v2 forbidden response a status code equal to that given
func (o *ReadPackagesCombinedV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the read packages combined v2 forbidden response
func (o *ReadPackagesCombinedV2Forbidden) Code() int {
	return 403
}

func (o *ReadPackagesCombinedV2Forbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/packages/v2][%d] readPackagesCombinedV2Forbidden  %+v", 403, o.Payload)
}

func (o *ReadPackagesCombinedV2Forbidden) String() string {
	return fmt.Sprintf("[GET /container-security/combined/packages/v2][%d] readPackagesCombinedV2Forbidden  %+v", 403, o.Payload)
}

func (o *ReadPackagesCombinedV2Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReadPackagesCombinedV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReadPackagesCombinedV2TooManyRequests creates a ReadPackagesCombinedV2TooManyRequests with default headers values
func NewReadPackagesCombinedV2TooManyRequests() *ReadPackagesCombinedV2TooManyRequests {
	return &ReadPackagesCombinedV2TooManyRequests{}
}

/*
ReadPackagesCombinedV2TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ReadPackagesCombinedV2TooManyRequests struct {

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

// IsSuccess returns true when this read packages combined v2 too many requests response has a 2xx status code
func (o *ReadPackagesCombinedV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read packages combined v2 too many requests response has a 3xx status code
func (o *ReadPackagesCombinedV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read packages combined v2 too many requests response has a 4xx status code
func (o *ReadPackagesCombinedV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this read packages combined v2 too many requests response has a 5xx status code
func (o *ReadPackagesCombinedV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this read packages combined v2 too many requests response a status code equal to that given
func (o *ReadPackagesCombinedV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the read packages combined v2 too many requests response
func (o *ReadPackagesCombinedV2TooManyRequests) Code() int {
	return 429
}

func (o *ReadPackagesCombinedV2TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/packages/v2][%d] readPackagesCombinedV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *ReadPackagesCombinedV2TooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/combined/packages/v2][%d] readPackagesCombinedV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *ReadPackagesCombinedV2TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReadPackagesCombinedV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReadPackagesCombinedV2InternalServerError creates a ReadPackagesCombinedV2InternalServerError with default headers values
func NewReadPackagesCombinedV2InternalServerError() *ReadPackagesCombinedV2InternalServerError {
	return &ReadPackagesCombinedV2InternalServerError{}
}

/*
ReadPackagesCombinedV2InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ReadPackagesCombinedV2InternalServerError struct {

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

// IsSuccess returns true when this read packages combined v2 internal server error response has a 2xx status code
func (o *ReadPackagesCombinedV2InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read packages combined v2 internal server error response has a 3xx status code
func (o *ReadPackagesCombinedV2InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read packages combined v2 internal server error response has a 4xx status code
func (o *ReadPackagesCombinedV2InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this read packages combined v2 internal server error response has a 5xx status code
func (o *ReadPackagesCombinedV2InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this read packages combined v2 internal server error response a status code equal to that given
func (o *ReadPackagesCombinedV2InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the read packages combined v2 internal server error response
func (o *ReadPackagesCombinedV2InternalServerError) Code() int {
	return 500
}

func (o *ReadPackagesCombinedV2InternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/packages/v2][%d] readPackagesCombinedV2InternalServerError  %+v", 500, o.Payload)
}

func (o *ReadPackagesCombinedV2InternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/combined/packages/v2][%d] readPackagesCombinedV2InternalServerError  %+v", 500, o.Payload)
}

func (o *ReadPackagesCombinedV2InternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *ReadPackagesCombinedV2InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
