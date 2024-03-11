// Code generated by go-swagger; DO NOT EDIT.

package container_alerts

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

// ReadContainerAlertsCountReader is a Reader for the ReadContainerAlertsCount structure.
type ReadContainerAlertsCountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReadContainerAlertsCountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewReadContainerAlertsCountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewReadContainerAlertsCountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewReadContainerAlertsCountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewReadContainerAlertsCountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/aggregates/container-alerts/count/v1] ReadContainerAlertsCount", response, response.Code())
	}
}

// NewReadContainerAlertsCountOK creates a ReadContainerAlertsCountOK with default headers values
func NewReadContainerAlertsCountOK() *ReadContainerAlertsCountOK {
	return &ReadContainerAlertsCountOK{}
}

/*
ReadContainerAlertsCountOK describes a response with status code 200, with default header values.

OK
*/
type ReadContainerAlertsCountOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.AlertsContainerAlertsCountValue
}

// IsSuccess returns true when this read container alerts count o k response has a 2xx status code
func (o *ReadContainerAlertsCountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this read container alerts count o k response has a 3xx status code
func (o *ReadContainerAlertsCountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read container alerts count o k response has a 4xx status code
func (o *ReadContainerAlertsCountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this read container alerts count o k response has a 5xx status code
func (o *ReadContainerAlertsCountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this read container alerts count o k response a status code equal to that given
func (o *ReadContainerAlertsCountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the read container alerts count o k response
func (o *ReadContainerAlertsCountOK) Code() int {
	return 200
}

func (o *ReadContainerAlertsCountOK) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/container-alerts/count/v1][%d] readContainerAlertsCountOK  %+v", 200, o.Payload)
}

func (o *ReadContainerAlertsCountOK) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/container-alerts/count/v1][%d] readContainerAlertsCountOK  %+v", 200, o.Payload)
}

func (o *ReadContainerAlertsCountOK) GetPayload() *models.AlertsContainerAlertsCountValue {
	return o.Payload
}

func (o *ReadContainerAlertsCountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.AlertsContainerAlertsCountValue)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewReadContainerAlertsCountForbidden creates a ReadContainerAlertsCountForbidden with default headers values
func NewReadContainerAlertsCountForbidden() *ReadContainerAlertsCountForbidden {
	return &ReadContainerAlertsCountForbidden{}
}

/*
ReadContainerAlertsCountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ReadContainerAlertsCountForbidden struct {

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

// IsSuccess returns true when this read container alerts count forbidden response has a 2xx status code
func (o *ReadContainerAlertsCountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read container alerts count forbidden response has a 3xx status code
func (o *ReadContainerAlertsCountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read container alerts count forbidden response has a 4xx status code
func (o *ReadContainerAlertsCountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this read container alerts count forbidden response has a 5xx status code
func (o *ReadContainerAlertsCountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this read container alerts count forbidden response a status code equal to that given
func (o *ReadContainerAlertsCountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the read container alerts count forbidden response
func (o *ReadContainerAlertsCountForbidden) Code() int {
	return 403
}

func (o *ReadContainerAlertsCountForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/container-alerts/count/v1][%d] readContainerAlertsCountForbidden  %+v", 403, o.Payload)
}

func (o *ReadContainerAlertsCountForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/container-alerts/count/v1][%d] readContainerAlertsCountForbidden  %+v", 403, o.Payload)
}

func (o *ReadContainerAlertsCountForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReadContainerAlertsCountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReadContainerAlertsCountTooManyRequests creates a ReadContainerAlertsCountTooManyRequests with default headers values
func NewReadContainerAlertsCountTooManyRequests() *ReadContainerAlertsCountTooManyRequests {
	return &ReadContainerAlertsCountTooManyRequests{}
}

/*
ReadContainerAlertsCountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ReadContainerAlertsCountTooManyRequests struct {

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

// IsSuccess returns true when this read container alerts count too many requests response has a 2xx status code
func (o *ReadContainerAlertsCountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read container alerts count too many requests response has a 3xx status code
func (o *ReadContainerAlertsCountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read container alerts count too many requests response has a 4xx status code
func (o *ReadContainerAlertsCountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this read container alerts count too many requests response has a 5xx status code
func (o *ReadContainerAlertsCountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this read container alerts count too many requests response a status code equal to that given
func (o *ReadContainerAlertsCountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the read container alerts count too many requests response
func (o *ReadContainerAlertsCountTooManyRequests) Code() int {
	return 429
}

func (o *ReadContainerAlertsCountTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/container-alerts/count/v1][%d] readContainerAlertsCountTooManyRequests  %+v", 429, o.Payload)
}

func (o *ReadContainerAlertsCountTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/container-alerts/count/v1][%d] readContainerAlertsCountTooManyRequests  %+v", 429, o.Payload)
}

func (o *ReadContainerAlertsCountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReadContainerAlertsCountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReadContainerAlertsCountInternalServerError creates a ReadContainerAlertsCountInternalServerError with default headers values
func NewReadContainerAlertsCountInternalServerError() *ReadContainerAlertsCountInternalServerError {
	return &ReadContainerAlertsCountInternalServerError{}
}

/*
ReadContainerAlertsCountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ReadContainerAlertsCountInternalServerError struct {

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

// IsSuccess returns true when this read container alerts count internal server error response has a 2xx status code
func (o *ReadContainerAlertsCountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read container alerts count internal server error response has a 3xx status code
func (o *ReadContainerAlertsCountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read container alerts count internal server error response has a 4xx status code
func (o *ReadContainerAlertsCountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this read container alerts count internal server error response has a 5xx status code
func (o *ReadContainerAlertsCountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this read container alerts count internal server error response a status code equal to that given
func (o *ReadContainerAlertsCountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the read container alerts count internal server error response
func (o *ReadContainerAlertsCountInternalServerError) Code() int {
	return 500
}

func (o *ReadContainerAlertsCountInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/container-alerts/count/v1][%d] readContainerAlertsCountInternalServerError  %+v", 500, o.Payload)
}

func (o *ReadContainerAlertsCountInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/container-alerts/count/v1][%d] readContainerAlertsCountInternalServerError  %+v", 500, o.Payload)
}

func (o *ReadContainerAlertsCountInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *ReadContainerAlertsCountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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