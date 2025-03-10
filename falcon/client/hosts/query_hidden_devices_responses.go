// Code generated by go-swagger; DO NOT EDIT.

package hosts

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

// QueryHiddenDevicesReader is a Reader for the QueryHiddenDevices structure.
type QueryHiddenDevicesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryHiddenDevicesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryHiddenDevicesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewQueryHiddenDevicesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryHiddenDevicesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryHiddenDevicesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /devices/queries/devices-hidden/v1] QueryHiddenDevices", response, response.Code())
	}
}

// NewQueryHiddenDevicesOK creates a QueryHiddenDevicesOK with default headers values
func NewQueryHiddenDevicesOK() *QueryHiddenDevicesOK {
	return &QueryHiddenDevicesOK{}
}

/*
QueryHiddenDevicesOK describes a response with status code 200, with default header values.

OK
*/
type QueryHiddenDevicesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaQueryResponse
}

// IsSuccess returns true when this query hidden devices o k response has a 2xx status code
func (o *QueryHiddenDevicesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query hidden devices o k response has a 3xx status code
func (o *QueryHiddenDevicesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query hidden devices o k response has a 4xx status code
func (o *QueryHiddenDevicesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query hidden devices o k response has a 5xx status code
func (o *QueryHiddenDevicesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query hidden devices o k response a status code equal to that given
func (o *QueryHiddenDevicesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query hidden devices o k response
func (o *QueryHiddenDevicesOK) Code() int {
	return 200
}

func (o *QueryHiddenDevicesOK) Error() string {
	return fmt.Sprintf("[GET /devices/queries/devices-hidden/v1][%d] queryHiddenDevicesOK  %+v", 200, o.Payload)
}

func (o *QueryHiddenDevicesOK) String() string {
	return fmt.Sprintf("[GET /devices/queries/devices-hidden/v1][%d] queryHiddenDevicesOK  %+v", 200, o.Payload)
}

func (o *QueryHiddenDevicesOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryHiddenDevicesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryHiddenDevicesForbidden creates a QueryHiddenDevicesForbidden with default headers values
func NewQueryHiddenDevicesForbidden() *QueryHiddenDevicesForbidden {
	return &QueryHiddenDevicesForbidden{}
}

/*
QueryHiddenDevicesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryHiddenDevicesForbidden struct {

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

// IsSuccess returns true when this query hidden devices forbidden response has a 2xx status code
func (o *QueryHiddenDevicesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query hidden devices forbidden response has a 3xx status code
func (o *QueryHiddenDevicesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query hidden devices forbidden response has a 4xx status code
func (o *QueryHiddenDevicesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query hidden devices forbidden response has a 5xx status code
func (o *QueryHiddenDevicesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query hidden devices forbidden response a status code equal to that given
func (o *QueryHiddenDevicesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query hidden devices forbidden response
func (o *QueryHiddenDevicesForbidden) Code() int {
	return 403
}

func (o *QueryHiddenDevicesForbidden) Error() string {
	return fmt.Sprintf("[GET /devices/queries/devices-hidden/v1][%d] queryHiddenDevicesForbidden  %+v", 403, o.Payload)
}

func (o *QueryHiddenDevicesForbidden) String() string {
	return fmt.Sprintf("[GET /devices/queries/devices-hidden/v1][%d] queryHiddenDevicesForbidden  %+v", 403, o.Payload)
}

func (o *QueryHiddenDevicesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryHiddenDevicesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryHiddenDevicesTooManyRequests creates a QueryHiddenDevicesTooManyRequests with default headers values
func NewQueryHiddenDevicesTooManyRequests() *QueryHiddenDevicesTooManyRequests {
	return &QueryHiddenDevicesTooManyRequests{}
}

/*
QueryHiddenDevicesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryHiddenDevicesTooManyRequests struct {

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

// IsSuccess returns true when this query hidden devices too many requests response has a 2xx status code
func (o *QueryHiddenDevicesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query hidden devices too many requests response has a 3xx status code
func (o *QueryHiddenDevicesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query hidden devices too many requests response has a 4xx status code
func (o *QueryHiddenDevicesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query hidden devices too many requests response has a 5xx status code
func (o *QueryHiddenDevicesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query hidden devices too many requests response a status code equal to that given
func (o *QueryHiddenDevicesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query hidden devices too many requests response
func (o *QueryHiddenDevicesTooManyRequests) Code() int {
	return 429
}

func (o *QueryHiddenDevicesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /devices/queries/devices-hidden/v1][%d] queryHiddenDevicesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryHiddenDevicesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /devices/queries/devices-hidden/v1][%d] queryHiddenDevicesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryHiddenDevicesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryHiddenDevicesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryHiddenDevicesInternalServerError creates a QueryHiddenDevicesInternalServerError with default headers values
func NewQueryHiddenDevicesInternalServerError() *QueryHiddenDevicesInternalServerError {
	return &QueryHiddenDevicesInternalServerError{}
}

/*
QueryHiddenDevicesInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type QueryHiddenDevicesInternalServerError struct {

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

// IsSuccess returns true when this query hidden devices internal server error response has a 2xx status code
func (o *QueryHiddenDevicesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query hidden devices internal server error response has a 3xx status code
func (o *QueryHiddenDevicesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query hidden devices internal server error response has a 4xx status code
func (o *QueryHiddenDevicesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query hidden devices internal server error response has a 5xx status code
func (o *QueryHiddenDevicesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query hidden devices internal server error response a status code equal to that given
func (o *QueryHiddenDevicesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query hidden devices internal server error response
func (o *QueryHiddenDevicesInternalServerError) Code() int {
	return 500
}

func (o *QueryHiddenDevicesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /devices/queries/devices-hidden/v1][%d] queryHiddenDevicesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryHiddenDevicesInternalServerError) String() string {
	return fmt.Sprintf("[GET /devices/queries/devices-hidden/v1][%d] queryHiddenDevicesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryHiddenDevicesInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryHiddenDevicesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
