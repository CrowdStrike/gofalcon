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

// UpdateDeviceTagsReader is a Reader for the UpdateDeviceTags structure.
type UpdateDeviceTagsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateDeviceTagsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateDeviceTagsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 202:
		result := NewUpdateDeviceTagsAccepted()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateDeviceTagsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateDeviceTagsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateDeviceTagsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpdateDeviceTagsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /devices/entities/devices/tags/v1] UpdateDeviceTags", response, response.Code())
	}
}

// NewUpdateDeviceTagsOK creates a UpdateDeviceTagsOK with default headers values
func NewUpdateDeviceTagsOK() *UpdateDeviceTagsOK {
	return &UpdateDeviceTagsOK{}
}

/*
UpdateDeviceTagsOK describes a response with status code 200, with default header values.

OK
*/
type UpdateDeviceTagsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DeviceapiUpdateDeviceTagsSwaggerV1
}

// IsSuccess returns true when this update device tags o k response has a 2xx status code
func (o *UpdateDeviceTagsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update device tags o k response has a 3xx status code
func (o *UpdateDeviceTagsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update device tags o k response has a 4xx status code
func (o *UpdateDeviceTagsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update device tags o k response has a 5xx status code
func (o *UpdateDeviceTagsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update device tags o k response a status code equal to that given
func (o *UpdateDeviceTagsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update device tags o k response
func (o *UpdateDeviceTagsOK) Code() int {
	return 200
}

func (o *UpdateDeviceTagsOK) Error() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsOK  %+v", 200, o.Payload)
}

func (o *UpdateDeviceTagsOK) String() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsOK  %+v", 200, o.Payload)
}

func (o *UpdateDeviceTagsOK) GetPayload() *models.DeviceapiUpdateDeviceTagsSwaggerV1 {
	return o.Payload
}

func (o *UpdateDeviceTagsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DeviceapiUpdateDeviceTagsSwaggerV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateDeviceTagsAccepted creates a UpdateDeviceTagsAccepted with default headers values
func NewUpdateDeviceTagsAccepted() *UpdateDeviceTagsAccepted {
	return &UpdateDeviceTagsAccepted{}
}

/*
UpdateDeviceTagsAccepted describes a response with status code 202, with default header values.

OK
*/
type UpdateDeviceTagsAccepted struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DeviceapiUpdateDeviceTagsSwaggerV1
}

// IsSuccess returns true when this update device tags accepted response has a 2xx status code
func (o *UpdateDeviceTagsAccepted) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update device tags accepted response has a 3xx status code
func (o *UpdateDeviceTagsAccepted) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update device tags accepted response has a 4xx status code
func (o *UpdateDeviceTagsAccepted) IsClientError() bool {
	return false
}

// IsServerError returns true when this update device tags accepted response has a 5xx status code
func (o *UpdateDeviceTagsAccepted) IsServerError() bool {
	return false
}

// IsCode returns true when this update device tags accepted response a status code equal to that given
func (o *UpdateDeviceTagsAccepted) IsCode(code int) bool {
	return code == 202
}

// Code gets the status code for the update device tags accepted response
func (o *UpdateDeviceTagsAccepted) Code() int {
	return 202
}

func (o *UpdateDeviceTagsAccepted) Error() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsAccepted  %+v", 202, o.Payload)
}

func (o *UpdateDeviceTagsAccepted) String() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsAccepted  %+v", 202, o.Payload)
}

func (o *UpdateDeviceTagsAccepted) GetPayload() *models.DeviceapiUpdateDeviceTagsSwaggerV1 {
	return o.Payload
}

func (o *UpdateDeviceTagsAccepted) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DeviceapiUpdateDeviceTagsSwaggerV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateDeviceTagsBadRequest creates a UpdateDeviceTagsBadRequest with default headers values
func NewUpdateDeviceTagsBadRequest() *UpdateDeviceTagsBadRequest {
	return &UpdateDeviceTagsBadRequest{}
}

/*
UpdateDeviceTagsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type UpdateDeviceTagsBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaReplyAffectedEntities
}

// IsSuccess returns true when this update device tags bad request response has a 2xx status code
func (o *UpdateDeviceTagsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update device tags bad request response has a 3xx status code
func (o *UpdateDeviceTagsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update device tags bad request response has a 4xx status code
func (o *UpdateDeviceTagsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update device tags bad request response has a 5xx status code
func (o *UpdateDeviceTagsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update device tags bad request response a status code equal to that given
func (o *UpdateDeviceTagsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update device tags bad request response
func (o *UpdateDeviceTagsBadRequest) Code() int {
	return 400
}

func (o *UpdateDeviceTagsBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateDeviceTagsBadRequest) String() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateDeviceTagsBadRequest) GetPayload() *models.MsaReplyAffectedEntities {
	return o.Payload
}

func (o *UpdateDeviceTagsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaReplyAffectedEntities)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateDeviceTagsForbidden creates a UpdateDeviceTagsForbidden with default headers values
func NewUpdateDeviceTagsForbidden() *UpdateDeviceTagsForbidden {
	return &UpdateDeviceTagsForbidden{}
}

/*
UpdateDeviceTagsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateDeviceTagsForbidden struct {

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

// IsSuccess returns true when this update device tags forbidden response has a 2xx status code
func (o *UpdateDeviceTagsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update device tags forbidden response has a 3xx status code
func (o *UpdateDeviceTagsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update device tags forbidden response has a 4xx status code
func (o *UpdateDeviceTagsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update device tags forbidden response has a 5xx status code
func (o *UpdateDeviceTagsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update device tags forbidden response a status code equal to that given
func (o *UpdateDeviceTagsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update device tags forbidden response
func (o *UpdateDeviceTagsForbidden) Code() int {
	return 403
}

func (o *UpdateDeviceTagsForbidden) Error() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsForbidden  %+v", 403, o.Payload)
}

func (o *UpdateDeviceTagsForbidden) String() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsForbidden  %+v", 403, o.Payload)
}

func (o *UpdateDeviceTagsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdateDeviceTagsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateDeviceTagsTooManyRequests creates a UpdateDeviceTagsTooManyRequests with default headers values
func NewUpdateDeviceTagsTooManyRequests() *UpdateDeviceTagsTooManyRequests {
	return &UpdateDeviceTagsTooManyRequests{}
}

/*
UpdateDeviceTagsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type UpdateDeviceTagsTooManyRequests struct {

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

// IsSuccess returns true when this update device tags too many requests response has a 2xx status code
func (o *UpdateDeviceTagsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update device tags too many requests response has a 3xx status code
func (o *UpdateDeviceTagsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update device tags too many requests response has a 4xx status code
func (o *UpdateDeviceTagsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update device tags too many requests response has a 5xx status code
func (o *UpdateDeviceTagsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update device tags too many requests response a status code equal to that given
func (o *UpdateDeviceTagsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update device tags too many requests response
func (o *UpdateDeviceTagsTooManyRequests) Code() int {
	return 429
}

func (o *UpdateDeviceTagsTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateDeviceTagsTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateDeviceTagsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdateDeviceTagsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateDeviceTagsInternalServerError creates a UpdateDeviceTagsInternalServerError with default headers values
func NewUpdateDeviceTagsInternalServerError() *UpdateDeviceTagsInternalServerError {
	return &UpdateDeviceTagsInternalServerError{}
}

/*
UpdateDeviceTagsInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type UpdateDeviceTagsInternalServerError struct {

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

// IsSuccess returns true when this update device tags internal server error response has a 2xx status code
func (o *UpdateDeviceTagsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update device tags internal server error response has a 3xx status code
func (o *UpdateDeviceTagsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update device tags internal server error response has a 4xx status code
func (o *UpdateDeviceTagsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this update device tags internal server error response has a 5xx status code
func (o *UpdateDeviceTagsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this update device tags internal server error response a status code equal to that given
func (o *UpdateDeviceTagsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the update device tags internal server error response
func (o *UpdateDeviceTagsInternalServerError) Code() int {
	return 500
}

func (o *UpdateDeviceTagsInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateDeviceTagsInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /devices/entities/devices/tags/v1][%d] updateDeviceTagsInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateDeviceTagsInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdateDeviceTagsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
