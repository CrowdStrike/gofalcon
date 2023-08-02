// Code generated by go-swagger; DO NOT EDIT.

package device_control_policies

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

// CreateDeviceControlPoliciesReader is a Reader for the CreateDeviceControlPolicies structure.
type CreateDeviceControlPoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateDeviceControlPoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateDeviceControlPoliciesCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateDeviceControlPoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateDeviceControlPoliciesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateDeviceControlPoliciesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateDeviceControlPoliciesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateDeviceControlPoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /policy/entities/device-control/v1] createDeviceControlPolicies", response, response.Code())
	}
}

// NewCreateDeviceControlPoliciesCreated creates a CreateDeviceControlPoliciesCreated with default headers values
func NewCreateDeviceControlPoliciesCreated() *CreateDeviceControlPoliciesCreated {
	return &CreateDeviceControlPoliciesCreated{}
}

/*
CreateDeviceControlPoliciesCreated describes a response with status code 201, with default header values.

Created
*/
type CreateDeviceControlPoliciesCreated struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DeviceControlRespV2
}

// IsSuccess returns true when this create device control policies created response has a 2xx status code
func (o *CreateDeviceControlPoliciesCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create device control policies created response has a 3xx status code
func (o *CreateDeviceControlPoliciesCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create device control policies created response has a 4xx status code
func (o *CreateDeviceControlPoliciesCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create device control policies created response has a 5xx status code
func (o *CreateDeviceControlPoliciesCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create device control policies created response a status code equal to that given
func (o *CreateDeviceControlPoliciesCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create device control policies created response
func (o *CreateDeviceControlPoliciesCreated) Code() int {
	return 201
}

func (o *CreateDeviceControlPoliciesCreated) Error() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesCreated  %+v", 201, o.Payload)
}

func (o *CreateDeviceControlPoliciesCreated) String() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesCreated  %+v", 201, o.Payload)
}

func (o *CreateDeviceControlPoliciesCreated) GetPayload() *models.DeviceControlRespV2 {
	return o.Payload
}

func (o *CreateDeviceControlPoliciesCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DeviceControlRespV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDeviceControlPoliciesBadRequest creates a CreateDeviceControlPoliciesBadRequest with default headers values
func NewCreateDeviceControlPoliciesBadRequest() *CreateDeviceControlPoliciesBadRequest {
	return &CreateDeviceControlPoliciesBadRequest{}
}

/*
CreateDeviceControlPoliciesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CreateDeviceControlPoliciesBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DeviceControlRespV2
}

// IsSuccess returns true when this create device control policies bad request response has a 2xx status code
func (o *CreateDeviceControlPoliciesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create device control policies bad request response has a 3xx status code
func (o *CreateDeviceControlPoliciesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create device control policies bad request response has a 4xx status code
func (o *CreateDeviceControlPoliciesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create device control policies bad request response has a 5xx status code
func (o *CreateDeviceControlPoliciesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create device control policies bad request response a status code equal to that given
func (o *CreateDeviceControlPoliciesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create device control policies bad request response
func (o *CreateDeviceControlPoliciesBadRequest) Code() int {
	return 400
}

func (o *CreateDeviceControlPoliciesBadRequest) Error() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *CreateDeviceControlPoliciesBadRequest) String() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *CreateDeviceControlPoliciesBadRequest) GetPayload() *models.DeviceControlRespV2 {
	return o.Payload
}

func (o *CreateDeviceControlPoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DeviceControlRespV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDeviceControlPoliciesForbidden creates a CreateDeviceControlPoliciesForbidden with default headers values
func NewCreateDeviceControlPoliciesForbidden() *CreateDeviceControlPoliciesForbidden {
	return &CreateDeviceControlPoliciesForbidden{}
}

/*
CreateDeviceControlPoliciesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateDeviceControlPoliciesForbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this create device control policies forbidden response has a 2xx status code
func (o *CreateDeviceControlPoliciesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create device control policies forbidden response has a 3xx status code
func (o *CreateDeviceControlPoliciesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create device control policies forbidden response has a 4xx status code
func (o *CreateDeviceControlPoliciesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create device control policies forbidden response has a 5xx status code
func (o *CreateDeviceControlPoliciesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create device control policies forbidden response a status code equal to that given
func (o *CreateDeviceControlPoliciesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create device control policies forbidden response
func (o *CreateDeviceControlPoliciesForbidden) Code() int {
	return 403
}

func (o *CreateDeviceControlPoliciesForbidden) Error() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesForbidden  %+v", 403, o.Payload)
}

func (o *CreateDeviceControlPoliciesForbidden) String() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesForbidden  %+v", 403, o.Payload)
}

func (o *CreateDeviceControlPoliciesForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *CreateDeviceControlPoliciesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDeviceControlPoliciesNotFound creates a CreateDeviceControlPoliciesNotFound with default headers values
func NewCreateDeviceControlPoliciesNotFound() *CreateDeviceControlPoliciesNotFound {
	return &CreateDeviceControlPoliciesNotFound{}
}

/*
CreateDeviceControlPoliciesNotFound describes a response with status code 404, with default header values.

Not Found
*/
type CreateDeviceControlPoliciesNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DeviceControlRespV1
}

// IsSuccess returns true when this create device control policies not found response has a 2xx status code
func (o *CreateDeviceControlPoliciesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create device control policies not found response has a 3xx status code
func (o *CreateDeviceControlPoliciesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create device control policies not found response has a 4xx status code
func (o *CreateDeviceControlPoliciesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create device control policies not found response has a 5xx status code
func (o *CreateDeviceControlPoliciesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create device control policies not found response a status code equal to that given
func (o *CreateDeviceControlPoliciesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create device control policies not found response
func (o *CreateDeviceControlPoliciesNotFound) Code() int {
	return 404
}

func (o *CreateDeviceControlPoliciesNotFound) Error() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesNotFound  %+v", 404, o.Payload)
}

func (o *CreateDeviceControlPoliciesNotFound) String() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesNotFound  %+v", 404, o.Payload)
}

func (o *CreateDeviceControlPoliciesNotFound) GetPayload() *models.DeviceControlRespV1 {
	return o.Payload
}

func (o *CreateDeviceControlPoliciesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DeviceControlRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDeviceControlPoliciesTooManyRequests creates a CreateDeviceControlPoliciesTooManyRequests with default headers values
func NewCreateDeviceControlPoliciesTooManyRequests() *CreateDeviceControlPoliciesTooManyRequests {
	return &CreateDeviceControlPoliciesTooManyRequests{}
}

/*
CreateDeviceControlPoliciesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateDeviceControlPoliciesTooManyRequests struct {

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

// IsSuccess returns true when this create device control policies too many requests response has a 2xx status code
func (o *CreateDeviceControlPoliciesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create device control policies too many requests response has a 3xx status code
func (o *CreateDeviceControlPoliciesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create device control policies too many requests response has a 4xx status code
func (o *CreateDeviceControlPoliciesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create device control policies too many requests response has a 5xx status code
func (o *CreateDeviceControlPoliciesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create device control policies too many requests response a status code equal to that given
func (o *CreateDeviceControlPoliciesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create device control policies too many requests response
func (o *CreateDeviceControlPoliciesTooManyRequests) Code() int {
	return 429
}

func (o *CreateDeviceControlPoliciesTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateDeviceControlPoliciesTooManyRequests) String() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateDeviceControlPoliciesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateDeviceControlPoliciesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateDeviceControlPoliciesInternalServerError creates a CreateDeviceControlPoliciesInternalServerError with default headers values
func NewCreateDeviceControlPoliciesInternalServerError() *CreateDeviceControlPoliciesInternalServerError {
	return &CreateDeviceControlPoliciesInternalServerError{}
}

/*
CreateDeviceControlPoliciesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateDeviceControlPoliciesInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DeviceControlRespV2
}

// IsSuccess returns true when this create device control policies internal server error response has a 2xx status code
func (o *CreateDeviceControlPoliciesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create device control policies internal server error response has a 3xx status code
func (o *CreateDeviceControlPoliciesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create device control policies internal server error response has a 4xx status code
func (o *CreateDeviceControlPoliciesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create device control policies internal server error response has a 5xx status code
func (o *CreateDeviceControlPoliciesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create device control policies internal server error response a status code equal to that given
func (o *CreateDeviceControlPoliciesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create device control policies internal server error response
func (o *CreateDeviceControlPoliciesInternalServerError) Code() int {
	return 500
}

func (o *CreateDeviceControlPoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateDeviceControlPoliciesInternalServerError) String() string {
	return fmt.Sprintf("[POST /policy/entities/device-control/v1][%d] createDeviceControlPoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateDeviceControlPoliciesInternalServerError) GetPayload() *models.DeviceControlRespV2 {
	return o.Payload
}

func (o *CreateDeviceControlPoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DeviceControlRespV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
