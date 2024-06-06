// Code generated by go-swagger; DO NOT EDIT.

package response_policies

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/aslape/gofalcon/falcon/models"
)

// UpdateRTResponsePoliciesReader is a Reader for the UpdateRTResponsePolicies structure.
type UpdateRTResponsePoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateRTResponsePoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateRTResponsePoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateRTResponsePoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateRTResponsePoliciesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateRTResponsePoliciesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateRTResponsePoliciesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpdateRTResponsePoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /policy/entities/response/v1] updateRTResponsePolicies", response, response.Code())
	}
}

// NewUpdateRTResponsePoliciesOK creates a UpdateRTResponsePoliciesOK with default headers values
func NewUpdateRTResponsePoliciesOK() *UpdateRTResponsePoliciesOK {
	return &UpdateRTResponsePoliciesOK{}
}

/*
UpdateRTResponsePoliciesOK describes a response with status code 200, with default header values.

OK
*/
type UpdateRTResponsePoliciesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RemoteResponseRespV1
}

// IsSuccess returns true when this update r t response policies o k response has a 2xx status code
func (o *UpdateRTResponsePoliciesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update r t response policies o k response has a 3xx status code
func (o *UpdateRTResponsePoliciesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update r t response policies o k response has a 4xx status code
func (o *UpdateRTResponsePoliciesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update r t response policies o k response has a 5xx status code
func (o *UpdateRTResponsePoliciesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update r t response policies o k response a status code equal to that given
func (o *UpdateRTResponsePoliciesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update r t response policies o k response
func (o *UpdateRTResponsePoliciesOK) Code() int {
	return 200
}

func (o *UpdateRTResponsePoliciesOK) Error() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesOK  %+v", 200, o.Payload)
}

func (o *UpdateRTResponsePoliciesOK) String() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesOK  %+v", 200, o.Payload)
}

func (o *UpdateRTResponsePoliciesOK) GetPayload() *models.RemoteResponseRespV1 {
	return o.Payload
}

func (o *UpdateRTResponsePoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RemoteResponseRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateRTResponsePoliciesBadRequest creates a UpdateRTResponsePoliciesBadRequest with default headers values
func NewUpdateRTResponsePoliciesBadRequest() *UpdateRTResponsePoliciesBadRequest {
	return &UpdateRTResponsePoliciesBadRequest{}
}

/*
UpdateRTResponsePoliciesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type UpdateRTResponsePoliciesBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RemoteResponseRespV1
}

// IsSuccess returns true when this update r t response policies bad request response has a 2xx status code
func (o *UpdateRTResponsePoliciesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update r t response policies bad request response has a 3xx status code
func (o *UpdateRTResponsePoliciesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update r t response policies bad request response has a 4xx status code
func (o *UpdateRTResponsePoliciesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update r t response policies bad request response has a 5xx status code
func (o *UpdateRTResponsePoliciesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update r t response policies bad request response a status code equal to that given
func (o *UpdateRTResponsePoliciesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update r t response policies bad request response
func (o *UpdateRTResponsePoliciesBadRequest) Code() int {
	return 400
}

func (o *UpdateRTResponsePoliciesBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateRTResponsePoliciesBadRequest) String() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateRTResponsePoliciesBadRequest) GetPayload() *models.RemoteResponseRespV1 {
	return o.Payload
}

func (o *UpdateRTResponsePoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RemoteResponseRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateRTResponsePoliciesForbidden creates a UpdateRTResponsePoliciesForbidden with default headers values
func NewUpdateRTResponsePoliciesForbidden() *UpdateRTResponsePoliciesForbidden {
	return &UpdateRTResponsePoliciesForbidden{}
}

/*
UpdateRTResponsePoliciesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateRTResponsePoliciesForbidden struct {

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

// IsSuccess returns true when this update r t response policies forbidden response has a 2xx status code
func (o *UpdateRTResponsePoliciesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update r t response policies forbidden response has a 3xx status code
func (o *UpdateRTResponsePoliciesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update r t response policies forbidden response has a 4xx status code
func (o *UpdateRTResponsePoliciesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update r t response policies forbidden response has a 5xx status code
func (o *UpdateRTResponsePoliciesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update r t response policies forbidden response a status code equal to that given
func (o *UpdateRTResponsePoliciesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update r t response policies forbidden response
func (o *UpdateRTResponsePoliciesForbidden) Code() int {
	return 403
}

func (o *UpdateRTResponsePoliciesForbidden) Error() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesForbidden  %+v", 403, o.Payload)
}

func (o *UpdateRTResponsePoliciesForbidden) String() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesForbidden  %+v", 403, o.Payload)
}

func (o *UpdateRTResponsePoliciesForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *UpdateRTResponsePoliciesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateRTResponsePoliciesNotFound creates a UpdateRTResponsePoliciesNotFound with default headers values
func NewUpdateRTResponsePoliciesNotFound() *UpdateRTResponsePoliciesNotFound {
	return &UpdateRTResponsePoliciesNotFound{}
}

/*
UpdateRTResponsePoliciesNotFound describes a response with status code 404, with default header values.

Not Found
*/
type UpdateRTResponsePoliciesNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RemoteResponseRespV1
}

// IsSuccess returns true when this update r t response policies not found response has a 2xx status code
func (o *UpdateRTResponsePoliciesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update r t response policies not found response has a 3xx status code
func (o *UpdateRTResponsePoliciesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update r t response policies not found response has a 4xx status code
func (o *UpdateRTResponsePoliciesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update r t response policies not found response has a 5xx status code
func (o *UpdateRTResponsePoliciesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update r t response policies not found response a status code equal to that given
func (o *UpdateRTResponsePoliciesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update r t response policies not found response
func (o *UpdateRTResponsePoliciesNotFound) Code() int {
	return 404
}

func (o *UpdateRTResponsePoliciesNotFound) Error() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesNotFound  %+v", 404, o.Payload)
}

func (o *UpdateRTResponsePoliciesNotFound) String() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesNotFound  %+v", 404, o.Payload)
}

func (o *UpdateRTResponsePoliciesNotFound) GetPayload() *models.RemoteResponseRespV1 {
	return o.Payload
}

func (o *UpdateRTResponsePoliciesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RemoteResponseRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateRTResponsePoliciesTooManyRequests creates a UpdateRTResponsePoliciesTooManyRequests with default headers values
func NewUpdateRTResponsePoliciesTooManyRequests() *UpdateRTResponsePoliciesTooManyRequests {
	return &UpdateRTResponsePoliciesTooManyRequests{}
}

/*
UpdateRTResponsePoliciesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type UpdateRTResponsePoliciesTooManyRequests struct {

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

// IsSuccess returns true when this update r t response policies too many requests response has a 2xx status code
func (o *UpdateRTResponsePoliciesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update r t response policies too many requests response has a 3xx status code
func (o *UpdateRTResponsePoliciesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update r t response policies too many requests response has a 4xx status code
func (o *UpdateRTResponsePoliciesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update r t response policies too many requests response has a 5xx status code
func (o *UpdateRTResponsePoliciesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update r t response policies too many requests response a status code equal to that given
func (o *UpdateRTResponsePoliciesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update r t response policies too many requests response
func (o *UpdateRTResponsePoliciesTooManyRequests) Code() int {
	return 429
}

func (o *UpdateRTResponsePoliciesTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateRTResponsePoliciesTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateRTResponsePoliciesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdateRTResponsePoliciesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateRTResponsePoliciesInternalServerError creates a UpdateRTResponsePoliciesInternalServerError with default headers values
func NewUpdateRTResponsePoliciesInternalServerError() *UpdateRTResponsePoliciesInternalServerError {
	return &UpdateRTResponsePoliciesInternalServerError{}
}

/*
UpdateRTResponsePoliciesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type UpdateRTResponsePoliciesInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RemoteResponseRespV1
}

// IsSuccess returns true when this update r t response policies internal server error response has a 2xx status code
func (o *UpdateRTResponsePoliciesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update r t response policies internal server error response has a 3xx status code
func (o *UpdateRTResponsePoliciesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update r t response policies internal server error response has a 4xx status code
func (o *UpdateRTResponsePoliciesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this update r t response policies internal server error response has a 5xx status code
func (o *UpdateRTResponsePoliciesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this update r t response policies internal server error response a status code equal to that given
func (o *UpdateRTResponsePoliciesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the update r t response policies internal server error response
func (o *UpdateRTResponsePoliciesInternalServerError) Code() int {
	return 500
}

func (o *UpdateRTResponsePoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateRTResponsePoliciesInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /policy/entities/response/v1][%d] updateRTResponsePoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateRTResponsePoliciesInternalServerError) GetPayload() *models.RemoteResponseRespV1 {
	return o.Payload
}

func (o *UpdateRTResponsePoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RemoteResponseRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
