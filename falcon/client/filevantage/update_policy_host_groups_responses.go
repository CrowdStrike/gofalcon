// Code generated by go-swagger; DO NOT EDIT.

package filevantage

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

// UpdatePolicyHostGroupsReader is a Reader for the UpdatePolicyHostGroups structure.
type UpdatePolicyHostGroupsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdatePolicyHostGroupsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdatePolicyHostGroupsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdatePolicyHostGroupsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdatePolicyHostGroupsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdatePolicyHostGroupsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpdatePolicyHostGroupsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /filevantage/entities/policies-host-groups/v1] updatePolicyHostGroups", response, response.Code())
	}
}

// NewUpdatePolicyHostGroupsOK creates a UpdatePolicyHostGroupsOK with default headers values
func NewUpdatePolicyHostGroupsOK() *UpdatePolicyHostGroupsOK {
	return &UpdatePolicyHostGroupsOK{}
}

/*
UpdatePolicyHostGroupsOK describes a response with status code 200, with default header values.

Assigned hosts have been updated.
*/
type UpdatePolicyHostGroupsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.PoliciesResponse
}

// IsSuccess returns true when this update policy host groups o k response has a 2xx status code
func (o *UpdatePolicyHostGroupsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update policy host groups o k response has a 3xx status code
func (o *UpdatePolicyHostGroupsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy host groups o k response has a 4xx status code
func (o *UpdatePolicyHostGroupsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update policy host groups o k response has a 5xx status code
func (o *UpdatePolicyHostGroupsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy host groups o k response a status code equal to that given
func (o *UpdatePolicyHostGroupsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update policy host groups o k response
func (o *UpdatePolicyHostGroupsOK) Code() int {
	return 200
}

func (o *UpdatePolicyHostGroupsOK) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-host-groups/v1][%d] updatePolicyHostGroupsOK  %+v", 200, o.Payload)
}

func (o *UpdatePolicyHostGroupsOK) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-host-groups/v1][%d] updatePolicyHostGroupsOK  %+v", 200, o.Payload)
}

func (o *UpdatePolicyHostGroupsOK) GetPayload() *models.PoliciesResponse {
	return o.Payload
}

func (o *UpdatePolicyHostGroupsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.PoliciesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePolicyHostGroupsBadRequest creates a UpdatePolicyHostGroupsBadRequest with default headers values
func NewUpdatePolicyHostGroupsBadRequest() *UpdatePolicyHostGroupsBadRequest {
	return &UpdatePolicyHostGroupsBadRequest{}
}

/*
UpdatePolicyHostGroupsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type UpdatePolicyHostGroupsBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this update policy host groups bad request response has a 2xx status code
func (o *UpdatePolicyHostGroupsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy host groups bad request response has a 3xx status code
func (o *UpdatePolicyHostGroupsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy host groups bad request response has a 4xx status code
func (o *UpdatePolicyHostGroupsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy host groups bad request response has a 5xx status code
func (o *UpdatePolicyHostGroupsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy host groups bad request response a status code equal to that given
func (o *UpdatePolicyHostGroupsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update policy host groups bad request response
func (o *UpdatePolicyHostGroupsBadRequest) Code() int {
	return 400
}

func (o *UpdatePolicyHostGroupsBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-host-groups/v1][%d] updatePolicyHostGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *UpdatePolicyHostGroupsBadRequest) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-host-groups/v1][%d] updatePolicyHostGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *UpdatePolicyHostGroupsBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdatePolicyHostGroupsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePolicyHostGroupsForbidden creates a UpdatePolicyHostGroupsForbidden with default headers values
func NewUpdatePolicyHostGroupsForbidden() *UpdatePolicyHostGroupsForbidden {
	return &UpdatePolicyHostGroupsForbidden{}
}

/*
UpdatePolicyHostGroupsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdatePolicyHostGroupsForbidden struct {

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

// IsSuccess returns true when this update policy host groups forbidden response has a 2xx status code
func (o *UpdatePolicyHostGroupsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy host groups forbidden response has a 3xx status code
func (o *UpdatePolicyHostGroupsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy host groups forbidden response has a 4xx status code
func (o *UpdatePolicyHostGroupsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy host groups forbidden response has a 5xx status code
func (o *UpdatePolicyHostGroupsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy host groups forbidden response a status code equal to that given
func (o *UpdatePolicyHostGroupsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update policy host groups forbidden response
func (o *UpdatePolicyHostGroupsForbidden) Code() int {
	return 403
}

func (o *UpdatePolicyHostGroupsForbidden) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-host-groups/v1][%d] updatePolicyHostGroupsForbidden  %+v", 403, o.Payload)
}

func (o *UpdatePolicyHostGroupsForbidden) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-host-groups/v1][%d] updatePolicyHostGroupsForbidden  %+v", 403, o.Payload)
}

func (o *UpdatePolicyHostGroupsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdatePolicyHostGroupsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePolicyHostGroupsTooManyRequests creates a UpdatePolicyHostGroupsTooManyRequests with default headers values
func NewUpdatePolicyHostGroupsTooManyRequests() *UpdatePolicyHostGroupsTooManyRequests {
	return &UpdatePolicyHostGroupsTooManyRequests{}
}

/*
UpdatePolicyHostGroupsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type UpdatePolicyHostGroupsTooManyRequests struct {

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

// IsSuccess returns true when this update policy host groups too many requests response has a 2xx status code
func (o *UpdatePolicyHostGroupsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy host groups too many requests response has a 3xx status code
func (o *UpdatePolicyHostGroupsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy host groups too many requests response has a 4xx status code
func (o *UpdatePolicyHostGroupsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy host groups too many requests response has a 5xx status code
func (o *UpdatePolicyHostGroupsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy host groups too many requests response a status code equal to that given
func (o *UpdatePolicyHostGroupsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update policy host groups too many requests response
func (o *UpdatePolicyHostGroupsTooManyRequests) Code() int {
	return 429
}

func (o *UpdatePolicyHostGroupsTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-host-groups/v1][%d] updatePolicyHostGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdatePolicyHostGroupsTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-host-groups/v1][%d] updatePolicyHostGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdatePolicyHostGroupsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdatePolicyHostGroupsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePolicyHostGroupsInternalServerError creates a UpdatePolicyHostGroupsInternalServerError with default headers values
func NewUpdatePolicyHostGroupsInternalServerError() *UpdatePolicyHostGroupsInternalServerError {
	return &UpdatePolicyHostGroupsInternalServerError{}
}

/*
UpdatePolicyHostGroupsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type UpdatePolicyHostGroupsInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this update policy host groups internal server error response has a 2xx status code
func (o *UpdatePolicyHostGroupsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy host groups internal server error response has a 3xx status code
func (o *UpdatePolicyHostGroupsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy host groups internal server error response has a 4xx status code
func (o *UpdatePolicyHostGroupsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this update policy host groups internal server error response has a 5xx status code
func (o *UpdatePolicyHostGroupsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this update policy host groups internal server error response a status code equal to that given
func (o *UpdatePolicyHostGroupsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the update policy host groups internal server error response
func (o *UpdatePolicyHostGroupsInternalServerError) Code() int {
	return 500
}

func (o *UpdatePolicyHostGroupsInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-host-groups/v1][%d] updatePolicyHostGroupsInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdatePolicyHostGroupsInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-host-groups/v1][%d] updatePolicyHostGroupsInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdatePolicyHostGroupsInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdatePolicyHostGroupsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
