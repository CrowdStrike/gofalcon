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

// UpdatePoliciesReader is a Reader for the UpdatePolicies structure.
type UpdatePoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdatePoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdatePoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdatePoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdatePoliciesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdatePoliciesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdatePoliciesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpdatePoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /filevantage/entities/policies/v1] updatePolicies", response, response.Code())
	}
}

// NewUpdatePoliciesOK creates a UpdatePoliciesOK with default headers values
func NewUpdatePoliciesOK() *UpdatePoliciesOK {
	return &UpdatePoliciesOK{}
}

/* UpdatePoliciesOK describes a response with status code 200, with default header values.

Policy has been updated
*/
type UpdatePoliciesOK struct {

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

// IsSuccess returns true when this update policies o k response has a 2xx status code
func (o *UpdatePoliciesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update policies o k response has a 3xx status code
func (o *UpdatePoliciesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policies o k response has a 4xx status code
func (o *UpdatePoliciesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update policies o k response has a 5xx status code
func (o *UpdatePoliciesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update policies o k response a status code equal to that given
func (o *UpdatePoliciesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update policies o k response
func (o *UpdatePoliciesOK) Code() int {
	return 200
}

func (o *UpdatePoliciesOK) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesOK  %+v", 200, o.Payload)
}

func (o *UpdatePoliciesOK) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesOK  %+v", 200, o.Payload)
}

func (o *UpdatePoliciesOK) GetPayload() *models.PoliciesResponse {
	return o.Payload
}

func (o *UpdatePoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePoliciesBadRequest creates a UpdatePoliciesBadRequest with default headers values
func NewUpdatePoliciesBadRequest() *UpdatePoliciesBadRequest {
	return &UpdatePoliciesBadRequest{}
}

/* UpdatePoliciesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type UpdatePoliciesBadRequest struct {

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

// IsSuccess returns true when this update policies bad request response has a 2xx status code
func (o *UpdatePoliciesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policies bad request response has a 3xx status code
func (o *UpdatePoliciesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policies bad request response has a 4xx status code
func (o *UpdatePoliciesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policies bad request response has a 5xx status code
func (o *UpdatePoliciesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update policies bad request response a status code equal to that given
func (o *UpdatePoliciesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update policies bad request response
func (o *UpdatePoliciesBadRequest) Code() int {
	return 400
}

func (o *UpdatePoliciesBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *UpdatePoliciesBadRequest) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *UpdatePoliciesBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdatePoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePoliciesForbidden creates a UpdatePoliciesForbidden with default headers values
func NewUpdatePoliciesForbidden() *UpdatePoliciesForbidden {
	return &UpdatePoliciesForbidden{}
}

/* UpdatePoliciesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdatePoliciesForbidden struct {

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

// IsSuccess returns true when this update policies forbidden response has a 2xx status code
func (o *UpdatePoliciesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policies forbidden response has a 3xx status code
func (o *UpdatePoliciesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policies forbidden response has a 4xx status code
func (o *UpdatePoliciesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policies forbidden response has a 5xx status code
func (o *UpdatePoliciesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update policies forbidden response a status code equal to that given
func (o *UpdatePoliciesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update policies forbidden response
func (o *UpdatePoliciesForbidden) Code() int {
	return 403
}

func (o *UpdatePoliciesForbidden) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesForbidden  %+v", 403, o.Payload)
}

func (o *UpdatePoliciesForbidden) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesForbidden  %+v", 403, o.Payload)
}

func (o *UpdatePoliciesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdatePoliciesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePoliciesNotFound creates a UpdatePoliciesNotFound with default headers values
func NewUpdatePoliciesNotFound() *UpdatePoliciesNotFound {
	return &UpdatePoliciesNotFound{}
}

/* UpdatePoliciesNotFound describes a response with status code 404, with default header values.

Not Found
*/
type UpdatePoliciesNotFound struct {

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

// IsSuccess returns true when this update policies not found response has a 2xx status code
func (o *UpdatePoliciesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policies not found response has a 3xx status code
func (o *UpdatePoliciesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policies not found response has a 4xx status code
func (o *UpdatePoliciesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policies not found response has a 5xx status code
func (o *UpdatePoliciesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update policies not found response a status code equal to that given
func (o *UpdatePoliciesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update policies not found response
func (o *UpdatePoliciesNotFound) Code() int {
	return 404
}

func (o *UpdatePoliciesNotFound) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesNotFound  %+v", 404, o.Payload)
}

func (o *UpdatePoliciesNotFound) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesNotFound  %+v", 404, o.Payload)
}

func (o *UpdatePoliciesNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdatePoliciesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePoliciesTooManyRequests creates a UpdatePoliciesTooManyRequests with default headers values
func NewUpdatePoliciesTooManyRequests() *UpdatePoliciesTooManyRequests {
	return &UpdatePoliciesTooManyRequests{}
}

/* UpdatePoliciesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type UpdatePoliciesTooManyRequests struct {

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

// IsSuccess returns true when this update policies too many requests response has a 2xx status code
func (o *UpdatePoliciesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policies too many requests response has a 3xx status code
func (o *UpdatePoliciesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policies too many requests response has a 4xx status code
func (o *UpdatePoliciesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policies too many requests response has a 5xx status code
func (o *UpdatePoliciesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update policies too many requests response a status code equal to that given
func (o *UpdatePoliciesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update policies too many requests response
func (o *UpdatePoliciesTooManyRequests) Code() int {
	return 429
}

func (o *UpdatePoliciesTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdatePoliciesTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdatePoliciesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdatePoliciesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePoliciesInternalServerError creates a UpdatePoliciesInternalServerError with default headers values
func NewUpdatePoliciesInternalServerError() *UpdatePoliciesInternalServerError {
	return &UpdatePoliciesInternalServerError{}
}

/* UpdatePoliciesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type UpdatePoliciesInternalServerError struct {

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

// IsSuccess returns true when this update policies internal server error response has a 2xx status code
func (o *UpdatePoliciesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policies internal server error response has a 3xx status code
func (o *UpdatePoliciesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policies internal server error response has a 4xx status code
func (o *UpdatePoliciesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this update policies internal server error response has a 5xx status code
func (o *UpdatePoliciesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this update policies internal server error response a status code equal to that given
func (o *UpdatePoliciesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the update policies internal server error response
func (o *UpdatePoliciesInternalServerError) Code() int {
	return 500
}

func (o *UpdatePoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdatePoliciesInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies/v1][%d] updatePoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdatePoliciesInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdatePoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
