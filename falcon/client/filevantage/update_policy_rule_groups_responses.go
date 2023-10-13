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

// UpdatePolicyRuleGroupsReader is a Reader for the UpdatePolicyRuleGroups structure.
type UpdatePolicyRuleGroupsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdatePolicyRuleGroupsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdatePolicyRuleGroupsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdatePolicyRuleGroupsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdatePolicyRuleGroupsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdatePolicyRuleGroupsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpdatePolicyRuleGroupsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /filevantage/entities/policies-rule-groups/v1] updatePolicyRuleGroups", response, response.Code())
	}
}

// NewUpdatePolicyRuleGroupsOK creates a UpdatePolicyRuleGroupsOK with default headers values
func NewUpdatePolicyRuleGroupsOK() *UpdatePolicyRuleGroupsOK {
	return &UpdatePolicyRuleGroupsOK{}
}

/* UpdatePolicyRuleGroupsOK describes a response with status code 200, with default header values.

Assigned rule groups have been updated.
*/
type UpdatePolicyRuleGroupsOK struct {

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

// IsSuccess returns true when this update policy rule groups o k response has a 2xx status code
func (o *UpdatePolicyRuleGroupsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update policy rule groups o k response has a 3xx status code
func (o *UpdatePolicyRuleGroupsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy rule groups o k response has a 4xx status code
func (o *UpdatePolicyRuleGroupsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update policy rule groups o k response has a 5xx status code
func (o *UpdatePolicyRuleGroupsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy rule groups o k response a status code equal to that given
func (o *UpdatePolicyRuleGroupsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update policy rule groups o k response
func (o *UpdatePolicyRuleGroupsOK) Code() int {
	return 200
}

func (o *UpdatePolicyRuleGroupsOK) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-rule-groups/v1][%d] updatePolicyRuleGroupsOK  %+v", 200, o.Payload)
}

func (o *UpdatePolicyRuleGroupsOK) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-rule-groups/v1][%d] updatePolicyRuleGroupsOK  %+v", 200, o.Payload)
}

func (o *UpdatePolicyRuleGroupsOK) GetPayload() *models.PoliciesResponse {
	return o.Payload
}

func (o *UpdatePolicyRuleGroupsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePolicyRuleGroupsBadRequest creates a UpdatePolicyRuleGroupsBadRequest with default headers values
func NewUpdatePolicyRuleGroupsBadRequest() *UpdatePolicyRuleGroupsBadRequest {
	return &UpdatePolicyRuleGroupsBadRequest{}
}

/* UpdatePolicyRuleGroupsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type UpdatePolicyRuleGroupsBadRequest struct {

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

// IsSuccess returns true when this update policy rule groups bad request response has a 2xx status code
func (o *UpdatePolicyRuleGroupsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy rule groups bad request response has a 3xx status code
func (o *UpdatePolicyRuleGroupsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy rule groups bad request response has a 4xx status code
func (o *UpdatePolicyRuleGroupsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy rule groups bad request response has a 5xx status code
func (o *UpdatePolicyRuleGroupsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy rule groups bad request response a status code equal to that given
func (o *UpdatePolicyRuleGroupsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update policy rule groups bad request response
func (o *UpdatePolicyRuleGroupsBadRequest) Code() int {
	return 400
}

func (o *UpdatePolicyRuleGroupsBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-rule-groups/v1][%d] updatePolicyRuleGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *UpdatePolicyRuleGroupsBadRequest) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-rule-groups/v1][%d] updatePolicyRuleGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *UpdatePolicyRuleGroupsBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdatePolicyRuleGroupsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePolicyRuleGroupsForbidden creates a UpdatePolicyRuleGroupsForbidden with default headers values
func NewUpdatePolicyRuleGroupsForbidden() *UpdatePolicyRuleGroupsForbidden {
	return &UpdatePolicyRuleGroupsForbidden{}
}

/* UpdatePolicyRuleGroupsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdatePolicyRuleGroupsForbidden struct {

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

// IsSuccess returns true when this update policy rule groups forbidden response has a 2xx status code
func (o *UpdatePolicyRuleGroupsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy rule groups forbidden response has a 3xx status code
func (o *UpdatePolicyRuleGroupsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy rule groups forbidden response has a 4xx status code
func (o *UpdatePolicyRuleGroupsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy rule groups forbidden response has a 5xx status code
func (o *UpdatePolicyRuleGroupsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy rule groups forbidden response a status code equal to that given
func (o *UpdatePolicyRuleGroupsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update policy rule groups forbidden response
func (o *UpdatePolicyRuleGroupsForbidden) Code() int {
	return 403
}

func (o *UpdatePolicyRuleGroupsForbidden) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-rule-groups/v1][%d] updatePolicyRuleGroupsForbidden  %+v", 403, o.Payload)
}

func (o *UpdatePolicyRuleGroupsForbidden) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-rule-groups/v1][%d] updatePolicyRuleGroupsForbidden  %+v", 403, o.Payload)
}

func (o *UpdatePolicyRuleGroupsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdatePolicyRuleGroupsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePolicyRuleGroupsTooManyRequests creates a UpdatePolicyRuleGroupsTooManyRequests with default headers values
func NewUpdatePolicyRuleGroupsTooManyRequests() *UpdatePolicyRuleGroupsTooManyRequests {
	return &UpdatePolicyRuleGroupsTooManyRequests{}
}

/* UpdatePolicyRuleGroupsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type UpdatePolicyRuleGroupsTooManyRequests struct {

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

// IsSuccess returns true when this update policy rule groups too many requests response has a 2xx status code
func (o *UpdatePolicyRuleGroupsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy rule groups too many requests response has a 3xx status code
func (o *UpdatePolicyRuleGroupsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy rule groups too many requests response has a 4xx status code
func (o *UpdatePolicyRuleGroupsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy rule groups too many requests response has a 5xx status code
func (o *UpdatePolicyRuleGroupsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy rule groups too many requests response a status code equal to that given
func (o *UpdatePolicyRuleGroupsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update policy rule groups too many requests response
func (o *UpdatePolicyRuleGroupsTooManyRequests) Code() int {
	return 429
}

func (o *UpdatePolicyRuleGroupsTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-rule-groups/v1][%d] updatePolicyRuleGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdatePolicyRuleGroupsTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-rule-groups/v1][%d] updatePolicyRuleGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdatePolicyRuleGroupsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdatePolicyRuleGroupsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdatePolicyRuleGroupsInternalServerError creates a UpdatePolicyRuleGroupsInternalServerError with default headers values
func NewUpdatePolicyRuleGroupsInternalServerError() *UpdatePolicyRuleGroupsInternalServerError {
	return &UpdatePolicyRuleGroupsInternalServerError{}
}

/* UpdatePolicyRuleGroupsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type UpdatePolicyRuleGroupsInternalServerError struct {

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

// IsSuccess returns true when this update policy rule groups internal server error response has a 2xx status code
func (o *UpdatePolicyRuleGroupsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy rule groups internal server error response has a 3xx status code
func (o *UpdatePolicyRuleGroupsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy rule groups internal server error response has a 4xx status code
func (o *UpdatePolicyRuleGroupsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this update policy rule groups internal server error response has a 5xx status code
func (o *UpdatePolicyRuleGroupsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this update policy rule groups internal server error response a status code equal to that given
func (o *UpdatePolicyRuleGroupsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the update policy rule groups internal server error response
func (o *UpdatePolicyRuleGroupsInternalServerError) Code() int {
	return 500
}

func (o *UpdatePolicyRuleGroupsInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-rule-groups/v1][%d] updatePolicyRuleGroupsInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdatePolicyRuleGroupsInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /filevantage/entities/policies-rule-groups/v1][%d] updatePolicyRuleGroupsInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdatePolicyRuleGroupsInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdatePolicyRuleGroupsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
