// Code generated by go-swagger; DO NOT EDIT.

package mssp

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

// DeleteUserGroupMembersReader is a Reader for the DeleteUserGroupMembers structure.
type DeleteUserGroupMembersReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteUserGroupMembersReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteUserGroupMembersOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewDeleteUserGroupMembersMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteUserGroupMembersBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteUserGroupMembersForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteUserGroupMembersTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /mssp/entities/user-group-members/v1] deleteUserGroupMembers", response, response.Code())
	}
}

// NewDeleteUserGroupMembersOK creates a DeleteUserGroupMembersOK with default headers values
func NewDeleteUserGroupMembersOK() *DeleteUserGroupMembersOK {
	return &DeleteUserGroupMembersOK{}
}

/* DeleteUserGroupMembersOK describes a response with status code 200, with default header values.

OK
*/
type DeleteUserGroupMembersOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainUserGroupMembersResponseV1
}

// IsSuccess returns true when this delete user group members o k response has a 2xx status code
func (o *DeleteUserGroupMembersOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete user group members o k response has a 3xx status code
func (o *DeleteUserGroupMembersOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user group members o k response has a 4xx status code
func (o *DeleteUserGroupMembersOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete user group members o k response has a 5xx status code
func (o *DeleteUserGroupMembersOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user group members o k response a status code equal to that given
func (o *DeleteUserGroupMembersOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete user group members o k response
func (o *DeleteUserGroupMembersOK) Code() int {
	return 200
}

func (o *DeleteUserGroupMembersOK) Error() string {
	return fmt.Sprintf("[DELETE /mssp/entities/user-group-members/v1][%d] deleteUserGroupMembersOK  %+v", 200, o.Payload)
}

func (o *DeleteUserGroupMembersOK) String() string {
	return fmt.Sprintf("[DELETE /mssp/entities/user-group-members/v1][%d] deleteUserGroupMembersOK  %+v", 200, o.Payload)
}

func (o *DeleteUserGroupMembersOK) GetPayload() *models.DomainUserGroupMembersResponseV1 {
	return o.Payload
}

func (o *DeleteUserGroupMembersOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainUserGroupMembersResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserGroupMembersMultiStatus creates a DeleteUserGroupMembersMultiStatus with default headers values
func NewDeleteUserGroupMembersMultiStatus() *DeleteUserGroupMembersMultiStatus {
	return &DeleteUserGroupMembersMultiStatus{}
}

/* DeleteUserGroupMembersMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type DeleteUserGroupMembersMultiStatus struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainUserGroupMembersResponseV1
}

// IsSuccess returns true when this delete user group members multi status response has a 2xx status code
func (o *DeleteUserGroupMembersMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete user group members multi status response has a 3xx status code
func (o *DeleteUserGroupMembersMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user group members multi status response has a 4xx status code
func (o *DeleteUserGroupMembersMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete user group members multi status response has a 5xx status code
func (o *DeleteUserGroupMembersMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user group members multi status response a status code equal to that given
func (o *DeleteUserGroupMembersMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the delete user group members multi status response
func (o *DeleteUserGroupMembersMultiStatus) Code() int {
	return 207
}

func (o *DeleteUserGroupMembersMultiStatus) Error() string {
	return fmt.Sprintf("[DELETE /mssp/entities/user-group-members/v1][%d] deleteUserGroupMembersMultiStatus  %+v", 207, o.Payload)
}

func (o *DeleteUserGroupMembersMultiStatus) String() string {
	return fmt.Sprintf("[DELETE /mssp/entities/user-group-members/v1][%d] deleteUserGroupMembersMultiStatus  %+v", 207, o.Payload)
}

func (o *DeleteUserGroupMembersMultiStatus) GetPayload() *models.DomainUserGroupMembersResponseV1 {
	return o.Payload
}

func (o *DeleteUserGroupMembersMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainUserGroupMembersResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserGroupMembersBadRequest creates a DeleteUserGroupMembersBadRequest with default headers values
func NewDeleteUserGroupMembersBadRequest() *DeleteUserGroupMembersBadRequest {
	return &DeleteUserGroupMembersBadRequest{}
}

/* DeleteUserGroupMembersBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DeleteUserGroupMembersBadRequest struct {

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

// IsSuccess returns true when this delete user group members bad request response has a 2xx status code
func (o *DeleteUserGroupMembersBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user group members bad request response has a 3xx status code
func (o *DeleteUserGroupMembersBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user group members bad request response has a 4xx status code
func (o *DeleteUserGroupMembersBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user group members bad request response has a 5xx status code
func (o *DeleteUserGroupMembersBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user group members bad request response a status code equal to that given
func (o *DeleteUserGroupMembersBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete user group members bad request response
func (o *DeleteUserGroupMembersBadRequest) Code() int {
	return 400
}

func (o *DeleteUserGroupMembersBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /mssp/entities/user-group-members/v1][%d] deleteUserGroupMembersBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteUserGroupMembersBadRequest) String() string {
	return fmt.Sprintf("[DELETE /mssp/entities/user-group-members/v1][%d] deleteUserGroupMembersBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteUserGroupMembersBadRequest) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *DeleteUserGroupMembersBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteUserGroupMembersForbidden creates a DeleteUserGroupMembersForbidden with default headers values
func NewDeleteUserGroupMembersForbidden() *DeleteUserGroupMembersForbidden {
	return &DeleteUserGroupMembersForbidden{}
}

/* DeleteUserGroupMembersForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteUserGroupMembersForbidden struct {

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

// IsSuccess returns true when this delete user group members forbidden response has a 2xx status code
func (o *DeleteUserGroupMembersForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user group members forbidden response has a 3xx status code
func (o *DeleteUserGroupMembersForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user group members forbidden response has a 4xx status code
func (o *DeleteUserGroupMembersForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user group members forbidden response has a 5xx status code
func (o *DeleteUserGroupMembersForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user group members forbidden response a status code equal to that given
func (o *DeleteUserGroupMembersForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete user group members forbidden response
func (o *DeleteUserGroupMembersForbidden) Code() int {
	return 403
}

func (o *DeleteUserGroupMembersForbidden) Error() string {
	return fmt.Sprintf("[DELETE /mssp/entities/user-group-members/v1][%d] deleteUserGroupMembersForbidden  %+v", 403, o.Payload)
}

func (o *DeleteUserGroupMembersForbidden) String() string {
	return fmt.Sprintf("[DELETE /mssp/entities/user-group-members/v1][%d] deleteUserGroupMembersForbidden  %+v", 403, o.Payload)
}

func (o *DeleteUserGroupMembersForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *DeleteUserGroupMembersForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteUserGroupMembersTooManyRequests creates a DeleteUserGroupMembersTooManyRequests with default headers values
func NewDeleteUserGroupMembersTooManyRequests() *DeleteUserGroupMembersTooManyRequests {
	return &DeleteUserGroupMembersTooManyRequests{}
}

/* DeleteUserGroupMembersTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type DeleteUserGroupMembersTooManyRequests struct {

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

// IsSuccess returns true when this delete user group members too many requests response has a 2xx status code
func (o *DeleteUserGroupMembersTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user group members too many requests response has a 3xx status code
func (o *DeleteUserGroupMembersTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user group members too many requests response has a 4xx status code
func (o *DeleteUserGroupMembersTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user group members too many requests response has a 5xx status code
func (o *DeleteUserGroupMembersTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user group members too many requests response a status code equal to that given
func (o *DeleteUserGroupMembersTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete user group members too many requests response
func (o *DeleteUserGroupMembersTooManyRequests) Code() int {
	return 429
}

func (o *DeleteUserGroupMembersTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /mssp/entities/user-group-members/v1][%d] deleteUserGroupMembersTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteUserGroupMembersTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /mssp/entities/user-group-members/v1][%d] deleteUserGroupMembersTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteUserGroupMembersTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeleteUserGroupMembersTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
