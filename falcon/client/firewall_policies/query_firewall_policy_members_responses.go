// Code generated by go-swagger; DO NOT EDIT.

package firewall_policies

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

// QueryFirewallPolicyMembersReader is a Reader for the QueryFirewallPolicyMembers structure.
type QueryFirewallPolicyMembersReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryFirewallPolicyMembersReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryFirewallPolicyMembersOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryFirewallPolicyMembersBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryFirewallPolicyMembersForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewQueryFirewallPolicyMembersNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryFirewallPolicyMembersTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryFirewallPolicyMembersInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /policy/queries/firewall-members/v1] queryFirewallPolicyMembers", response, response.Code())
	}
}

// NewQueryFirewallPolicyMembersOK creates a QueryFirewallPolicyMembersOK with default headers values
func NewQueryFirewallPolicyMembersOK() *QueryFirewallPolicyMembersOK {
	return &QueryFirewallPolicyMembersOK{}
}

/* QueryFirewallPolicyMembersOK describes a response with status code 200, with default header values.

OK
*/
type QueryFirewallPolicyMembersOK struct {

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

// IsSuccess returns true when this query firewall policy members o k response has a 2xx status code
func (o *QueryFirewallPolicyMembersOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query firewall policy members o k response has a 3xx status code
func (o *QueryFirewallPolicyMembersOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query firewall policy members o k response has a 4xx status code
func (o *QueryFirewallPolicyMembersOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query firewall policy members o k response has a 5xx status code
func (o *QueryFirewallPolicyMembersOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query firewall policy members o k response a status code equal to that given
func (o *QueryFirewallPolicyMembersOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query firewall policy members o k response
func (o *QueryFirewallPolicyMembersOK) Code() int {
	return 200
}

func (o *QueryFirewallPolicyMembersOK) Error() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersOK  %+v", 200, o.Payload)
}

func (o *QueryFirewallPolicyMembersOK) String() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersOK  %+v", 200, o.Payload)
}

func (o *QueryFirewallPolicyMembersOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryFirewallPolicyMembersOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryFirewallPolicyMembersBadRequest creates a QueryFirewallPolicyMembersBadRequest with default headers values
func NewQueryFirewallPolicyMembersBadRequest() *QueryFirewallPolicyMembersBadRequest {
	return &QueryFirewallPolicyMembersBadRequest{}
}

/* QueryFirewallPolicyMembersBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryFirewallPolicyMembersBadRequest struct {

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

// IsSuccess returns true when this query firewall policy members bad request response has a 2xx status code
func (o *QueryFirewallPolicyMembersBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query firewall policy members bad request response has a 3xx status code
func (o *QueryFirewallPolicyMembersBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query firewall policy members bad request response has a 4xx status code
func (o *QueryFirewallPolicyMembersBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query firewall policy members bad request response has a 5xx status code
func (o *QueryFirewallPolicyMembersBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query firewall policy members bad request response a status code equal to that given
func (o *QueryFirewallPolicyMembersBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query firewall policy members bad request response
func (o *QueryFirewallPolicyMembersBadRequest) Code() int {
	return 400
}

func (o *QueryFirewallPolicyMembersBadRequest) Error() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersBadRequest  %+v", 400, o.Payload)
}

func (o *QueryFirewallPolicyMembersBadRequest) String() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersBadRequest  %+v", 400, o.Payload)
}

func (o *QueryFirewallPolicyMembersBadRequest) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryFirewallPolicyMembersBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryFirewallPolicyMembersForbidden creates a QueryFirewallPolicyMembersForbidden with default headers values
func NewQueryFirewallPolicyMembersForbidden() *QueryFirewallPolicyMembersForbidden {
	return &QueryFirewallPolicyMembersForbidden{}
}

/* QueryFirewallPolicyMembersForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryFirewallPolicyMembersForbidden struct {

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

// IsSuccess returns true when this query firewall policy members forbidden response has a 2xx status code
func (o *QueryFirewallPolicyMembersForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query firewall policy members forbidden response has a 3xx status code
func (o *QueryFirewallPolicyMembersForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query firewall policy members forbidden response has a 4xx status code
func (o *QueryFirewallPolicyMembersForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query firewall policy members forbidden response has a 5xx status code
func (o *QueryFirewallPolicyMembersForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query firewall policy members forbidden response a status code equal to that given
func (o *QueryFirewallPolicyMembersForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query firewall policy members forbidden response
func (o *QueryFirewallPolicyMembersForbidden) Code() int {
	return 403
}

func (o *QueryFirewallPolicyMembersForbidden) Error() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersForbidden  %+v", 403, o.Payload)
}

func (o *QueryFirewallPolicyMembersForbidden) String() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersForbidden  %+v", 403, o.Payload)
}

func (o *QueryFirewallPolicyMembersForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *QueryFirewallPolicyMembersForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryFirewallPolicyMembersNotFound creates a QueryFirewallPolicyMembersNotFound with default headers values
func NewQueryFirewallPolicyMembersNotFound() *QueryFirewallPolicyMembersNotFound {
	return &QueryFirewallPolicyMembersNotFound{}
}

/* QueryFirewallPolicyMembersNotFound describes a response with status code 404, with default header values.

Not Found
*/
type QueryFirewallPolicyMembersNotFound struct {

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

// IsSuccess returns true when this query firewall policy members not found response has a 2xx status code
func (o *QueryFirewallPolicyMembersNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query firewall policy members not found response has a 3xx status code
func (o *QueryFirewallPolicyMembersNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query firewall policy members not found response has a 4xx status code
func (o *QueryFirewallPolicyMembersNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this query firewall policy members not found response has a 5xx status code
func (o *QueryFirewallPolicyMembersNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this query firewall policy members not found response a status code equal to that given
func (o *QueryFirewallPolicyMembersNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the query firewall policy members not found response
func (o *QueryFirewallPolicyMembersNotFound) Code() int {
	return 404
}

func (o *QueryFirewallPolicyMembersNotFound) Error() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersNotFound  %+v", 404, o.Payload)
}

func (o *QueryFirewallPolicyMembersNotFound) String() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersNotFound  %+v", 404, o.Payload)
}

func (o *QueryFirewallPolicyMembersNotFound) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryFirewallPolicyMembersNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryFirewallPolicyMembersTooManyRequests creates a QueryFirewallPolicyMembersTooManyRequests with default headers values
func NewQueryFirewallPolicyMembersTooManyRequests() *QueryFirewallPolicyMembersTooManyRequests {
	return &QueryFirewallPolicyMembersTooManyRequests{}
}

/* QueryFirewallPolicyMembersTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryFirewallPolicyMembersTooManyRequests struct {

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

// IsSuccess returns true when this query firewall policy members too many requests response has a 2xx status code
func (o *QueryFirewallPolicyMembersTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query firewall policy members too many requests response has a 3xx status code
func (o *QueryFirewallPolicyMembersTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query firewall policy members too many requests response has a 4xx status code
func (o *QueryFirewallPolicyMembersTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query firewall policy members too many requests response has a 5xx status code
func (o *QueryFirewallPolicyMembersTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query firewall policy members too many requests response a status code equal to that given
func (o *QueryFirewallPolicyMembersTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query firewall policy members too many requests response
func (o *QueryFirewallPolicyMembersTooManyRequests) Code() int {
	return 429
}

func (o *QueryFirewallPolicyMembersTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryFirewallPolicyMembersTooManyRequests) String() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryFirewallPolicyMembersTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryFirewallPolicyMembersTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryFirewallPolicyMembersInternalServerError creates a QueryFirewallPolicyMembersInternalServerError with default headers values
func NewQueryFirewallPolicyMembersInternalServerError() *QueryFirewallPolicyMembersInternalServerError {
	return &QueryFirewallPolicyMembersInternalServerError{}
}

/* QueryFirewallPolicyMembersInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryFirewallPolicyMembersInternalServerError struct {

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

// IsSuccess returns true when this query firewall policy members internal server error response has a 2xx status code
func (o *QueryFirewallPolicyMembersInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query firewall policy members internal server error response has a 3xx status code
func (o *QueryFirewallPolicyMembersInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query firewall policy members internal server error response has a 4xx status code
func (o *QueryFirewallPolicyMembersInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query firewall policy members internal server error response has a 5xx status code
func (o *QueryFirewallPolicyMembersInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query firewall policy members internal server error response a status code equal to that given
func (o *QueryFirewallPolicyMembersInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query firewall policy members internal server error response
func (o *QueryFirewallPolicyMembersInternalServerError) Code() int {
	return 500
}

func (o *QueryFirewallPolicyMembersInternalServerError) Error() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryFirewallPolicyMembersInternalServerError) String() string {
	return fmt.Sprintf("[GET /policy/queries/firewall-members/v1][%d] queryFirewallPolicyMembersInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryFirewallPolicyMembersInternalServerError) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryFirewallPolicyMembersInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
