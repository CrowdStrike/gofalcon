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

// DeleteFirewallPoliciesReader is a Reader for the DeleteFirewallPolicies structure.
type DeleteFirewallPoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteFirewallPoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteFirewallPoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewDeleteFirewallPoliciesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteFirewallPoliciesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteFirewallPoliciesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeleteFirewallPoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /policy/entities/firewall/v1] deleteFirewallPolicies", response, response.Code())
	}
}

// NewDeleteFirewallPoliciesOK creates a DeleteFirewallPoliciesOK with default headers values
func NewDeleteFirewallPoliciesOK() *DeleteFirewallPoliciesOK {
	return &DeleteFirewallPoliciesOK{}
}

/* DeleteFirewallPoliciesOK describes a response with status code 200, with default header values.

OK
*/
type DeleteFirewallPoliciesOK struct {

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

// IsSuccess returns true when this delete firewall policies o k response has a 2xx status code
func (o *DeleteFirewallPoliciesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete firewall policies o k response has a 3xx status code
func (o *DeleteFirewallPoliciesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete firewall policies o k response has a 4xx status code
func (o *DeleteFirewallPoliciesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete firewall policies o k response has a 5xx status code
func (o *DeleteFirewallPoliciesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete firewall policies o k response a status code equal to that given
func (o *DeleteFirewallPoliciesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete firewall policies o k response
func (o *DeleteFirewallPoliciesOK) Code() int {
	return 200
}

func (o *DeleteFirewallPoliciesOK) Error() string {
	return fmt.Sprintf("[DELETE /policy/entities/firewall/v1][%d] deleteFirewallPoliciesOK  %+v", 200, o.Payload)
}

func (o *DeleteFirewallPoliciesOK) String() string {
	return fmt.Sprintf("[DELETE /policy/entities/firewall/v1][%d] deleteFirewallPoliciesOK  %+v", 200, o.Payload)
}

func (o *DeleteFirewallPoliciesOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *DeleteFirewallPoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteFirewallPoliciesForbidden creates a DeleteFirewallPoliciesForbidden with default headers values
func NewDeleteFirewallPoliciesForbidden() *DeleteFirewallPoliciesForbidden {
	return &DeleteFirewallPoliciesForbidden{}
}

/* DeleteFirewallPoliciesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteFirewallPoliciesForbidden struct {

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

// IsSuccess returns true when this delete firewall policies forbidden response has a 2xx status code
func (o *DeleteFirewallPoliciesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete firewall policies forbidden response has a 3xx status code
func (o *DeleteFirewallPoliciesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete firewall policies forbidden response has a 4xx status code
func (o *DeleteFirewallPoliciesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete firewall policies forbidden response has a 5xx status code
func (o *DeleteFirewallPoliciesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete firewall policies forbidden response a status code equal to that given
func (o *DeleteFirewallPoliciesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete firewall policies forbidden response
func (o *DeleteFirewallPoliciesForbidden) Code() int {
	return 403
}

func (o *DeleteFirewallPoliciesForbidden) Error() string {
	return fmt.Sprintf("[DELETE /policy/entities/firewall/v1][%d] deleteFirewallPoliciesForbidden  %+v", 403, o.Payload)
}

func (o *DeleteFirewallPoliciesForbidden) String() string {
	return fmt.Sprintf("[DELETE /policy/entities/firewall/v1][%d] deleteFirewallPoliciesForbidden  %+v", 403, o.Payload)
}

func (o *DeleteFirewallPoliciesForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *DeleteFirewallPoliciesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteFirewallPoliciesNotFound creates a DeleteFirewallPoliciesNotFound with default headers values
func NewDeleteFirewallPoliciesNotFound() *DeleteFirewallPoliciesNotFound {
	return &DeleteFirewallPoliciesNotFound{}
}

/* DeleteFirewallPoliciesNotFound describes a response with status code 404, with default header values.

Not Found
*/
type DeleteFirewallPoliciesNotFound struct {

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

// IsSuccess returns true when this delete firewall policies not found response has a 2xx status code
func (o *DeleteFirewallPoliciesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete firewall policies not found response has a 3xx status code
func (o *DeleteFirewallPoliciesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete firewall policies not found response has a 4xx status code
func (o *DeleteFirewallPoliciesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete firewall policies not found response has a 5xx status code
func (o *DeleteFirewallPoliciesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete firewall policies not found response a status code equal to that given
func (o *DeleteFirewallPoliciesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete firewall policies not found response
func (o *DeleteFirewallPoliciesNotFound) Code() int {
	return 404
}

func (o *DeleteFirewallPoliciesNotFound) Error() string {
	return fmt.Sprintf("[DELETE /policy/entities/firewall/v1][%d] deleteFirewallPoliciesNotFound  %+v", 404, o.Payload)
}

func (o *DeleteFirewallPoliciesNotFound) String() string {
	return fmt.Sprintf("[DELETE /policy/entities/firewall/v1][%d] deleteFirewallPoliciesNotFound  %+v", 404, o.Payload)
}

func (o *DeleteFirewallPoliciesNotFound) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *DeleteFirewallPoliciesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteFirewallPoliciesTooManyRequests creates a DeleteFirewallPoliciesTooManyRequests with default headers values
func NewDeleteFirewallPoliciesTooManyRequests() *DeleteFirewallPoliciesTooManyRequests {
	return &DeleteFirewallPoliciesTooManyRequests{}
}

/* DeleteFirewallPoliciesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type DeleteFirewallPoliciesTooManyRequests struct {

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

// IsSuccess returns true when this delete firewall policies too many requests response has a 2xx status code
func (o *DeleteFirewallPoliciesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete firewall policies too many requests response has a 3xx status code
func (o *DeleteFirewallPoliciesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete firewall policies too many requests response has a 4xx status code
func (o *DeleteFirewallPoliciesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete firewall policies too many requests response has a 5xx status code
func (o *DeleteFirewallPoliciesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete firewall policies too many requests response a status code equal to that given
func (o *DeleteFirewallPoliciesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete firewall policies too many requests response
func (o *DeleteFirewallPoliciesTooManyRequests) Code() int {
	return 429
}

func (o *DeleteFirewallPoliciesTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /policy/entities/firewall/v1][%d] deleteFirewallPoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteFirewallPoliciesTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /policy/entities/firewall/v1][%d] deleteFirewallPoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteFirewallPoliciesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeleteFirewallPoliciesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteFirewallPoliciesInternalServerError creates a DeleteFirewallPoliciesInternalServerError with default headers values
func NewDeleteFirewallPoliciesInternalServerError() *DeleteFirewallPoliciesInternalServerError {
	return &DeleteFirewallPoliciesInternalServerError{}
}

/* DeleteFirewallPoliciesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type DeleteFirewallPoliciesInternalServerError struct {

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

// IsSuccess returns true when this delete firewall policies internal server error response has a 2xx status code
func (o *DeleteFirewallPoliciesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete firewall policies internal server error response has a 3xx status code
func (o *DeleteFirewallPoliciesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete firewall policies internal server error response has a 4xx status code
func (o *DeleteFirewallPoliciesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete firewall policies internal server error response has a 5xx status code
func (o *DeleteFirewallPoliciesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this delete firewall policies internal server error response a status code equal to that given
func (o *DeleteFirewallPoliciesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the delete firewall policies internal server error response
func (o *DeleteFirewallPoliciesInternalServerError) Code() int {
	return 500
}

func (o *DeleteFirewallPoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /policy/entities/firewall/v1][%d] deleteFirewallPoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteFirewallPoliciesInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /policy/entities/firewall/v1][%d] deleteFirewallPoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteFirewallPoliciesInternalServerError) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *DeleteFirewallPoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
