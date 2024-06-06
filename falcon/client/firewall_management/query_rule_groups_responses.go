// Code generated by go-swagger; DO NOT EDIT.

package firewall_management

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

// QueryRuleGroupsReader is a Reader for the QueryRuleGroups structure.
type QueryRuleGroupsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryRuleGroupsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryRuleGroupsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryRuleGroupsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryRuleGroupsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryRuleGroupsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /fwmgr/queries/rule-groups/v1] query-rule-groups", response, response.Code())
	}
}

// NewQueryRuleGroupsOK creates a QueryRuleGroupsOK with default headers values
func NewQueryRuleGroupsOK() *QueryRuleGroupsOK {
	return &QueryRuleGroupsOK{}
}

/*
QueryRuleGroupsOK describes a response with status code 200, with default header values.

OK
*/
type QueryRuleGroupsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.FwmgrAPIQueryResponse
}

// IsSuccess returns true when this query rule groups o k response has a 2xx status code
func (o *QueryRuleGroupsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query rule groups o k response has a 3xx status code
func (o *QueryRuleGroupsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query rule groups o k response has a 4xx status code
func (o *QueryRuleGroupsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query rule groups o k response has a 5xx status code
func (o *QueryRuleGroupsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query rule groups o k response a status code equal to that given
func (o *QueryRuleGroupsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query rule groups o k response
func (o *QueryRuleGroupsOK) Code() int {
	return 200
}

func (o *QueryRuleGroupsOK) Error() string {
	return fmt.Sprintf("[GET /fwmgr/queries/rule-groups/v1][%d] queryRuleGroupsOK  %+v", 200, o.Payload)
}

func (o *QueryRuleGroupsOK) String() string {
	return fmt.Sprintf("[GET /fwmgr/queries/rule-groups/v1][%d] queryRuleGroupsOK  %+v", 200, o.Payload)
}

func (o *QueryRuleGroupsOK) GetPayload() *models.FwmgrAPIQueryResponse {
	return o.Payload
}

func (o *QueryRuleGroupsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.FwmgrAPIQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryRuleGroupsBadRequest creates a QueryRuleGroupsBadRequest with default headers values
func NewQueryRuleGroupsBadRequest() *QueryRuleGroupsBadRequest {
	return &QueryRuleGroupsBadRequest{}
}

/*
QueryRuleGroupsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryRuleGroupsBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.FwmgrMsaspecResponseFields
}

// IsSuccess returns true when this query rule groups bad request response has a 2xx status code
func (o *QueryRuleGroupsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query rule groups bad request response has a 3xx status code
func (o *QueryRuleGroupsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query rule groups bad request response has a 4xx status code
func (o *QueryRuleGroupsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query rule groups bad request response has a 5xx status code
func (o *QueryRuleGroupsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query rule groups bad request response a status code equal to that given
func (o *QueryRuleGroupsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query rule groups bad request response
func (o *QueryRuleGroupsBadRequest) Code() int {
	return 400
}

func (o *QueryRuleGroupsBadRequest) Error() string {
	return fmt.Sprintf("[GET /fwmgr/queries/rule-groups/v1][%d] queryRuleGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *QueryRuleGroupsBadRequest) String() string {
	return fmt.Sprintf("[GET /fwmgr/queries/rule-groups/v1][%d] queryRuleGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *QueryRuleGroupsBadRequest) GetPayload() *models.FwmgrMsaspecResponseFields {
	return o.Payload
}

func (o *QueryRuleGroupsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.FwmgrMsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryRuleGroupsForbidden creates a QueryRuleGroupsForbidden with default headers values
func NewQueryRuleGroupsForbidden() *QueryRuleGroupsForbidden {
	return &QueryRuleGroupsForbidden{}
}

/*
QueryRuleGroupsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryRuleGroupsForbidden struct {

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

// IsSuccess returns true when this query rule groups forbidden response has a 2xx status code
func (o *QueryRuleGroupsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query rule groups forbidden response has a 3xx status code
func (o *QueryRuleGroupsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query rule groups forbidden response has a 4xx status code
func (o *QueryRuleGroupsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query rule groups forbidden response has a 5xx status code
func (o *QueryRuleGroupsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query rule groups forbidden response a status code equal to that given
func (o *QueryRuleGroupsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query rule groups forbidden response
func (o *QueryRuleGroupsForbidden) Code() int {
	return 403
}

func (o *QueryRuleGroupsForbidden) Error() string {
	return fmt.Sprintf("[GET /fwmgr/queries/rule-groups/v1][%d] queryRuleGroupsForbidden  %+v", 403, o.Payload)
}

func (o *QueryRuleGroupsForbidden) String() string {
	return fmt.Sprintf("[GET /fwmgr/queries/rule-groups/v1][%d] queryRuleGroupsForbidden  %+v", 403, o.Payload)
}

func (o *QueryRuleGroupsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryRuleGroupsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryRuleGroupsTooManyRequests creates a QueryRuleGroupsTooManyRequests with default headers values
func NewQueryRuleGroupsTooManyRequests() *QueryRuleGroupsTooManyRequests {
	return &QueryRuleGroupsTooManyRequests{}
}

/*
QueryRuleGroupsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryRuleGroupsTooManyRequests struct {

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

// IsSuccess returns true when this query rule groups too many requests response has a 2xx status code
func (o *QueryRuleGroupsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query rule groups too many requests response has a 3xx status code
func (o *QueryRuleGroupsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query rule groups too many requests response has a 4xx status code
func (o *QueryRuleGroupsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query rule groups too many requests response has a 5xx status code
func (o *QueryRuleGroupsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query rule groups too many requests response a status code equal to that given
func (o *QueryRuleGroupsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query rule groups too many requests response
func (o *QueryRuleGroupsTooManyRequests) Code() int {
	return 429
}

func (o *QueryRuleGroupsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /fwmgr/queries/rule-groups/v1][%d] queryRuleGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryRuleGroupsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /fwmgr/queries/rule-groups/v1][%d] queryRuleGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryRuleGroupsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryRuleGroupsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
