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

// DeleteRuleGroupsReader is a Reader for the DeleteRuleGroups structure.
type DeleteRuleGroupsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteRuleGroupsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteRuleGroupsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteRuleGroupsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteRuleGroupsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteRuleGroupsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteRuleGroupsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeleteRuleGroupsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /filevantage/entities/rule-groups/v1] deleteRuleGroups", response, response.Code())
	}
}

// NewDeleteRuleGroupsOK creates a DeleteRuleGroupsOK with default headers values
func NewDeleteRuleGroupsOK() *DeleteRuleGroupsOK {
	return &DeleteRuleGroupsOK{}
}

/*
DeleteRuleGroupsOK describes a response with status code 200, with default header values.

OK
*/
type DeleteRuleGroupsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RulegroupsDeleteResponse
}

// IsSuccess returns true when this delete rule groups o k response has a 2xx status code
func (o *DeleteRuleGroupsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete rule groups o k response has a 3xx status code
func (o *DeleteRuleGroupsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rule groups o k response has a 4xx status code
func (o *DeleteRuleGroupsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete rule groups o k response has a 5xx status code
func (o *DeleteRuleGroupsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete rule groups o k response a status code equal to that given
func (o *DeleteRuleGroupsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete rule groups o k response
func (o *DeleteRuleGroupsOK) Code() int {
	return 200
}

func (o *DeleteRuleGroupsOK) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsOK  %+v", 200, o.Payload)
}

func (o *DeleteRuleGroupsOK) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsOK  %+v", 200, o.Payload)
}

func (o *DeleteRuleGroupsOK) GetPayload() *models.RulegroupsDeleteResponse {
	return o.Payload
}

func (o *DeleteRuleGroupsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RulegroupsDeleteResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteRuleGroupsBadRequest creates a DeleteRuleGroupsBadRequest with default headers values
func NewDeleteRuleGroupsBadRequest() *DeleteRuleGroupsBadRequest {
	return &DeleteRuleGroupsBadRequest{}
}

/*
DeleteRuleGroupsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DeleteRuleGroupsBadRequest struct {

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

// IsSuccess returns true when this delete rule groups bad request response has a 2xx status code
func (o *DeleteRuleGroupsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete rule groups bad request response has a 3xx status code
func (o *DeleteRuleGroupsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rule groups bad request response has a 4xx status code
func (o *DeleteRuleGroupsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete rule groups bad request response has a 5xx status code
func (o *DeleteRuleGroupsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete rule groups bad request response a status code equal to that given
func (o *DeleteRuleGroupsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete rule groups bad request response
func (o *DeleteRuleGroupsBadRequest) Code() int {
	return 400
}

func (o *DeleteRuleGroupsBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteRuleGroupsBadRequest) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteRuleGroupsBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DeleteRuleGroupsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteRuleGroupsForbidden creates a DeleteRuleGroupsForbidden with default headers values
func NewDeleteRuleGroupsForbidden() *DeleteRuleGroupsForbidden {
	return &DeleteRuleGroupsForbidden{}
}

/*
DeleteRuleGroupsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteRuleGroupsForbidden struct {

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

// IsSuccess returns true when this delete rule groups forbidden response has a 2xx status code
func (o *DeleteRuleGroupsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete rule groups forbidden response has a 3xx status code
func (o *DeleteRuleGroupsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rule groups forbidden response has a 4xx status code
func (o *DeleteRuleGroupsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete rule groups forbidden response has a 5xx status code
func (o *DeleteRuleGroupsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete rule groups forbidden response a status code equal to that given
func (o *DeleteRuleGroupsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete rule groups forbidden response
func (o *DeleteRuleGroupsForbidden) Code() int {
	return 403
}

func (o *DeleteRuleGroupsForbidden) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsForbidden  %+v", 403, o.Payload)
}

func (o *DeleteRuleGroupsForbidden) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsForbidden  %+v", 403, o.Payload)
}

func (o *DeleteRuleGroupsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeleteRuleGroupsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteRuleGroupsNotFound creates a DeleteRuleGroupsNotFound with default headers values
func NewDeleteRuleGroupsNotFound() *DeleteRuleGroupsNotFound {
	return &DeleteRuleGroupsNotFound{}
}

/*
DeleteRuleGroupsNotFound describes a response with status code 404, with default header values.

Not Found
*/
type DeleteRuleGroupsNotFound struct {

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

// IsSuccess returns true when this delete rule groups not found response has a 2xx status code
func (o *DeleteRuleGroupsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete rule groups not found response has a 3xx status code
func (o *DeleteRuleGroupsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rule groups not found response has a 4xx status code
func (o *DeleteRuleGroupsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete rule groups not found response has a 5xx status code
func (o *DeleteRuleGroupsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete rule groups not found response a status code equal to that given
func (o *DeleteRuleGroupsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete rule groups not found response
func (o *DeleteRuleGroupsNotFound) Code() int {
	return 404
}

func (o *DeleteRuleGroupsNotFound) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsNotFound  %+v", 404, o.Payload)
}

func (o *DeleteRuleGroupsNotFound) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsNotFound  %+v", 404, o.Payload)
}

func (o *DeleteRuleGroupsNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DeleteRuleGroupsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteRuleGroupsTooManyRequests creates a DeleteRuleGroupsTooManyRequests with default headers values
func NewDeleteRuleGroupsTooManyRequests() *DeleteRuleGroupsTooManyRequests {
	return &DeleteRuleGroupsTooManyRequests{}
}

/*
DeleteRuleGroupsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type DeleteRuleGroupsTooManyRequests struct {

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

// IsSuccess returns true when this delete rule groups too many requests response has a 2xx status code
func (o *DeleteRuleGroupsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete rule groups too many requests response has a 3xx status code
func (o *DeleteRuleGroupsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rule groups too many requests response has a 4xx status code
func (o *DeleteRuleGroupsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete rule groups too many requests response has a 5xx status code
func (o *DeleteRuleGroupsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete rule groups too many requests response a status code equal to that given
func (o *DeleteRuleGroupsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete rule groups too many requests response
func (o *DeleteRuleGroupsTooManyRequests) Code() int {
	return 429
}

func (o *DeleteRuleGroupsTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteRuleGroupsTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteRuleGroupsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeleteRuleGroupsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteRuleGroupsInternalServerError creates a DeleteRuleGroupsInternalServerError with default headers values
func NewDeleteRuleGroupsInternalServerError() *DeleteRuleGroupsInternalServerError {
	return &DeleteRuleGroupsInternalServerError{}
}

/*
DeleteRuleGroupsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type DeleteRuleGroupsInternalServerError struct {

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

// IsSuccess returns true when this delete rule groups internal server error response has a 2xx status code
func (o *DeleteRuleGroupsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete rule groups internal server error response has a 3xx status code
func (o *DeleteRuleGroupsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rule groups internal server error response has a 4xx status code
func (o *DeleteRuleGroupsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete rule groups internal server error response has a 5xx status code
func (o *DeleteRuleGroupsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this delete rule groups internal server error response a status code equal to that given
func (o *DeleteRuleGroupsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the delete rule groups internal server error response
func (o *DeleteRuleGroupsInternalServerError) Code() int {
	return 500
}

func (o *DeleteRuleGroupsInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteRuleGroupsInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/rule-groups/v1][%d] deleteRuleGroupsInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteRuleGroupsInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DeleteRuleGroupsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
