// Code generated by go-swagger; DO NOT EDIT.

package cspm_registration

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

// DeleteCSPMAzureManagementGroupReader is a Reader for the DeleteCSPMAzureManagementGroup structure.
type DeleteCSPMAzureManagementGroupReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteCSPMAzureManagementGroupReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteCSPMAzureManagementGroupOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewDeleteCSPMAzureManagementGroupMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteCSPMAzureManagementGroupBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteCSPMAzureManagementGroupForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteCSPMAzureManagementGroupTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeleteCSPMAzureManagementGroupInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1] DeleteCSPMAzureManagementGroup", response, response.Code())
	}
}

// NewDeleteCSPMAzureManagementGroupOK creates a DeleteCSPMAzureManagementGroupOK with default headers values
func NewDeleteCSPMAzureManagementGroupOK() *DeleteCSPMAzureManagementGroupOK {
	return &DeleteCSPMAzureManagementGroupOK{}
}

/*
DeleteCSPMAzureManagementGroupOK describes a response with status code 200, with default header values.

OK
*/
type DeleteCSPMAzureManagementGroupOK struct {

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

// IsSuccess returns true when this delete c s p m azure management group o k response has a 2xx status code
func (o *DeleteCSPMAzureManagementGroupOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete c s p m azure management group o k response has a 3xx status code
func (o *DeleteCSPMAzureManagementGroupOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete c s p m azure management group o k response has a 4xx status code
func (o *DeleteCSPMAzureManagementGroupOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete c s p m azure management group o k response has a 5xx status code
func (o *DeleteCSPMAzureManagementGroupOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete c s p m azure management group o k response a status code equal to that given
func (o *DeleteCSPMAzureManagementGroupOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete c s p m azure management group o k response
func (o *DeleteCSPMAzureManagementGroupOK) Code() int {
	return 200
}

func (o *DeleteCSPMAzureManagementGroupOK) Error() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupOK  %+v", 200, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupOK) String() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupOK  %+v", 200, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupOK) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DeleteCSPMAzureManagementGroupOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteCSPMAzureManagementGroupMultiStatus creates a DeleteCSPMAzureManagementGroupMultiStatus with default headers values
func NewDeleteCSPMAzureManagementGroupMultiStatus() *DeleteCSPMAzureManagementGroupMultiStatus {
	return &DeleteCSPMAzureManagementGroupMultiStatus{}
}

/*
DeleteCSPMAzureManagementGroupMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type DeleteCSPMAzureManagementGroupMultiStatus struct {

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

// IsSuccess returns true when this delete c s p m azure management group multi status response has a 2xx status code
func (o *DeleteCSPMAzureManagementGroupMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete c s p m azure management group multi status response has a 3xx status code
func (o *DeleteCSPMAzureManagementGroupMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete c s p m azure management group multi status response has a 4xx status code
func (o *DeleteCSPMAzureManagementGroupMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete c s p m azure management group multi status response has a 5xx status code
func (o *DeleteCSPMAzureManagementGroupMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this delete c s p m azure management group multi status response a status code equal to that given
func (o *DeleteCSPMAzureManagementGroupMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the delete c s p m azure management group multi status response
func (o *DeleteCSPMAzureManagementGroupMultiStatus) Code() int {
	return 207
}

func (o *DeleteCSPMAzureManagementGroupMultiStatus) Error() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupMultiStatus  %+v", 207, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupMultiStatus) String() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupMultiStatus  %+v", 207, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupMultiStatus) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DeleteCSPMAzureManagementGroupMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteCSPMAzureManagementGroupBadRequest creates a DeleteCSPMAzureManagementGroupBadRequest with default headers values
func NewDeleteCSPMAzureManagementGroupBadRequest() *DeleteCSPMAzureManagementGroupBadRequest {
	return &DeleteCSPMAzureManagementGroupBadRequest{}
}

/*
DeleteCSPMAzureManagementGroupBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DeleteCSPMAzureManagementGroupBadRequest struct {

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

// IsSuccess returns true when this delete c s p m azure management group bad request response has a 2xx status code
func (o *DeleteCSPMAzureManagementGroupBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete c s p m azure management group bad request response has a 3xx status code
func (o *DeleteCSPMAzureManagementGroupBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete c s p m azure management group bad request response has a 4xx status code
func (o *DeleteCSPMAzureManagementGroupBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete c s p m azure management group bad request response has a 5xx status code
func (o *DeleteCSPMAzureManagementGroupBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete c s p m azure management group bad request response a status code equal to that given
func (o *DeleteCSPMAzureManagementGroupBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete c s p m azure management group bad request response
func (o *DeleteCSPMAzureManagementGroupBadRequest) Code() int {
	return 400
}

func (o *DeleteCSPMAzureManagementGroupBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupBadRequest) String() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DeleteCSPMAzureManagementGroupBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteCSPMAzureManagementGroupForbidden creates a DeleteCSPMAzureManagementGroupForbidden with default headers values
func NewDeleteCSPMAzureManagementGroupForbidden() *DeleteCSPMAzureManagementGroupForbidden {
	return &DeleteCSPMAzureManagementGroupForbidden{}
}

/*
DeleteCSPMAzureManagementGroupForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteCSPMAzureManagementGroupForbidden struct {

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

// IsSuccess returns true when this delete c s p m azure management group forbidden response has a 2xx status code
func (o *DeleteCSPMAzureManagementGroupForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete c s p m azure management group forbidden response has a 3xx status code
func (o *DeleteCSPMAzureManagementGroupForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete c s p m azure management group forbidden response has a 4xx status code
func (o *DeleteCSPMAzureManagementGroupForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete c s p m azure management group forbidden response has a 5xx status code
func (o *DeleteCSPMAzureManagementGroupForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete c s p m azure management group forbidden response a status code equal to that given
func (o *DeleteCSPMAzureManagementGroupForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete c s p m azure management group forbidden response
func (o *DeleteCSPMAzureManagementGroupForbidden) Code() int {
	return 403
}

func (o *DeleteCSPMAzureManagementGroupForbidden) Error() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupForbidden  %+v", 403, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupForbidden) String() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupForbidden  %+v", 403, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupForbidden) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DeleteCSPMAzureManagementGroupForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteCSPMAzureManagementGroupTooManyRequests creates a DeleteCSPMAzureManagementGroupTooManyRequests with default headers values
func NewDeleteCSPMAzureManagementGroupTooManyRequests() *DeleteCSPMAzureManagementGroupTooManyRequests {
	return &DeleteCSPMAzureManagementGroupTooManyRequests{}
}

/*
DeleteCSPMAzureManagementGroupTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type DeleteCSPMAzureManagementGroupTooManyRequests struct {

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

// IsSuccess returns true when this delete c s p m azure management group too many requests response has a 2xx status code
func (o *DeleteCSPMAzureManagementGroupTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete c s p m azure management group too many requests response has a 3xx status code
func (o *DeleteCSPMAzureManagementGroupTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete c s p m azure management group too many requests response has a 4xx status code
func (o *DeleteCSPMAzureManagementGroupTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete c s p m azure management group too many requests response has a 5xx status code
func (o *DeleteCSPMAzureManagementGroupTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete c s p m azure management group too many requests response a status code equal to that given
func (o *DeleteCSPMAzureManagementGroupTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete c s p m azure management group too many requests response
func (o *DeleteCSPMAzureManagementGroupTooManyRequests) Code() int {
	return 429
}

func (o *DeleteCSPMAzureManagementGroupTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeleteCSPMAzureManagementGroupTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteCSPMAzureManagementGroupInternalServerError creates a DeleteCSPMAzureManagementGroupInternalServerError with default headers values
func NewDeleteCSPMAzureManagementGroupInternalServerError() *DeleteCSPMAzureManagementGroupInternalServerError {
	return &DeleteCSPMAzureManagementGroupInternalServerError{}
}

/*
DeleteCSPMAzureManagementGroupInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type DeleteCSPMAzureManagementGroupInternalServerError struct {

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

// IsSuccess returns true when this delete c s p m azure management group internal server error response has a 2xx status code
func (o *DeleteCSPMAzureManagementGroupInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete c s p m azure management group internal server error response has a 3xx status code
func (o *DeleteCSPMAzureManagementGroupInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete c s p m azure management group internal server error response has a 4xx status code
func (o *DeleteCSPMAzureManagementGroupInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete c s p m azure management group internal server error response has a 5xx status code
func (o *DeleteCSPMAzureManagementGroupInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this delete c s p m azure management group internal server error response a status code equal to that given
func (o *DeleteCSPMAzureManagementGroupInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the delete c s p m azure management group internal server error response
func (o *DeleteCSPMAzureManagementGroupInternalServerError) Code() int {
	return 500
}

func (o *DeleteCSPMAzureManagementGroupInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /cloud-connect-cspm-azure/entities/management-group/v1][%d] deleteCSPMAzureManagementGroupInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteCSPMAzureManagementGroupInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DeleteCSPMAzureManagementGroupInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
