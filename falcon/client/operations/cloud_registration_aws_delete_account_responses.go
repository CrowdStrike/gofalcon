// Code generated by go-swagger; DO NOT EDIT.

package operations

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

// CloudRegistrationAwsDeleteAccountReader is a Reader for the CloudRegistrationAwsDeleteAccount structure.
type CloudRegistrationAwsDeleteAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CloudRegistrationAwsDeleteAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCloudRegistrationAwsDeleteAccountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewCloudRegistrationAwsDeleteAccountMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCloudRegistrationAwsDeleteAccountBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCloudRegistrationAwsDeleteAccountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCloudRegistrationAwsDeleteAccountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCloudRegistrationAwsDeleteAccountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /cloud-security-registration-aws/entities/account/v1] cloud-registration-aws-delete-account", response, response.Code())
	}
}

// NewCloudRegistrationAwsDeleteAccountOK creates a CloudRegistrationAwsDeleteAccountOK with default headers values
func NewCloudRegistrationAwsDeleteAccountOK() *CloudRegistrationAwsDeleteAccountOK {
	return &CloudRegistrationAwsDeleteAccountOK{}
}

/*
CloudRegistrationAwsDeleteAccountOK describes a response with status code 200, with default header values.

OK
*/
type CloudRegistrationAwsDeleteAccountOK struct {

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

// IsSuccess returns true when this cloud registration aws delete account o k response has a 2xx status code
func (o *CloudRegistrationAwsDeleteAccountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cloud registration aws delete account o k response has a 3xx status code
func (o *CloudRegistrationAwsDeleteAccountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cloud registration aws delete account o k response has a 4xx status code
func (o *CloudRegistrationAwsDeleteAccountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cloud registration aws delete account o k response has a 5xx status code
func (o *CloudRegistrationAwsDeleteAccountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this cloud registration aws delete account o k response a status code equal to that given
func (o *CloudRegistrationAwsDeleteAccountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the cloud registration aws delete account o k response
func (o *CloudRegistrationAwsDeleteAccountOK) Code() int {
	return 200
}

func (o *CloudRegistrationAwsDeleteAccountOK) Error() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountOK  %+v", 200, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountOK) String() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountOK  %+v", 200, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountOK) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CloudRegistrationAwsDeleteAccountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCloudRegistrationAwsDeleteAccountMultiStatus creates a CloudRegistrationAwsDeleteAccountMultiStatus with default headers values
func NewCloudRegistrationAwsDeleteAccountMultiStatus() *CloudRegistrationAwsDeleteAccountMultiStatus {
	return &CloudRegistrationAwsDeleteAccountMultiStatus{}
}

/*
CloudRegistrationAwsDeleteAccountMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type CloudRegistrationAwsDeleteAccountMultiStatus struct {

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

// IsSuccess returns true when this cloud registration aws delete account multi status response has a 2xx status code
func (o *CloudRegistrationAwsDeleteAccountMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cloud registration aws delete account multi status response has a 3xx status code
func (o *CloudRegistrationAwsDeleteAccountMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cloud registration aws delete account multi status response has a 4xx status code
func (o *CloudRegistrationAwsDeleteAccountMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this cloud registration aws delete account multi status response has a 5xx status code
func (o *CloudRegistrationAwsDeleteAccountMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this cloud registration aws delete account multi status response a status code equal to that given
func (o *CloudRegistrationAwsDeleteAccountMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the cloud registration aws delete account multi status response
func (o *CloudRegistrationAwsDeleteAccountMultiStatus) Code() int {
	return 207
}

func (o *CloudRegistrationAwsDeleteAccountMultiStatus) Error() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountMultiStatus) String() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountMultiStatus) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CloudRegistrationAwsDeleteAccountMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCloudRegistrationAwsDeleteAccountBadRequest creates a CloudRegistrationAwsDeleteAccountBadRequest with default headers values
func NewCloudRegistrationAwsDeleteAccountBadRequest() *CloudRegistrationAwsDeleteAccountBadRequest {
	return &CloudRegistrationAwsDeleteAccountBadRequest{}
}

/*
CloudRegistrationAwsDeleteAccountBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CloudRegistrationAwsDeleteAccountBadRequest struct {

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

// IsSuccess returns true when this cloud registration aws delete account bad request response has a 2xx status code
func (o *CloudRegistrationAwsDeleteAccountBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cloud registration aws delete account bad request response has a 3xx status code
func (o *CloudRegistrationAwsDeleteAccountBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cloud registration aws delete account bad request response has a 4xx status code
func (o *CloudRegistrationAwsDeleteAccountBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this cloud registration aws delete account bad request response has a 5xx status code
func (o *CloudRegistrationAwsDeleteAccountBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this cloud registration aws delete account bad request response a status code equal to that given
func (o *CloudRegistrationAwsDeleteAccountBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the cloud registration aws delete account bad request response
func (o *CloudRegistrationAwsDeleteAccountBadRequest) Code() int {
	return 400
}

func (o *CloudRegistrationAwsDeleteAccountBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountBadRequest  %+v", 400, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountBadRequest) String() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountBadRequest  %+v", 400, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CloudRegistrationAwsDeleteAccountBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCloudRegistrationAwsDeleteAccountForbidden creates a CloudRegistrationAwsDeleteAccountForbidden with default headers values
func NewCloudRegistrationAwsDeleteAccountForbidden() *CloudRegistrationAwsDeleteAccountForbidden {
	return &CloudRegistrationAwsDeleteAccountForbidden{}
}

/*
CloudRegistrationAwsDeleteAccountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CloudRegistrationAwsDeleteAccountForbidden struct {

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

// IsSuccess returns true when this cloud registration aws delete account forbidden response has a 2xx status code
func (o *CloudRegistrationAwsDeleteAccountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cloud registration aws delete account forbidden response has a 3xx status code
func (o *CloudRegistrationAwsDeleteAccountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cloud registration aws delete account forbidden response has a 4xx status code
func (o *CloudRegistrationAwsDeleteAccountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this cloud registration aws delete account forbidden response has a 5xx status code
func (o *CloudRegistrationAwsDeleteAccountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this cloud registration aws delete account forbidden response a status code equal to that given
func (o *CloudRegistrationAwsDeleteAccountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the cloud registration aws delete account forbidden response
func (o *CloudRegistrationAwsDeleteAccountForbidden) Code() int {
	return 403
}

func (o *CloudRegistrationAwsDeleteAccountForbidden) Error() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountForbidden  %+v", 403, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountForbidden) String() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountForbidden  %+v", 403, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountForbidden) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CloudRegistrationAwsDeleteAccountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCloudRegistrationAwsDeleteAccountTooManyRequests creates a CloudRegistrationAwsDeleteAccountTooManyRequests with default headers values
func NewCloudRegistrationAwsDeleteAccountTooManyRequests() *CloudRegistrationAwsDeleteAccountTooManyRequests {
	return &CloudRegistrationAwsDeleteAccountTooManyRequests{}
}

/*
CloudRegistrationAwsDeleteAccountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CloudRegistrationAwsDeleteAccountTooManyRequests struct {

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

// IsSuccess returns true when this cloud registration aws delete account too many requests response has a 2xx status code
func (o *CloudRegistrationAwsDeleteAccountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cloud registration aws delete account too many requests response has a 3xx status code
func (o *CloudRegistrationAwsDeleteAccountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cloud registration aws delete account too many requests response has a 4xx status code
func (o *CloudRegistrationAwsDeleteAccountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this cloud registration aws delete account too many requests response has a 5xx status code
func (o *CloudRegistrationAwsDeleteAccountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this cloud registration aws delete account too many requests response a status code equal to that given
func (o *CloudRegistrationAwsDeleteAccountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the cloud registration aws delete account too many requests response
func (o *CloudRegistrationAwsDeleteAccountTooManyRequests) Code() int {
	return 429
}

func (o *CloudRegistrationAwsDeleteAccountTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CloudRegistrationAwsDeleteAccountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCloudRegistrationAwsDeleteAccountInternalServerError creates a CloudRegistrationAwsDeleteAccountInternalServerError with default headers values
func NewCloudRegistrationAwsDeleteAccountInternalServerError() *CloudRegistrationAwsDeleteAccountInternalServerError {
	return &CloudRegistrationAwsDeleteAccountInternalServerError{}
}

/*
CloudRegistrationAwsDeleteAccountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CloudRegistrationAwsDeleteAccountInternalServerError struct {

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

// IsSuccess returns true when this cloud registration aws delete account internal server error response has a 2xx status code
func (o *CloudRegistrationAwsDeleteAccountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cloud registration aws delete account internal server error response has a 3xx status code
func (o *CloudRegistrationAwsDeleteAccountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cloud registration aws delete account internal server error response has a 4xx status code
func (o *CloudRegistrationAwsDeleteAccountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this cloud registration aws delete account internal server error response has a 5xx status code
func (o *CloudRegistrationAwsDeleteAccountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this cloud registration aws delete account internal server error response a status code equal to that given
func (o *CloudRegistrationAwsDeleteAccountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the cloud registration aws delete account internal server error response
func (o *CloudRegistrationAwsDeleteAccountInternalServerError) Code() int {
	return 500
}

func (o *CloudRegistrationAwsDeleteAccountInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /cloud-security-registration-aws/entities/account/v1][%d] cloudRegistrationAwsDeleteAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *CloudRegistrationAwsDeleteAccountInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CloudRegistrationAwsDeleteAccountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
