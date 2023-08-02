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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// GetCSPMAzureAccountReader is a Reader for the GetCSPMAzureAccount structure.
type GetCSPMAzureAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetCSPMAzureAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetCSPMAzureAccountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewGetCSPMAzureAccountMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetCSPMAzureAccountBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetCSPMAzureAccountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetCSPMAzureAccountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetCSPMAzureAccountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /cloud-connect-cspm-azure/entities/account/v1] GetCSPMAzureAccount", response, response.Code())
	}
}

// NewGetCSPMAzureAccountOK creates a GetCSPMAzureAccountOK with default headers values
func NewGetCSPMAzureAccountOK() *GetCSPMAzureAccountOK {
	return &GetCSPMAzureAccountOK{}
}

/*
GetCSPMAzureAccountOK describes a response with status code 200, with default header values.

OK
*/
type GetCSPMAzureAccountOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAzureAccountResponseV1
}

// IsSuccess returns true when this get c s p m azure account o k response has a 2xx status code
func (o *GetCSPMAzureAccountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get c s p m azure account o k response has a 3xx status code
func (o *GetCSPMAzureAccountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get c s p m azure account o k response has a 4xx status code
func (o *GetCSPMAzureAccountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get c s p m azure account o k response has a 5xx status code
func (o *GetCSPMAzureAccountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get c s p m azure account o k response a status code equal to that given
func (o *GetCSPMAzureAccountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get c s p m azure account o k response
func (o *GetCSPMAzureAccountOK) Code() int {
	return 200
}

func (o *GetCSPMAzureAccountOK) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountOK  %+v", 200, o.Payload)
}

func (o *GetCSPMAzureAccountOK) String() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountOK  %+v", 200, o.Payload)
}

func (o *GetCSPMAzureAccountOK) GetPayload() *models.RegistrationAzureAccountResponseV1 {
	return o.Payload
}

func (o *GetCSPMAzureAccountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAzureAccountResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCSPMAzureAccountMultiStatus creates a GetCSPMAzureAccountMultiStatus with default headers values
func NewGetCSPMAzureAccountMultiStatus() *GetCSPMAzureAccountMultiStatus {
	return &GetCSPMAzureAccountMultiStatus{}
}

/*
GetCSPMAzureAccountMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type GetCSPMAzureAccountMultiStatus struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAzureAccountResponseV1
}

// IsSuccess returns true when this get c s p m azure account multi status response has a 2xx status code
func (o *GetCSPMAzureAccountMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get c s p m azure account multi status response has a 3xx status code
func (o *GetCSPMAzureAccountMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get c s p m azure account multi status response has a 4xx status code
func (o *GetCSPMAzureAccountMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this get c s p m azure account multi status response has a 5xx status code
func (o *GetCSPMAzureAccountMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this get c s p m azure account multi status response a status code equal to that given
func (o *GetCSPMAzureAccountMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the get c s p m azure account multi status response
func (o *GetCSPMAzureAccountMultiStatus) Code() int {
	return 207
}

func (o *GetCSPMAzureAccountMultiStatus) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *GetCSPMAzureAccountMultiStatus) String() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *GetCSPMAzureAccountMultiStatus) GetPayload() *models.RegistrationAzureAccountResponseV1 {
	return o.Payload
}

func (o *GetCSPMAzureAccountMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAzureAccountResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCSPMAzureAccountBadRequest creates a GetCSPMAzureAccountBadRequest with default headers values
func NewGetCSPMAzureAccountBadRequest() *GetCSPMAzureAccountBadRequest {
	return &GetCSPMAzureAccountBadRequest{}
}

/*
GetCSPMAzureAccountBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetCSPMAzureAccountBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAzureAccountResponseV1
}

// IsSuccess returns true when this get c s p m azure account bad request response has a 2xx status code
func (o *GetCSPMAzureAccountBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get c s p m azure account bad request response has a 3xx status code
func (o *GetCSPMAzureAccountBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get c s p m azure account bad request response has a 4xx status code
func (o *GetCSPMAzureAccountBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get c s p m azure account bad request response has a 5xx status code
func (o *GetCSPMAzureAccountBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get c s p m azure account bad request response a status code equal to that given
func (o *GetCSPMAzureAccountBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get c s p m azure account bad request response
func (o *GetCSPMAzureAccountBadRequest) Code() int {
	return 400
}

func (o *GetCSPMAzureAccountBadRequest) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountBadRequest  %+v", 400, o.Payload)
}

func (o *GetCSPMAzureAccountBadRequest) String() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountBadRequest  %+v", 400, o.Payload)
}

func (o *GetCSPMAzureAccountBadRequest) GetPayload() *models.RegistrationAzureAccountResponseV1 {
	return o.Payload
}

func (o *GetCSPMAzureAccountBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAzureAccountResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCSPMAzureAccountForbidden creates a GetCSPMAzureAccountForbidden with default headers values
func NewGetCSPMAzureAccountForbidden() *GetCSPMAzureAccountForbidden {
	return &GetCSPMAzureAccountForbidden{}
}

/*
GetCSPMAzureAccountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetCSPMAzureAccountForbidden struct {

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

// IsSuccess returns true when this get c s p m azure account forbidden response has a 2xx status code
func (o *GetCSPMAzureAccountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get c s p m azure account forbidden response has a 3xx status code
func (o *GetCSPMAzureAccountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get c s p m azure account forbidden response has a 4xx status code
func (o *GetCSPMAzureAccountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get c s p m azure account forbidden response has a 5xx status code
func (o *GetCSPMAzureAccountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get c s p m azure account forbidden response a status code equal to that given
func (o *GetCSPMAzureAccountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get c s p m azure account forbidden response
func (o *GetCSPMAzureAccountForbidden) Code() int {
	return 403
}

func (o *GetCSPMAzureAccountForbidden) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountForbidden  %+v", 403, o.Payload)
}

func (o *GetCSPMAzureAccountForbidden) String() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountForbidden  %+v", 403, o.Payload)
}

func (o *GetCSPMAzureAccountForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetCSPMAzureAccountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetCSPMAzureAccountTooManyRequests creates a GetCSPMAzureAccountTooManyRequests with default headers values
func NewGetCSPMAzureAccountTooManyRequests() *GetCSPMAzureAccountTooManyRequests {
	return &GetCSPMAzureAccountTooManyRequests{}
}

/*
GetCSPMAzureAccountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetCSPMAzureAccountTooManyRequests struct {

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

// IsSuccess returns true when this get c s p m azure account too many requests response has a 2xx status code
func (o *GetCSPMAzureAccountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get c s p m azure account too many requests response has a 3xx status code
func (o *GetCSPMAzureAccountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get c s p m azure account too many requests response has a 4xx status code
func (o *GetCSPMAzureAccountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get c s p m azure account too many requests response has a 5xx status code
func (o *GetCSPMAzureAccountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get c s p m azure account too many requests response a status code equal to that given
func (o *GetCSPMAzureAccountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get c s p m azure account too many requests response
func (o *GetCSPMAzureAccountTooManyRequests) Code() int {
	return 429
}

func (o *GetCSPMAzureAccountTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetCSPMAzureAccountTooManyRequests) String() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetCSPMAzureAccountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetCSPMAzureAccountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetCSPMAzureAccountInternalServerError creates a GetCSPMAzureAccountInternalServerError with default headers values
func NewGetCSPMAzureAccountInternalServerError() *GetCSPMAzureAccountInternalServerError {
	return &GetCSPMAzureAccountInternalServerError{}
}

/*
GetCSPMAzureAccountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetCSPMAzureAccountInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAzureAccountResponseV1
}

// IsSuccess returns true when this get c s p m azure account internal server error response has a 2xx status code
func (o *GetCSPMAzureAccountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get c s p m azure account internal server error response has a 3xx status code
func (o *GetCSPMAzureAccountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get c s p m azure account internal server error response has a 4xx status code
func (o *GetCSPMAzureAccountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get c s p m azure account internal server error response has a 5xx status code
func (o *GetCSPMAzureAccountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get c s p m azure account internal server error response a status code equal to that given
func (o *GetCSPMAzureAccountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get c s p m azure account internal server error response
func (o *GetCSPMAzureAccountInternalServerError) Code() int {
	return 500
}

func (o *GetCSPMAzureAccountInternalServerError) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *GetCSPMAzureAccountInternalServerError) String() string {
	return fmt.Sprintf("[GET /cloud-connect-cspm-azure/entities/account/v1][%d] getCSPMAzureAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *GetCSPMAzureAccountInternalServerError) GetPayload() *models.RegistrationAzureAccountResponseV1 {
	return o.Payload
}

func (o *GetCSPMAzureAccountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAzureAccountResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
