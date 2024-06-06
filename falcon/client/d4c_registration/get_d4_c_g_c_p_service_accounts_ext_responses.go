// Code generated by go-swagger; DO NOT EDIT.

package d4c_registration

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

// GetD4CGCPServiceAccountsExtReader is a Reader for the GetD4CGCPServiceAccountsExt structure.
type GetD4CGCPServiceAccountsExtReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetD4CGCPServiceAccountsExtReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetD4CGCPServiceAccountsExtOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetD4CGCPServiceAccountsExtBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetD4CGCPServiceAccountsExtForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetD4CGCPServiceAccountsExtTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetD4CGCPServiceAccountsExtInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /cloud-connect-gcp/entities/service-accounts/v1] GetD4CGCPServiceAccountsExt", response, response.Code())
	}
}

// NewGetD4CGCPServiceAccountsExtOK creates a GetD4CGCPServiceAccountsExtOK with default headers values
func NewGetD4CGCPServiceAccountsExtOK() *GetD4CGCPServiceAccountsExtOK {
	return &GetD4CGCPServiceAccountsExtOK{}
}

/*
GetD4CGCPServiceAccountsExtOK describes a response with status code 200, with default header values.

OK
*/
type GetD4CGCPServiceAccountsExtOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationGCPServiceAccountResponseExtV1
}

// IsSuccess returns true when this get d4 c g c p service accounts ext o k response has a 2xx status code
func (o *GetD4CGCPServiceAccountsExtOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get d4 c g c p service accounts ext o k response has a 3xx status code
func (o *GetD4CGCPServiceAccountsExtOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get d4 c g c p service accounts ext o k response has a 4xx status code
func (o *GetD4CGCPServiceAccountsExtOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get d4 c g c p service accounts ext o k response has a 5xx status code
func (o *GetD4CGCPServiceAccountsExtOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get d4 c g c p service accounts ext o k response a status code equal to that given
func (o *GetD4CGCPServiceAccountsExtOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get d4 c g c p service accounts ext o k response
func (o *GetD4CGCPServiceAccountsExtOK) Code() int {
	return 200
}

func (o *GetD4CGCPServiceAccountsExtOK) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-gcp/entities/service-accounts/v1][%d] getD4CGCPServiceAccountsExtOK  %+v", 200, o.Payload)
}

func (o *GetD4CGCPServiceAccountsExtOK) String() string {
	return fmt.Sprintf("[GET /cloud-connect-gcp/entities/service-accounts/v1][%d] getD4CGCPServiceAccountsExtOK  %+v", 200, o.Payload)
}

func (o *GetD4CGCPServiceAccountsExtOK) GetPayload() *models.RegistrationGCPServiceAccountResponseExtV1 {
	return o.Payload
}

func (o *GetD4CGCPServiceAccountsExtOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationGCPServiceAccountResponseExtV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetD4CGCPServiceAccountsExtBadRequest creates a GetD4CGCPServiceAccountsExtBadRequest with default headers values
func NewGetD4CGCPServiceAccountsExtBadRequest() *GetD4CGCPServiceAccountsExtBadRequest {
	return &GetD4CGCPServiceAccountsExtBadRequest{}
}

/*
GetD4CGCPServiceAccountsExtBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetD4CGCPServiceAccountsExtBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationGCPServiceAccountResponseExtV1
}

// IsSuccess returns true when this get d4 c g c p service accounts ext bad request response has a 2xx status code
func (o *GetD4CGCPServiceAccountsExtBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get d4 c g c p service accounts ext bad request response has a 3xx status code
func (o *GetD4CGCPServiceAccountsExtBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get d4 c g c p service accounts ext bad request response has a 4xx status code
func (o *GetD4CGCPServiceAccountsExtBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get d4 c g c p service accounts ext bad request response has a 5xx status code
func (o *GetD4CGCPServiceAccountsExtBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get d4 c g c p service accounts ext bad request response a status code equal to that given
func (o *GetD4CGCPServiceAccountsExtBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get d4 c g c p service accounts ext bad request response
func (o *GetD4CGCPServiceAccountsExtBadRequest) Code() int {
	return 400
}

func (o *GetD4CGCPServiceAccountsExtBadRequest) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-gcp/entities/service-accounts/v1][%d] getD4CGCPServiceAccountsExtBadRequest  %+v", 400, o.Payload)
}

func (o *GetD4CGCPServiceAccountsExtBadRequest) String() string {
	return fmt.Sprintf("[GET /cloud-connect-gcp/entities/service-accounts/v1][%d] getD4CGCPServiceAccountsExtBadRequest  %+v", 400, o.Payload)
}

func (o *GetD4CGCPServiceAccountsExtBadRequest) GetPayload() *models.RegistrationGCPServiceAccountResponseExtV1 {
	return o.Payload
}

func (o *GetD4CGCPServiceAccountsExtBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationGCPServiceAccountResponseExtV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetD4CGCPServiceAccountsExtForbidden creates a GetD4CGCPServiceAccountsExtForbidden with default headers values
func NewGetD4CGCPServiceAccountsExtForbidden() *GetD4CGCPServiceAccountsExtForbidden {
	return &GetD4CGCPServiceAccountsExtForbidden{}
}

/*
GetD4CGCPServiceAccountsExtForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetD4CGCPServiceAccountsExtForbidden struct {

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

// IsSuccess returns true when this get d4 c g c p service accounts ext forbidden response has a 2xx status code
func (o *GetD4CGCPServiceAccountsExtForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get d4 c g c p service accounts ext forbidden response has a 3xx status code
func (o *GetD4CGCPServiceAccountsExtForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get d4 c g c p service accounts ext forbidden response has a 4xx status code
func (o *GetD4CGCPServiceAccountsExtForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get d4 c g c p service accounts ext forbidden response has a 5xx status code
func (o *GetD4CGCPServiceAccountsExtForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get d4 c g c p service accounts ext forbidden response a status code equal to that given
func (o *GetD4CGCPServiceAccountsExtForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get d4 c g c p service accounts ext forbidden response
func (o *GetD4CGCPServiceAccountsExtForbidden) Code() int {
	return 403
}

func (o *GetD4CGCPServiceAccountsExtForbidden) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-gcp/entities/service-accounts/v1][%d] getD4CGCPServiceAccountsExtForbidden  %+v", 403, o.Payload)
}

func (o *GetD4CGCPServiceAccountsExtForbidden) String() string {
	return fmt.Sprintf("[GET /cloud-connect-gcp/entities/service-accounts/v1][%d] getD4CGCPServiceAccountsExtForbidden  %+v", 403, o.Payload)
}

func (o *GetD4CGCPServiceAccountsExtForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetD4CGCPServiceAccountsExtForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetD4CGCPServiceAccountsExtTooManyRequests creates a GetD4CGCPServiceAccountsExtTooManyRequests with default headers values
func NewGetD4CGCPServiceAccountsExtTooManyRequests() *GetD4CGCPServiceAccountsExtTooManyRequests {
	return &GetD4CGCPServiceAccountsExtTooManyRequests{}
}

/*
GetD4CGCPServiceAccountsExtTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetD4CGCPServiceAccountsExtTooManyRequests struct {

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

// IsSuccess returns true when this get d4 c g c p service accounts ext too many requests response has a 2xx status code
func (o *GetD4CGCPServiceAccountsExtTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get d4 c g c p service accounts ext too many requests response has a 3xx status code
func (o *GetD4CGCPServiceAccountsExtTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get d4 c g c p service accounts ext too many requests response has a 4xx status code
func (o *GetD4CGCPServiceAccountsExtTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get d4 c g c p service accounts ext too many requests response has a 5xx status code
func (o *GetD4CGCPServiceAccountsExtTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get d4 c g c p service accounts ext too many requests response a status code equal to that given
func (o *GetD4CGCPServiceAccountsExtTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get d4 c g c p service accounts ext too many requests response
func (o *GetD4CGCPServiceAccountsExtTooManyRequests) Code() int {
	return 429
}

func (o *GetD4CGCPServiceAccountsExtTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-gcp/entities/service-accounts/v1][%d] getD4CGCPServiceAccountsExtTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetD4CGCPServiceAccountsExtTooManyRequests) String() string {
	return fmt.Sprintf("[GET /cloud-connect-gcp/entities/service-accounts/v1][%d] getD4CGCPServiceAccountsExtTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetD4CGCPServiceAccountsExtTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetD4CGCPServiceAccountsExtTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetD4CGCPServiceAccountsExtInternalServerError creates a GetD4CGCPServiceAccountsExtInternalServerError with default headers values
func NewGetD4CGCPServiceAccountsExtInternalServerError() *GetD4CGCPServiceAccountsExtInternalServerError {
	return &GetD4CGCPServiceAccountsExtInternalServerError{}
}

/*
GetD4CGCPServiceAccountsExtInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetD4CGCPServiceAccountsExtInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationGCPServiceAccountResponseExtV1
}

// IsSuccess returns true when this get d4 c g c p service accounts ext internal server error response has a 2xx status code
func (o *GetD4CGCPServiceAccountsExtInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get d4 c g c p service accounts ext internal server error response has a 3xx status code
func (o *GetD4CGCPServiceAccountsExtInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get d4 c g c p service accounts ext internal server error response has a 4xx status code
func (o *GetD4CGCPServiceAccountsExtInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get d4 c g c p service accounts ext internal server error response has a 5xx status code
func (o *GetD4CGCPServiceAccountsExtInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get d4 c g c p service accounts ext internal server error response a status code equal to that given
func (o *GetD4CGCPServiceAccountsExtInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get d4 c g c p service accounts ext internal server error response
func (o *GetD4CGCPServiceAccountsExtInternalServerError) Code() int {
	return 500
}

func (o *GetD4CGCPServiceAccountsExtInternalServerError) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-gcp/entities/service-accounts/v1][%d] getD4CGCPServiceAccountsExtInternalServerError  %+v", 500, o.Payload)
}

func (o *GetD4CGCPServiceAccountsExtInternalServerError) String() string {
	return fmt.Sprintf("[GET /cloud-connect-gcp/entities/service-accounts/v1][%d] getD4CGCPServiceAccountsExtInternalServerError  %+v", 500, o.Payload)
}

func (o *GetD4CGCPServiceAccountsExtInternalServerError) GetPayload() *models.RegistrationGCPServiceAccountResponseExtV1 {
	return o.Payload
}

func (o *GetD4CGCPServiceAccountsExtInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationGCPServiceAccountResponseExtV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
