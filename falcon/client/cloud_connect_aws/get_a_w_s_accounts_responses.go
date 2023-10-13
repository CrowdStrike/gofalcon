// Code generated by go-swagger; DO NOT EDIT.

package cloud_connect_aws

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

// GetAWSAccountsReader is a Reader for the GetAWSAccounts structure.
type GetAWSAccountsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAWSAccountsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAWSAccountsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAWSAccountsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAWSAccountsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAWSAccountsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAWSAccountsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAWSAccountsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /cloud-connect-aws/entities/accounts/v1] GetAWSAccounts", response, response.Code())
	}
}

// NewGetAWSAccountsOK creates a GetAWSAccountsOK with default headers values
func NewGetAWSAccountsOK() *GetAWSAccountsOK {
	return &GetAWSAccountsOK{}
}

/* GetAWSAccountsOK describes a response with status code 200, with default header values.

OK
*/
type GetAWSAccountsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ModelsAWSAccountsV1
}

// IsSuccess returns true when this get a w s accounts o k response has a 2xx status code
func (o *GetAWSAccountsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get a w s accounts o k response has a 3xx status code
func (o *GetAWSAccountsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get a w s accounts o k response has a 4xx status code
func (o *GetAWSAccountsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get a w s accounts o k response has a 5xx status code
func (o *GetAWSAccountsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get a w s accounts o k response a status code equal to that given
func (o *GetAWSAccountsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get a w s accounts o k response
func (o *GetAWSAccountsOK) Code() int {
	return 200
}

func (o *GetAWSAccountsOK) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsOK  %+v", 200, o.Payload)
}

func (o *GetAWSAccountsOK) String() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsOK  %+v", 200, o.Payload)
}

func (o *GetAWSAccountsOK) GetPayload() *models.ModelsAWSAccountsV1 {
	return o.Payload
}

func (o *GetAWSAccountsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ModelsAWSAccountsV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAWSAccountsBadRequest creates a GetAWSAccountsBadRequest with default headers values
func NewGetAWSAccountsBadRequest() *GetAWSAccountsBadRequest {
	return &GetAWSAccountsBadRequest{}
}

/* GetAWSAccountsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetAWSAccountsBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ModelsAWSAccountsV1
}

// IsSuccess returns true when this get a w s accounts bad request response has a 2xx status code
func (o *GetAWSAccountsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get a w s accounts bad request response has a 3xx status code
func (o *GetAWSAccountsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get a w s accounts bad request response has a 4xx status code
func (o *GetAWSAccountsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get a w s accounts bad request response has a 5xx status code
func (o *GetAWSAccountsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get a w s accounts bad request response a status code equal to that given
func (o *GetAWSAccountsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get a w s accounts bad request response
func (o *GetAWSAccountsBadRequest) Code() int {
	return 400
}

func (o *GetAWSAccountsBadRequest) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsBadRequest  %+v", 400, o.Payload)
}

func (o *GetAWSAccountsBadRequest) String() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsBadRequest  %+v", 400, o.Payload)
}

func (o *GetAWSAccountsBadRequest) GetPayload() *models.ModelsAWSAccountsV1 {
	return o.Payload
}

func (o *GetAWSAccountsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ModelsAWSAccountsV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAWSAccountsForbidden creates a GetAWSAccountsForbidden with default headers values
func NewGetAWSAccountsForbidden() *GetAWSAccountsForbidden {
	return &GetAWSAccountsForbidden{}
}

/* GetAWSAccountsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetAWSAccountsForbidden struct {

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

// IsSuccess returns true when this get a w s accounts forbidden response has a 2xx status code
func (o *GetAWSAccountsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get a w s accounts forbidden response has a 3xx status code
func (o *GetAWSAccountsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get a w s accounts forbidden response has a 4xx status code
func (o *GetAWSAccountsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get a w s accounts forbidden response has a 5xx status code
func (o *GetAWSAccountsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get a w s accounts forbidden response a status code equal to that given
func (o *GetAWSAccountsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get a w s accounts forbidden response
func (o *GetAWSAccountsForbidden) Code() int {
	return 403
}

func (o *GetAWSAccountsForbidden) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsForbidden  %+v", 403, o.Payload)
}

func (o *GetAWSAccountsForbidden) String() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsForbidden  %+v", 403, o.Payload)
}

func (o *GetAWSAccountsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetAWSAccountsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetAWSAccountsNotFound creates a GetAWSAccountsNotFound with default headers values
func NewGetAWSAccountsNotFound() *GetAWSAccountsNotFound {
	return &GetAWSAccountsNotFound{}
}

/* GetAWSAccountsNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetAWSAccountsNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ModelsAWSAccountsV1
}

// IsSuccess returns true when this get a w s accounts not found response has a 2xx status code
func (o *GetAWSAccountsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get a w s accounts not found response has a 3xx status code
func (o *GetAWSAccountsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get a w s accounts not found response has a 4xx status code
func (o *GetAWSAccountsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get a w s accounts not found response has a 5xx status code
func (o *GetAWSAccountsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get a w s accounts not found response a status code equal to that given
func (o *GetAWSAccountsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get a w s accounts not found response
func (o *GetAWSAccountsNotFound) Code() int {
	return 404
}

func (o *GetAWSAccountsNotFound) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsNotFound  %+v", 404, o.Payload)
}

func (o *GetAWSAccountsNotFound) String() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsNotFound  %+v", 404, o.Payload)
}

func (o *GetAWSAccountsNotFound) GetPayload() *models.ModelsAWSAccountsV1 {
	return o.Payload
}

func (o *GetAWSAccountsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ModelsAWSAccountsV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAWSAccountsTooManyRequests creates a GetAWSAccountsTooManyRequests with default headers values
func NewGetAWSAccountsTooManyRequests() *GetAWSAccountsTooManyRequests {
	return &GetAWSAccountsTooManyRequests{}
}

/* GetAWSAccountsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetAWSAccountsTooManyRequests struct {

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

// IsSuccess returns true when this get a w s accounts too many requests response has a 2xx status code
func (o *GetAWSAccountsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get a w s accounts too many requests response has a 3xx status code
func (o *GetAWSAccountsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get a w s accounts too many requests response has a 4xx status code
func (o *GetAWSAccountsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get a w s accounts too many requests response has a 5xx status code
func (o *GetAWSAccountsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get a w s accounts too many requests response a status code equal to that given
func (o *GetAWSAccountsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get a w s accounts too many requests response
func (o *GetAWSAccountsTooManyRequests) Code() int {
	return 429
}

func (o *GetAWSAccountsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAWSAccountsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAWSAccountsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetAWSAccountsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetAWSAccountsInternalServerError creates a GetAWSAccountsInternalServerError with default headers values
func NewGetAWSAccountsInternalServerError() *GetAWSAccountsInternalServerError {
	return &GetAWSAccountsInternalServerError{}
}

/* GetAWSAccountsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetAWSAccountsInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ModelsAWSAccountsV1
}

// IsSuccess returns true when this get a w s accounts internal server error response has a 2xx status code
func (o *GetAWSAccountsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get a w s accounts internal server error response has a 3xx status code
func (o *GetAWSAccountsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get a w s accounts internal server error response has a 4xx status code
func (o *GetAWSAccountsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get a w s accounts internal server error response has a 5xx status code
func (o *GetAWSAccountsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get a w s accounts internal server error response a status code equal to that given
func (o *GetAWSAccountsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get a w s accounts internal server error response
func (o *GetAWSAccountsInternalServerError) Code() int {
	return 500
}

func (o *GetAWSAccountsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsInternalServerError  %+v", 500, o.Payload)
}

func (o *GetAWSAccountsInternalServerError) String() string {
	return fmt.Sprintf("[GET /cloud-connect-aws/entities/accounts/v1][%d] getAWSAccountsInternalServerError  %+v", 500, o.Payload)
}

func (o *GetAWSAccountsInternalServerError) GetPayload() *models.ModelsAWSAccountsV1 {
	return o.Payload
}

func (o *GetAWSAccountsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ModelsAWSAccountsV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
