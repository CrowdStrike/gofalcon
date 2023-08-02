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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// CreateD4CAwsAccountReader is a Reader for the CreateD4CAwsAccount structure.
type CreateD4CAwsAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateD4CAwsAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateD4CAwsAccountCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewCreateD4CAwsAccountMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateD4CAwsAccountBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateD4CAwsAccountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateD4CAwsAccountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateD4CAwsAccountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /cloud-connect-aws/entities/account/v2] CreateD4CAwsAccount", response, response.Code())
	}
}

// NewCreateD4CAwsAccountCreated creates a CreateD4CAwsAccountCreated with default headers values
func NewCreateD4CAwsAccountCreated() *CreateD4CAwsAccountCreated {
	return &CreateD4CAwsAccountCreated{}
}

/*
CreateD4CAwsAccountCreated describes a response with status code 201, with default header values.

Created
*/
type CreateD4CAwsAccountCreated struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAWSAccountResponseV2
}

// IsSuccess returns true when this create d4 c aws account created response has a 2xx status code
func (o *CreateD4CAwsAccountCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create d4 c aws account created response has a 3xx status code
func (o *CreateD4CAwsAccountCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create d4 c aws account created response has a 4xx status code
func (o *CreateD4CAwsAccountCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create d4 c aws account created response has a 5xx status code
func (o *CreateD4CAwsAccountCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create d4 c aws account created response a status code equal to that given
func (o *CreateD4CAwsAccountCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create d4 c aws account created response
func (o *CreateD4CAwsAccountCreated) Code() int {
	return 201
}

func (o *CreateD4CAwsAccountCreated) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountCreated  %+v", 201, o.Payload)
}

func (o *CreateD4CAwsAccountCreated) String() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountCreated  %+v", 201, o.Payload)
}

func (o *CreateD4CAwsAccountCreated) GetPayload() *models.RegistrationAWSAccountResponseV2 {
	return o.Payload
}

func (o *CreateD4CAwsAccountCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAWSAccountResponseV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateD4CAwsAccountMultiStatus creates a CreateD4CAwsAccountMultiStatus with default headers values
func NewCreateD4CAwsAccountMultiStatus() *CreateD4CAwsAccountMultiStatus {
	return &CreateD4CAwsAccountMultiStatus{}
}

/*
CreateD4CAwsAccountMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type CreateD4CAwsAccountMultiStatus struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAWSAccountResponseV2
}

// IsSuccess returns true when this create d4 c aws account multi status response has a 2xx status code
func (o *CreateD4CAwsAccountMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create d4 c aws account multi status response has a 3xx status code
func (o *CreateD4CAwsAccountMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create d4 c aws account multi status response has a 4xx status code
func (o *CreateD4CAwsAccountMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this create d4 c aws account multi status response has a 5xx status code
func (o *CreateD4CAwsAccountMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this create d4 c aws account multi status response a status code equal to that given
func (o *CreateD4CAwsAccountMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the create d4 c aws account multi status response
func (o *CreateD4CAwsAccountMultiStatus) Code() int {
	return 207
}

func (o *CreateD4CAwsAccountMultiStatus) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *CreateD4CAwsAccountMultiStatus) String() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *CreateD4CAwsAccountMultiStatus) GetPayload() *models.RegistrationAWSAccountResponseV2 {
	return o.Payload
}

func (o *CreateD4CAwsAccountMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAWSAccountResponseV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateD4CAwsAccountBadRequest creates a CreateD4CAwsAccountBadRequest with default headers values
func NewCreateD4CAwsAccountBadRequest() *CreateD4CAwsAccountBadRequest {
	return &CreateD4CAwsAccountBadRequest{}
}

/*
CreateD4CAwsAccountBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CreateD4CAwsAccountBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAWSAccountResponseV2
}

// IsSuccess returns true when this create d4 c aws account bad request response has a 2xx status code
func (o *CreateD4CAwsAccountBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create d4 c aws account bad request response has a 3xx status code
func (o *CreateD4CAwsAccountBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create d4 c aws account bad request response has a 4xx status code
func (o *CreateD4CAwsAccountBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create d4 c aws account bad request response has a 5xx status code
func (o *CreateD4CAwsAccountBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create d4 c aws account bad request response a status code equal to that given
func (o *CreateD4CAwsAccountBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create d4 c aws account bad request response
func (o *CreateD4CAwsAccountBadRequest) Code() int {
	return 400
}

func (o *CreateD4CAwsAccountBadRequest) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountBadRequest  %+v", 400, o.Payload)
}

func (o *CreateD4CAwsAccountBadRequest) String() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountBadRequest  %+v", 400, o.Payload)
}

func (o *CreateD4CAwsAccountBadRequest) GetPayload() *models.RegistrationAWSAccountResponseV2 {
	return o.Payload
}

func (o *CreateD4CAwsAccountBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAWSAccountResponseV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateD4CAwsAccountForbidden creates a CreateD4CAwsAccountForbidden with default headers values
func NewCreateD4CAwsAccountForbidden() *CreateD4CAwsAccountForbidden {
	return &CreateD4CAwsAccountForbidden{}
}

/*
CreateD4CAwsAccountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateD4CAwsAccountForbidden struct {

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

// IsSuccess returns true when this create d4 c aws account forbidden response has a 2xx status code
func (o *CreateD4CAwsAccountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create d4 c aws account forbidden response has a 3xx status code
func (o *CreateD4CAwsAccountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create d4 c aws account forbidden response has a 4xx status code
func (o *CreateD4CAwsAccountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create d4 c aws account forbidden response has a 5xx status code
func (o *CreateD4CAwsAccountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create d4 c aws account forbidden response a status code equal to that given
func (o *CreateD4CAwsAccountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create d4 c aws account forbidden response
func (o *CreateD4CAwsAccountForbidden) Code() int {
	return 403
}

func (o *CreateD4CAwsAccountForbidden) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountForbidden  %+v", 403, o.Payload)
}

func (o *CreateD4CAwsAccountForbidden) String() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountForbidden  %+v", 403, o.Payload)
}

func (o *CreateD4CAwsAccountForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateD4CAwsAccountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateD4CAwsAccountTooManyRequests creates a CreateD4CAwsAccountTooManyRequests with default headers values
func NewCreateD4CAwsAccountTooManyRequests() *CreateD4CAwsAccountTooManyRequests {
	return &CreateD4CAwsAccountTooManyRequests{}
}

/*
CreateD4CAwsAccountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateD4CAwsAccountTooManyRequests struct {

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

// IsSuccess returns true when this create d4 c aws account too many requests response has a 2xx status code
func (o *CreateD4CAwsAccountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create d4 c aws account too many requests response has a 3xx status code
func (o *CreateD4CAwsAccountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create d4 c aws account too many requests response has a 4xx status code
func (o *CreateD4CAwsAccountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create d4 c aws account too many requests response has a 5xx status code
func (o *CreateD4CAwsAccountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create d4 c aws account too many requests response a status code equal to that given
func (o *CreateD4CAwsAccountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create d4 c aws account too many requests response
func (o *CreateD4CAwsAccountTooManyRequests) Code() int {
	return 429
}

func (o *CreateD4CAwsAccountTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateD4CAwsAccountTooManyRequests) String() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateD4CAwsAccountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateD4CAwsAccountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateD4CAwsAccountInternalServerError creates a CreateD4CAwsAccountInternalServerError with default headers values
func NewCreateD4CAwsAccountInternalServerError() *CreateD4CAwsAccountInternalServerError {
	return &CreateD4CAwsAccountInternalServerError{}
}

/*
CreateD4CAwsAccountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateD4CAwsAccountInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAWSAccountResponseV2
}

// IsSuccess returns true when this create d4 c aws account internal server error response has a 2xx status code
func (o *CreateD4CAwsAccountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create d4 c aws account internal server error response has a 3xx status code
func (o *CreateD4CAwsAccountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create d4 c aws account internal server error response has a 4xx status code
func (o *CreateD4CAwsAccountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create d4 c aws account internal server error response has a 5xx status code
func (o *CreateD4CAwsAccountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create d4 c aws account internal server error response a status code equal to that given
func (o *CreateD4CAwsAccountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create d4 c aws account internal server error response
func (o *CreateD4CAwsAccountInternalServerError) Code() int {
	return 500
}

func (o *CreateD4CAwsAccountInternalServerError) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateD4CAwsAccountInternalServerError) String() string {
	return fmt.Sprintf("[POST /cloud-connect-aws/entities/account/v2][%d] createD4CAwsAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateD4CAwsAccountInternalServerError) GetPayload() *models.RegistrationAWSAccountResponseV2 {
	return o.Payload
}

func (o *CreateD4CAwsAccountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAWSAccountResponseV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
