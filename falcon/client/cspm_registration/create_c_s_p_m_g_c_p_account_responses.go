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

// CreateCSPMGCPAccountReader is a Reader for the CreateCSPMGCPAccount structure.
type CreateCSPMGCPAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateCSPMGCPAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateCSPMGCPAccountCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewCreateCSPMGCPAccountMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateCSPMGCPAccountBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateCSPMGCPAccountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateCSPMGCPAccountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateCSPMGCPAccountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /cloud-connect-cspm-gcp/entities/account/v1] CreateCSPMGCPAccount", response, response.Code())
	}
}

// NewCreateCSPMGCPAccountCreated creates a CreateCSPMGCPAccountCreated with default headers values
func NewCreateCSPMGCPAccountCreated() *CreateCSPMGCPAccountCreated {
	return &CreateCSPMGCPAccountCreated{}
}

/*
CreateCSPMGCPAccountCreated describes a response with status code 201, with default header values.

Created
*/
type CreateCSPMGCPAccountCreated struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationGCPAccountResponseV1
}

// IsSuccess returns true when this create c s p m g c p account created response has a 2xx status code
func (o *CreateCSPMGCPAccountCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create c s p m g c p account created response has a 3xx status code
func (o *CreateCSPMGCPAccountCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m g c p account created response has a 4xx status code
func (o *CreateCSPMGCPAccountCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create c s p m g c p account created response has a 5xx status code
func (o *CreateCSPMGCPAccountCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create c s p m g c p account created response a status code equal to that given
func (o *CreateCSPMGCPAccountCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create c s p m g c p account created response
func (o *CreateCSPMGCPAccountCreated) Code() int {
	return 201
}

func (o *CreateCSPMGCPAccountCreated) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountCreated  %+v", 201, o.Payload)
}

func (o *CreateCSPMGCPAccountCreated) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountCreated  %+v", 201, o.Payload)
}

func (o *CreateCSPMGCPAccountCreated) GetPayload() *models.RegistrationGCPAccountResponseV1 {
	return o.Payload
}

func (o *CreateCSPMGCPAccountCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationGCPAccountResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCSPMGCPAccountMultiStatus creates a CreateCSPMGCPAccountMultiStatus with default headers values
func NewCreateCSPMGCPAccountMultiStatus() *CreateCSPMGCPAccountMultiStatus {
	return &CreateCSPMGCPAccountMultiStatus{}
}

/*
CreateCSPMGCPAccountMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type CreateCSPMGCPAccountMultiStatus struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationGCPAccountResponseV1
}

// IsSuccess returns true when this create c s p m g c p account multi status response has a 2xx status code
func (o *CreateCSPMGCPAccountMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create c s p m g c p account multi status response has a 3xx status code
func (o *CreateCSPMGCPAccountMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m g c p account multi status response has a 4xx status code
func (o *CreateCSPMGCPAccountMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this create c s p m g c p account multi status response has a 5xx status code
func (o *CreateCSPMGCPAccountMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this create c s p m g c p account multi status response a status code equal to that given
func (o *CreateCSPMGCPAccountMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the create c s p m g c p account multi status response
func (o *CreateCSPMGCPAccountMultiStatus) Code() int {
	return 207
}

func (o *CreateCSPMGCPAccountMultiStatus) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *CreateCSPMGCPAccountMultiStatus) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *CreateCSPMGCPAccountMultiStatus) GetPayload() *models.RegistrationGCPAccountResponseV1 {
	return o.Payload
}

func (o *CreateCSPMGCPAccountMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationGCPAccountResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCSPMGCPAccountBadRequest creates a CreateCSPMGCPAccountBadRequest with default headers values
func NewCreateCSPMGCPAccountBadRequest() *CreateCSPMGCPAccountBadRequest {
	return &CreateCSPMGCPAccountBadRequest{}
}

/*
CreateCSPMGCPAccountBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CreateCSPMGCPAccountBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationGCPAccountResponseV1
}

// IsSuccess returns true when this create c s p m g c p account bad request response has a 2xx status code
func (o *CreateCSPMGCPAccountBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create c s p m g c p account bad request response has a 3xx status code
func (o *CreateCSPMGCPAccountBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m g c p account bad request response has a 4xx status code
func (o *CreateCSPMGCPAccountBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create c s p m g c p account bad request response has a 5xx status code
func (o *CreateCSPMGCPAccountBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create c s p m g c p account bad request response a status code equal to that given
func (o *CreateCSPMGCPAccountBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create c s p m g c p account bad request response
func (o *CreateCSPMGCPAccountBadRequest) Code() int {
	return 400
}

func (o *CreateCSPMGCPAccountBadRequest) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountBadRequest  %+v", 400, o.Payload)
}

func (o *CreateCSPMGCPAccountBadRequest) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountBadRequest  %+v", 400, o.Payload)
}

func (o *CreateCSPMGCPAccountBadRequest) GetPayload() *models.RegistrationGCPAccountResponseV1 {
	return o.Payload
}

func (o *CreateCSPMGCPAccountBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationGCPAccountResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCSPMGCPAccountForbidden creates a CreateCSPMGCPAccountForbidden with default headers values
func NewCreateCSPMGCPAccountForbidden() *CreateCSPMGCPAccountForbidden {
	return &CreateCSPMGCPAccountForbidden{}
}

/*
CreateCSPMGCPAccountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateCSPMGCPAccountForbidden struct {

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

// IsSuccess returns true when this create c s p m g c p account forbidden response has a 2xx status code
func (o *CreateCSPMGCPAccountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create c s p m g c p account forbidden response has a 3xx status code
func (o *CreateCSPMGCPAccountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m g c p account forbidden response has a 4xx status code
func (o *CreateCSPMGCPAccountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create c s p m g c p account forbidden response has a 5xx status code
func (o *CreateCSPMGCPAccountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create c s p m g c p account forbidden response a status code equal to that given
func (o *CreateCSPMGCPAccountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create c s p m g c p account forbidden response
func (o *CreateCSPMGCPAccountForbidden) Code() int {
	return 403
}

func (o *CreateCSPMGCPAccountForbidden) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountForbidden  %+v", 403, o.Payload)
}

func (o *CreateCSPMGCPAccountForbidden) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountForbidden  %+v", 403, o.Payload)
}

func (o *CreateCSPMGCPAccountForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateCSPMGCPAccountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateCSPMGCPAccountTooManyRequests creates a CreateCSPMGCPAccountTooManyRequests with default headers values
func NewCreateCSPMGCPAccountTooManyRequests() *CreateCSPMGCPAccountTooManyRequests {
	return &CreateCSPMGCPAccountTooManyRequests{}
}

/*
CreateCSPMGCPAccountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateCSPMGCPAccountTooManyRequests struct {

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

// IsSuccess returns true when this create c s p m g c p account too many requests response has a 2xx status code
func (o *CreateCSPMGCPAccountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create c s p m g c p account too many requests response has a 3xx status code
func (o *CreateCSPMGCPAccountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m g c p account too many requests response has a 4xx status code
func (o *CreateCSPMGCPAccountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create c s p m g c p account too many requests response has a 5xx status code
func (o *CreateCSPMGCPAccountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create c s p m g c p account too many requests response a status code equal to that given
func (o *CreateCSPMGCPAccountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create c s p m g c p account too many requests response
func (o *CreateCSPMGCPAccountTooManyRequests) Code() int {
	return 429
}

func (o *CreateCSPMGCPAccountTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateCSPMGCPAccountTooManyRequests) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateCSPMGCPAccountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateCSPMGCPAccountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateCSPMGCPAccountInternalServerError creates a CreateCSPMGCPAccountInternalServerError with default headers values
func NewCreateCSPMGCPAccountInternalServerError() *CreateCSPMGCPAccountInternalServerError {
	return &CreateCSPMGCPAccountInternalServerError{}
}

/*
CreateCSPMGCPAccountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateCSPMGCPAccountInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationGCPAccountResponseV1
}

// IsSuccess returns true when this create c s p m g c p account internal server error response has a 2xx status code
func (o *CreateCSPMGCPAccountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create c s p m g c p account internal server error response has a 3xx status code
func (o *CreateCSPMGCPAccountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m g c p account internal server error response has a 4xx status code
func (o *CreateCSPMGCPAccountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create c s p m g c p account internal server error response has a 5xx status code
func (o *CreateCSPMGCPAccountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create c s p m g c p account internal server error response a status code equal to that given
func (o *CreateCSPMGCPAccountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create c s p m g c p account internal server error response
func (o *CreateCSPMGCPAccountInternalServerError) Code() int {
	return 500
}

func (o *CreateCSPMGCPAccountInternalServerError) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateCSPMGCPAccountInternalServerError) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-gcp/entities/account/v1][%d] createCSPMGCPAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateCSPMGCPAccountInternalServerError) GetPayload() *models.RegistrationGCPAccountResponseV1 {
	return o.Payload
}

func (o *CreateCSPMGCPAccountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationGCPAccountResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}