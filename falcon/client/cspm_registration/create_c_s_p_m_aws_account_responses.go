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

// CreateCSPMAwsAccountReader is a Reader for the CreateCSPMAwsAccount structure.
type CreateCSPMAwsAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateCSPMAwsAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateCSPMAwsAccountCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewCreateCSPMAwsAccountMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateCSPMAwsAccountBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateCSPMAwsAccountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateCSPMAwsAccountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateCSPMAwsAccountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /cloud-connect-cspm-aws/entities/account/v1] CreateCSPMAwsAccount", response, response.Code())
	}
}

// NewCreateCSPMAwsAccountCreated creates a CreateCSPMAwsAccountCreated with default headers values
func NewCreateCSPMAwsAccountCreated() *CreateCSPMAwsAccountCreated {
	return &CreateCSPMAwsAccountCreated{}
}

/* CreateCSPMAwsAccountCreated describes a response with status code 201, with default header values.

Created
*/
type CreateCSPMAwsAccountCreated struct {

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

// IsSuccess returns true when this create c s p m aws account created response has a 2xx status code
func (o *CreateCSPMAwsAccountCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create c s p m aws account created response has a 3xx status code
func (o *CreateCSPMAwsAccountCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m aws account created response has a 4xx status code
func (o *CreateCSPMAwsAccountCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create c s p m aws account created response has a 5xx status code
func (o *CreateCSPMAwsAccountCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create c s p m aws account created response a status code equal to that given
func (o *CreateCSPMAwsAccountCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create c s p m aws account created response
func (o *CreateCSPMAwsAccountCreated) Code() int {
	return 201
}

func (o *CreateCSPMAwsAccountCreated) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountCreated  %+v", 201, o.Payload)
}

func (o *CreateCSPMAwsAccountCreated) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountCreated  %+v", 201, o.Payload)
}

func (o *CreateCSPMAwsAccountCreated) GetPayload() *models.RegistrationAWSAccountResponseV2 {
	return o.Payload
}

func (o *CreateCSPMAwsAccountCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateCSPMAwsAccountMultiStatus creates a CreateCSPMAwsAccountMultiStatus with default headers values
func NewCreateCSPMAwsAccountMultiStatus() *CreateCSPMAwsAccountMultiStatus {
	return &CreateCSPMAwsAccountMultiStatus{}
}

/* CreateCSPMAwsAccountMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type CreateCSPMAwsAccountMultiStatus struct {

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

// IsSuccess returns true when this create c s p m aws account multi status response has a 2xx status code
func (o *CreateCSPMAwsAccountMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create c s p m aws account multi status response has a 3xx status code
func (o *CreateCSPMAwsAccountMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m aws account multi status response has a 4xx status code
func (o *CreateCSPMAwsAccountMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this create c s p m aws account multi status response has a 5xx status code
func (o *CreateCSPMAwsAccountMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this create c s p m aws account multi status response a status code equal to that given
func (o *CreateCSPMAwsAccountMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the create c s p m aws account multi status response
func (o *CreateCSPMAwsAccountMultiStatus) Code() int {
	return 207
}

func (o *CreateCSPMAwsAccountMultiStatus) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *CreateCSPMAwsAccountMultiStatus) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *CreateCSPMAwsAccountMultiStatus) GetPayload() *models.RegistrationAWSAccountResponseV2 {
	return o.Payload
}

func (o *CreateCSPMAwsAccountMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateCSPMAwsAccountBadRequest creates a CreateCSPMAwsAccountBadRequest with default headers values
func NewCreateCSPMAwsAccountBadRequest() *CreateCSPMAwsAccountBadRequest {
	return &CreateCSPMAwsAccountBadRequest{}
}

/* CreateCSPMAwsAccountBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CreateCSPMAwsAccountBadRequest struct {

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

// IsSuccess returns true when this create c s p m aws account bad request response has a 2xx status code
func (o *CreateCSPMAwsAccountBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create c s p m aws account bad request response has a 3xx status code
func (o *CreateCSPMAwsAccountBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m aws account bad request response has a 4xx status code
func (o *CreateCSPMAwsAccountBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create c s p m aws account bad request response has a 5xx status code
func (o *CreateCSPMAwsAccountBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create c s p m aws account bad request response a status code equal to that given
func (o *CreateCSPMAwsAccountBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create c s p m aws account bad request response
func (o *CreateCSPMAwsAccountBadRequest) Code() int {
	return 400
}

func (o *CreateCSPMAwsAccountBadRequest) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountBadRequest  %+v", 400, o.Payload)
}

func (o *CreateCSPMAwsAccountBadRequest) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountBadRequest  %+v", 400, o.Payload)
}

func (o *CreateCSPMAwsAccountBadRequest) GetPayload() *models.RegistrationAWSAccountResponseV2 {
	return o.Payload
}

func (o *CreateCSPMAwsAccountBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateCSPMAwsAccountForbidden creates a CreateCSPMAwsAccountForbidden with default headers values
func NewCreateCSPMAwsAccountForbidden() *CreateCSPMAwsAccountForbidden {
	return &CreateCSPMAwsAccountForbidden{}
}

/* CreateCSPMAwsAccountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateCSPMAwsAccountForbidden struct {

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

// IsSuccess returns true when this create c s p m aws account forbidden response has a 2xx status code
func (o *CreateCSPMAwsAccountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create c s p m aws account forbidden response has a 3xx status code
func (o *CreateCSPMAwsAccountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m aws account forbidden response has a 4xx status code
func (o *CreateCSPMAwsAccountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create c s p m aws account forbidden response has a 5xx status code
func (o *CreateCSPMAwsAccountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create c s p m aws account forbidden response a status code equal to that given
func (o *CreateCSPMAwsAccountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create c s p m aws account forbidden response
func (o *CreateCSPMAwsAccountForbidden) Code() int {
	return 403
}

func (o *CreateCSPMAwsAccountForbidden) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountForbidden  %+v", 403, o.Payload)
}

func (o *CreateCSPMAwsAccountForbidden) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountForbidden  %+v", 403, o.Payload)
}

func (o *CreateCSPMAwsAccountForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateCSPMAwsAccountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateCSPMAwsAccountTooManyRequests creates a CreateCSPMAwsAccountTooManyRequests with default headers values
func NewCreateCSPMAwsAccountTooManyRequests() *CreateCSPMAwsAccountTooManyRequests {
	return &CreateCSPMAwsAccountTooManyRequests{}
}

/* CreateCSPMAwsAccountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateCSPMAwsAccountTooManyRequests struct {

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

// IsSuccess returns true when this create c s p m aws account too many requests response has a 2xx status code
func (o *CreateCSPMAwsAccountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create c s p m aws account too many requests response has a 3xx status code
func (o *CreateCSPMAwsAccountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m aws account too many requests response has a 4xx status code
func (o *CreateCSPMAwsAccountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create c s p m aws account too many requests response has a 5xx status code
func (o *CreateCSPMAwsAccountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create c s p m aws account too many requests response a status code equal to that given
func (o *CreateCSPMAwsAccountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create c s p m aws account too many requests response
func (o *CreateCSPMAwsAccountTooManyRequests) Code() int {
	return 429
}

func (o *CreateCSPMAwsAccountTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateCSPMAwsAccountTooManyRequests) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateCSPMAwsAccountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateCSPMAwsAccountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateCSPMAwsAccountInternalServerError creates a CreateCSPMAwsAccountInternalServerError with default headers values
func NewCreateCSPMAwsAccountInternalServerError() *CreateCSPMAwsAccountInternalServerError {
	return &CreateCSPMAwsAccountInternalServerError{}
}

/* CreateCSPMAwsAccountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateCSPMAwsAccountInternalServerError struct {

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

// IsSuccess returns true when this create c s p m aws account internal server error response has a 2xx status code
func (o *CreateCSPMAwsAccountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create c s p m aws account internal server error response has a 3xx status code
func (o *CreateCSPMAwsAccountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create c s p m aws account internal server error response has a 4xx status code
func (o *CreateCSPMAwsAccountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create c s p m aws account internal server error response has a 5xx status code
func (o *CreateCSPMAwsAccountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create c s p m aws account internal server error response a status code equal to that given
func (o *CreateCSPMAwsAccountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create c s p m aws account internal server error response
func (o *CreateCSPMAwsAccountInternalServerError) Code() int {
	return 500
}

func (o *CreateCSPMAwsAccountInternalServerError) Error() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateCSPMAwsAccountInternalServerError) String() string {
	return fmt.Sprintf("[POST /cloud-connect-cspm-aws/entities/account/v1][%d] createCSPMAwsAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateCSPMAwsAccountInternalServerError) GetPayload() *models.RegistrationAWSAccountResponseV2 {
	return o.Payload
}

func (o *CreateCSPMAwsAccountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
