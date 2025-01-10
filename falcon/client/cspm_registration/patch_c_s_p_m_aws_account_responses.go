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

// PatchCSPMAwsAccountReader is a Reader for the PatchCSPMAwsAccount structure.
type PatchCSPMAwsAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchCSPMAwsAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPatchCSPMAwsAccountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewPatchCSPMAwsAccountMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchCSPMAwsAccountBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchCSPMAwsAccountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPatchCSPMAwsAccountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPatchCSPMAwsAccountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /cloud-connect-cspm-aws/entities/account/v1] PatchCSPMAwsAccount", response, response.Code())
	}
}

// NewPatchCSPMAwsAccountOK creates a PatchCSPMAwsAccountOK with default headers values
func NewPatchCSPMAwsAccountOK() *PatchCSPMAwsAccountOK {
	return &PatchCSPMAwsAccountOK{}
}

/*
PatchCSPMAwsAccountOK describes a response with status code 200, with default header values.

OK
*/
type PatchCSPMAwsAccountOK struct {

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

// IsSuccess returns true when this patch c s p m aws account o k response has a 2xx status code
func (o *PatchCSPMAwsAccountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this patch c s p m aws account o k response has a 3xx status code
func (o *PatchCSPMAwsAccountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch c s p m aws account o k response has a 4xx status code
func (o *PatchCSPMAwsAccountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this patch c s p m aws account o k response has a 5xx status code
func (o *PatchCSPMAwsAccountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this patch c s p m aws account o k response a status code equal to that given
func (o *PatchCSPMAwsAccountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the patch c s p m aws account o k response
func (o *PatchCSPMAwsAccountOK) Code() int {
	return 200
}

func (o *PatchCSPMAwsAccountOK) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountOK  %+v", 200, o.Payload)
}

func (o *PatchCSPMAwsAccountOK) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountOK  %+v", 200, o.Payload)
}

func (o *PatchCSPMAwsAccountOK) GetPayload() *models.RegistrationAWSAccountResponseV2 {
	return o.Payload
}

func (o *PatchCSPMAwsAccountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewPatchCSPMAwsAccountMultiStatus creates a PatchCSPMAwsAccountMultiStatus with default headers values
func NewPatchCSPMAwsAccountMultiStatus() *PatchCSPMAwsAccountMultiStatus {
	return &PatchCSPMAwsAccountMultiStatus{}
}

/*
PatchCSPMAwsAccountMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type PatchCSPMAwsAccountMultiStatus struct {

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

// IsSuccess returns true when this patch c s p m aws account multi status response has a 2xx status code
func (o *PatchCSPMAwsAccountMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this patch c s p m aws account multi status response has a 3xx status code
func (o *PatchCSPMAwsAccountMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch c s p m aws account multi status response has a 4xx status code
func (o *PatchCSPMAwsAccountMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this patch c s p m aws account multi status response has a 5xx status code
func (o *PatchCSPMAwsAccountMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this patch c s p m aws account multi status response a status code equal to that given
func (o *PatchCSPMAwsAccountMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the patch c s p m aws account multi status response
func (o *PatchCSPMAwsAccountMultiStatus) Code() int {
	return 207
}

func (o *PatchCSPMAwsAccountMultiStatus) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *PatchCSPMAwsAccountMultiStatus) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *PatchCSPMAwsAccountMultiStatus) GetPayload() *models.RegistrationAWSAccountResponseV2 {
	return o.Payload
}

func (o *PatchCSPMAwsAccountMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewPatchCSPMAwsAccountBadRequest creates a PatchCSPMAwsAccountBadRequest with default headers values
func NewPatchCSPMAwsAccountBadRequest() *PatchCSPMAwsAccountBadRequest {
	return &PatchCSPMAwsAccountBadRequest{}
}

/*
PatchCSPMAwsAccountBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PatchCSPMAwsAccountBadRequest struct {

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

// IsSuccess returns true when this patch c s p m aws account bad request response has a 2xx status code
func (o *PatchCSPMAwsAccountBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch c s p m aws account bad request response has a 3xx status code
func (o *PatchCSPMAwsAccountBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch c s p m aws account bad request response has a 4xx status code
func (o *PatchCSPMAwsAccountBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch c s p m aws account bad request response has a 5xx status code
func (o *PatchCSPMAwsAccountBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this patch c s p m aws account bad request response a status code equal to that given
func (o *PatchCSPMAwsAccountBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the patch c s p m aws account bad request response
func (o *PatchCSPMAwsAccountBadRequest) Code() int {
	return 400
}

func (o *PatchCSPMAwsAccountBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountBadRequest  %+v", 400, o.Payload)
}

func (o *PatchCSPMAwsAccountBadRequest) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountBadRequest  %+v", 400, o.Payload)
}

func (o *PatchCSPMAwsAccountBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *PatchCSPMAwsAccountBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewPatchCSPMAwsAccountForbidden creates a PatchCSPMAwsAccountForbidden with default headers values
func NewPatchCSPMAwsAccountForbidden() *PatchCSPMAwsAccountForbidden {
	return &PatchCSPMAwsAccountForbidden{}
}

/*
PatchCSPMAwsAccountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PatchCSPMAwsAccountForbidden struct {

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

// IsSuccess returns true when this patch c s p m aws account forbidden response has a 2xx status code
func (o *PatchCSPMAwsAccountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch c s p m aws account forbidden response has a 3xx status code
func (o *PatchCSPMAwsAccountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch c s p m aws account forbidden response has a 4xx status code
func (o *PatchCSPMAwsAccountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch c s p m aws account forbidden response has a 5xx status code
func (o *PatchCSPMAwsAccountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this patch c s p m aws account forbidden response a status code equal to that given
func (o *PatchCSPMAwsAccountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the patch c s p m aws account forbidden response
func (o *PatchCSPMAwsAccountForbidden) Code() int {
	return 403
}

func (o *PatchCSPMAwsAccountForbidden) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountForbidden  %+v", 403, o.Payload)
}

func (o *PatchCSPMAwsAccountForbidden) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountForbidden  %+v", 403, o.Payload)
}

func (o *PatchCSPMAwsAccountForbidden) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *PatchCSPMAwsAccountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewPatchCSPMAwsAccountTooManyRequests creates a PatchCSPMAwsAccountTooManyRequests with default headers values
func NewPatchCSPMAwsAccountTooManyRequests() *PatchCSPMAwsAccountTooManyRequests {
	return &PatchCSPMAwsAccountTooManyRequests{}
}

/*
PatchCSPMAwsAccountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type PatchCSPMAwsAccountTooManyRequests struct {

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

// IsSuccess returns true when this patch c s p m aws account too many requests response has a 2xx status code
func (o *PatchCSPMAwsAccountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch c s p m aws account too many requests response has a 3xx status code
func (o *PatchCSPMAwsAccountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch c s p m aws account too many requests response has a 4xx status code
func (o *PatchCSPMAwsAccountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch c s p m aws account too many requests response has a 5xx status code
func (o *PatchCSPMAwsAccountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this patch c s p m aws account too many requests response a status code equal to that given
func (o *PatchCSPMAwsAccountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the patch c s p m aws account too many requests response
func (o *PatchCSPMAwsAccountTooManyRequests) Code() int {
	return 429
}

func (o *PatchCSPMAwsAccountTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *PatchCSPMAwsAccountTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *PatchCSPMAwsAccountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *PatchCSPMAwsAccountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewPatchCSPMAwsAccountInternalServerError creates a PatchCSPMAwsAccountInternalServerError with default headers values
func NewPatchCSPMAwsAccountInternalServerError() *PatchCSPMAwsAccountInternalServerError {
	return &PatchCSPMAwsAccountInternalServerError{}
}

/*
PatchCSPMAwsAccountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PatchCSPMAwsAccountInternalServerError struct {

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

// IsSuccess returns true when this patch c s p m aws account internal server error response has a 2xx status code
func (o *PatchCSPMAwsAccountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch c s p m aws account internal server error response has a 3xx status code
func (o *PatchCSPMAwsAccountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch c s p m aws account internal server error response has a 4xx status code
func (o *PatchCSPMAwsAccountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this patch c s p m aws account internal server error response has a 5xx status code
func (o *PatchCSPMAwsAccountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this patch c s p m aws account internal server error response a status code equal to that given
func (o *PatchCSPMAwsAccountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the patch c s p m aws account internal server error response
func (o *PatchCSPMAwsAccountInternalServerError) Code() int {
	return 500
}

func (o *PatchCSPMAwsAccountInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *PatchCSPMAwsAccountInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-cspm-aws/entities/account/v1][%d] patchCSPMAwsAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *PatchCSPMAwsAccountInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *PatchCSPMAwsAccountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
