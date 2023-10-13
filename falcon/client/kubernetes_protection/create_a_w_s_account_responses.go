// Code generated by go-swagger; DO NOT EDIT.

package kubernetes_protection

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

// CreateAWSAccountReader is a Reader for the CreateAWSAccount structure.
type CreateAWSAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAWSAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateAWSAccountCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewCreateAWSAccountMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateAWSAccountBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateAWSAccountForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateAWSAccountTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateAWSAccountInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /kubernetes-protection/entities/accounts/aws/v1] CreateAWSAccount", response, response.Code())
	}
}

// NewCreateAWSAccountCreated creates a CreateAWSAccountCreated with default headers values
func NewCreateAWSAccountCreated() *CreateAWSAccountCreated {
	return &CreateAWSAccountCreated{}
}

/* CreateAWSAccountCreated describes a response with status code 201, with default header values.

Created
*/
type CreateAWSAccountCreated struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.K8sregCreateAWSAccResp
}

// IsSuccess returns true when this create a w s account created response has a 2xx status code
func (o *CreateAWSAccountCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create a w s account created response has a 3xx status code
func (o *CreateAWSAccountCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create a w s account created response has a 4xx status code
func (o *CreateAWSAccountCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create a w s account created response has a 5xx status code
func (o *CreateAWSAccountCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create a w s account created response a status code equal to that given
func (o *CreateAWSAccountCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create a w s account created response
func (o *CreateAWSAccountCreated) Code() int {
	return 201
}

func (o *CreateAWSAccountCreated) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountCreated  %+v", 201, o.Payload)
}

func (o *CreateAWSAccountCreated) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountCreated  %+v", 201, o.Payload)
}

func (o *CreateAWSAccountCreated) GetPayload() *models.K8sregCreateAWSAccResp {
	return o.Payload
}

func (o *CreateAWSAccountCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.K8sregCreateAWSAccResp)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAWSAccountMultiStatus creates a CreateAWSAccountMultiStatus with default headers values
func NewCreateAWSAccountMultiStatus() *CreateAWSAccountMultiStatus {
	return &CreateAWSAccountMultiStatus{}
}

/* CreateAWSAccountMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type CreateAWSAccountMultiStatus struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.K8sregCreateAWSAccResp
}

// IsSuccess returns true when this create a w s account multi status response has a 2xx status code
func (o *CreateAWSAccountMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create a w s account multi status response has a 3xx status code
func (o *CreateAWSAccountMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create a w s account multi status response has a 4xx status code
func (o *CreateAWSAccountMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this create a w s account multi status response has a 5xx status code
func (o *CreateAWSAccountMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this create a w s account multi status response a status code equal to that given
func (o *CreateAWSAccountMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the create a w s account multi status response
func (o *CreateAWSAccountMultiStatus) Code() int {
	return 207
}

func (o *CreateAWSAccountMultiStatus) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *CreateAWSAccountMultiStatus) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountMultiStatus  %+v", 207, o.Payload)
}

func (o *CreateAWSAccountMultiStatus) GetPayload() *models.K8sregCreateAWSAccResp {
	return o.Payload
}

func (o *CreateAWSAccountMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.K8sregCreateAWSAccResp)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAWSAccountBadRequest creates a CreateAWSAccountBadRequest with default headers values
func NewCreateAWSAccountBadRequest() *CreateAWSAccountBadRequest {
	return &CreateAWSAccountBadRequest{}
}

/* CreateAWSAccountBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CreateAWSAccountBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.K8sregCreateAWSAccResp
}

// IsSuccess returns true when this create a w s account bad request response has a 2xx status code
func (o *CreateAWSAccountBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create a w s account bad request response has a 3xx status code
func (o *CreateAWSAccountBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create a w s account bad request response has a 4xx status code
func (o *CreateAWSAccountBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create a w s account bad request response has a 5xx status code
func (o *CreateAWSAccountBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create a w s account bad request response a status code equal to that given
func (o *CreateAWSAccountBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create a w s account bad request response
func (o *CreateAWSAccountBadRequest) Code() int {
	return 400
}

func (o *CreateAWSAccountBadRequest) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountBadRequest  %+v", 400, o.Payload)
}

func (o *CreateAWSAccountBadRequest) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountBadRequest  %+v", 400, o.Payload)
}

func (o *CreateAWSAccountBadRequest) GetPayload() *models.K8sregCreateAWSAccResp {
	return o.Payload
}

func (o *CreateAWSAccountBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.K8sregCreateAWSAccResp)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAWSAccountForbidden creates a CreateAWSAccountForbidden with default headers values
func NewCreateAWSAccountForbidden() *CreateAWSAccountForbidden {
	return &CreateAWSAccountForbidden{}
}

/* CreateAWSAccountForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateAWSAccountForbidden struct {

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

// IsSuccess returns true when this create a w s account forbidden response has a 2xx status code
func (o *CreateAWSAccountForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create a w s account forbidden response has a 3xx status code
func (o *CreateAWSAccountForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create a w s account forbidden response has a 4xx status code
func (o *CreateAWSAccountForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create a w s account forbidden response has a 5xx status code
func (o *CreateAWSAccountForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create a w s account forbidden response a status code equal to that given
func (o *CreateAWSAccountForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create a w s account forbidden response
func (o *CreateAWSAccountForbidden) Code() int {
	return 403
}

func (o *CreateAWSAccountForbidden) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountForbidden  %+v", 403, o.Payload)
}

func (o *CreateAWSAccountForbidden) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountForbidden  %+v", 403, o.Payload)
}

func (o *CreateAWSAccountForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateAWSAccountForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateAWSAccountTooManyRequests creates a CreateAWSAccountTooManyRequests with default headers values
func NewCreateAWSAccountTooManyRequests() *CreateAWSAccountTooManyRequests {
	return &CreateAWSAccountTooManyRequests{}
}

/* CreateAWSAccountTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateAWSAccountTooManyRequests struct {

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

// IsSuccess returns true when this create a w s account too many requests response has a 2xx status code
func (o *CreateAWSAccountTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create a w s account too many requests response has a 3xx status code
func (o *CreateAWSAccountTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create a w s account too many requests response has a 4xx status code
func (o *CreateAWSAccountTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create a w s account too many requests response has a 5xx status code
func (o *CreateAWSAccountTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create a w s account too many requests response a status code equal to that given
func (o *CreateAWSAccountTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create a w s account too many requests response
func (o *CreateAWSAccountTooManyRequests) Code() int {
	return 429
}

func (o *CreateAWSAccountTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateAWSAccountTooManyRequests) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateAWSAccountTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateAWSAccountTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateAWSAccountInternalServerError creates a CreateAWSAccountInternalServerError with default headers values
func NewCreateAWSAccountInternalServerError() *CreateAWSAccountInternalServerError {
	return &CreateAWSAccountInternalServerError{}
}

/* CreateAWSAccountInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateAWSAccountInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.K8sregCreateAWSAccResp
}

// IsSuccess returns true when this create a w s account internal server error response has a 2xx status code
func (o *CreateAWSAccountInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create a w s account internal server error response has a 3xx status code
func (o *CreateAWSAccountInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create a w s account internal server error response has a 4xx status code
func (o *CreateAWSAccountInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create a w s account internal server error response has a 5xx status code
func (o *CreateAWSAccountInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create a w s account internal server error response a status code equal to that given
func (o *CreateAWSAccountInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create a w s account internal server error response
func (o *CreateAWSAccountInternalServerError) Code() int {
	return 500
}

func (o *CreateAWSAccountInternalServerError) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateAWSAccountInternalServerError) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/accounts/aws/v1][%d] createAWSAccountInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateAWSAccountInternalServerError) GetPayload() *models.K8sregCreateAWSAccResp {
	return o.Payload
}

func (o *CreateAWSAccountInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.K8sregCreateAWSAccResp)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
