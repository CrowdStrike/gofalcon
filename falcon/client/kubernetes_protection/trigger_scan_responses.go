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

// TriggerScanReader is a Reader for the TriggerScan structure.
type TriggerScanReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TriggerScanReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewTriggerScanCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewTriggerScanMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewTriggerScanBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewTriggerScanForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewTriggerScanTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewTriggerScanInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /kubernetes-protection/entities/scan/trigger/v1] TriggerScan", response, response.Code())
	}
}

// NewTriggerScanCreated creates a TriggerScanCreated with default headers values
func NewTriggerScanCreated() *TriggerScanCreated {
	return &TriggerScanCreated{}
}

/* TriggerScanCreated describes a response with status code 201, with default header values.

Created
*/
type TriggerScanCreated struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaBaseEntitiesResponse
}

// IsSuccess returns true when this trigger scan created response has a 2xx status code
func (o *TriggerScanCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this trigger scan created response has a 3xx status code
func (o *TriggerScanCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this trigger scan created response has a 4xx status code
func (o *TriggerScanCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this trigger scan created response has a 5xx status code
func (o *TriggerScanCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this trigger scan created response a status code equal to that given
func (o *TriggerScanCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the trigger scan created response
func (o *TriggerScanCreated) Code() int {
	return 201
}

func (o *TriggerScanCreated) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanCreated  %+v", 201, o.Payload)
}

func (o *TriggerScanCreated) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanCreated  %+v", 201, o.Payload)
}

func (o *TriggerScanCreated) GetPayload() *models.MsaBaseEntitiesResponse {
	return o.Payload
}

func (o *TriggerScanCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaBaseEntitiesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTriggerScanMultiStatus creates a TriggerScanMultiStatus with default headers values
func NewTriggerScanMultiStatus() *TriggerScanMultiStatus {
	return &TriggerScanMultiStatus{}
}

/* TriggerScanMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type TriggerScanMultiStatus struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaBaseEntitiesResponse
}

// IsSuccess returns true when this trigger scan multi status response has a 2xx status code
func (o *TriggerScanMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this trigger scan multi status response has a 3xx status code
func (o *TriggerScanMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this trigger scan multi status response has a 4xx status code
func (o *TriggerScanMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this trigger scan multi status response has a 5xx status code
func (o *TriggerScanMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this trigger scan multi status response a status code equal to that given
func (o *TriggerScanMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the trigger scan multi status response
func (o *TriggerScanMultiStatus) Code() int {
	return 207
}

func (o *TriggerScanMultiStatus) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanMultiStatus  %+v", 207, o.Payload)
}

func (o *TriggerScanMultiStatus) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanMultiStatus  %+v", 207, o.Payload)
}

func (o *TriggerScanMultiStatus) GetPayload() *models.MsaBaseEntitiesResponse {
	return o.Payload
}

func (o *TriggerScanMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaBaseEntitiesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTriggerScanBadRequest creates a TriggerScanBadRequest with default headers values
func NewTriggerScanBadRequest() *TriggerScanBadRequest {
	return &TriggerScanBadRequest{}
}

/* TriggerScanBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type TriggerScanBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaBaseEntitiesResponse
}

// IsSuccess returns true when this trigger scan bad request response has a 2xx status code
func (o *TriggerScanBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this trigger scan bad request response has a 3xx status code
func (o *TriggerScanBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this trigger scan bad request response has a 4xx status code
func (o *TriggerScanBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this trigger scan bad request response has a 5xx status code
func (o *TriggerScanBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this trigger scan bad request response a status code equal to that given
func (o *TriggerScanBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the trigger scan bad request response
func (o *TriggerScanBadRequest) Code() int {
	return 400
}

func (o *TriggerScanBadRequest) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanBadRequest  %+v", 400, o.Payload)
}

func (o *TriggerScanBadRequest) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanBadRequest  %+v", 400, o.Payload)
}

func (o *TriggerScanBadRequest) GetPayload() *models.MsaBaseEntitiesResponse {
	return o.Payload
}

func (o *TriggerScanBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaBaseEntitiesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTriggerScanForbidden creates a TriggerScanForbidden with default headers values
func NewTriggerScanForbidden() *TriggerScanForbidden {
	return &TriggerScanForbidden{}
}

/* TriggerScanForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type TriggerScanForbidden struct {

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

// IsSuccess returns true when this trigger scan forbidden response has a 2xx status code
func (o *TriggerScanForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this trigger scan forbidden response has a 3xx status code
func (o *TriggerScanForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this trigger scan forbidden response has a 4xx status code
func (o *TriggerScanForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this trigger scan forbidden response has a 5xx status code
func (o *TriggerScanForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this trigger scan forbidden response a status code equal to that given
func (o *TriggerScanForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the trigger scan forbidden response
func (o *TriggerScanForbidden) Code() int {
	return 403
}

func (o *TriggerScanForbidden) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanForbidden  %+v", 403, o.Payload)
}

func (o *TriggerScanForbidden) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanForbidden  %+v", 403, o.Payload)
}

func (o *TriggerScanForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *TriggerScanForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewTriggerScanTooManyRequests creates a TriggerScanTooManyRequests with default headers values
func NewTriggerScanTooManyRequests() *TriggerScanTooManyRequests {
	return &TriggerScanTooManyRequests{}
}

/* TriggerScanTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type TriggerScanTooManyRequests struct {

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

// IsSuccess returns true when this trigger scan too many requests response has a 2xx status code
func (o *TriggerScanTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this trigger scan too many requests response has a 3xx status code
func (o *TriggerScanTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this trigger scan too many requests response has a 4xx status code
func (o *TriggerScanTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this trigger scan too many requests response has a 5xx status code
func (o *TriggerScanTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this trigger scan too many requests response a status code equal to that given
func (o *TriggerScanTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the trigger scan too many requests response
func (o *TriggerScanTooManyRequests) Code() int {
	return 429
}

func (o *TriggerScanTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanTooManyRequests  %+v", 429, o.Payload)
}

func (o *TriggerScanTooManyRequests) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanTooManyRequests  %+v", 429, o.Payload)
}

func (o *TriggerScanTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *TriggerScanTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewTriggerScanInternalServerError creates a TriggerScanInternalServerError with default headers values
func NewTriggerScanInternalServerError() *TriggerScanInternalServerError {
	return &TriggerScanInternalServerError{}
}

/* TriggerScanInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type TriggerScanInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaBaseEntitiesResponse
}

// IsSuccess returns true when this trigger scan internal server error response has a 2xx status code
func (o *TriggerScanInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this trigger scan internal server error response has a 3xx status code
func (o *TriggerScanInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this trigger scan internal server error response has a 4xx status code
func (o *TriggerScanInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this trigger scan internal server error response has a 5xx status code
func (o *TriggerScanInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this trigger scan internal server error response a status code equal to that given
func (o *TriggerScanInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the trigger scan internal server error response
func (o *TriggerScanInternalServerError) Code() int {
	return 500
}

func (o *TriggerScanInternalServerError) Error() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanInternalServerError  %+v", 500, o.Payload)
}

func (o *TriggerScanInternalServerError) String() string {
	return fmt.Sprintf("[POST /kubernetes-protection/entities/scan/trigger/v1][%d] triggerScanInternalServerError  %+v", 500, o.Payload)
}

func (o *TriggerScanInternalServerError) GetPayload() *models.MsaBaseEntitiesResponse {
	return o.Payload
}

func (o *TriggerScanInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaBaseEntitiesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
