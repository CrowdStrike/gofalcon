// Code generated by go-swagger; DO NOT EDIT.

package filevantage

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

// DeletePoliciesReader is a Reader for the DeletePolicies structure.
type DeletePoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeletePoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeletePoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeletePoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeletePoliciesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeletePoliciesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeletePoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /filevantage/entities/policies/v1] deletePolicies", response, response.Code())
	}
}

// NewDeletePoliciesOK creates a DeletePoliciesOK with default headers values
func NewDeletePoliciesOK() *DeletePoliciesOK {
	return &DeletePoliciesOK{}
}

/* DeletePoliciesOK describes a response with status code 200, with default header values.

OK
*/
type DeletePoliciesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.PoliciesDeleteResponse
}

// IsSuccess returns true when this delete policies o k response has a 2xx status code
func (o *DeletePoliciesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete policies o k response has a 3xx status code
func (o *DeletePoliciesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policies o k response has a 4xx status code
func (o *DeletePoliciesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete policies o k response has a 5xx status code
func (o *DeletePoliciesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete policies o k response a status code equal to that given
func (o *DeletePoliciesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete policies o k response
func (o *DeletePoliciesOK) Code() int {
	return 200
}

func (o *DeletePoliciesOK) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/policies/v1][%d] deletePoliciesOK  %+v", 200, o.Payload)
}

func (o *DeletePoliciesOK) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/policies/v1][%d] deletePoliciesOK  %+v", 200, o.Payload)
}

func (o *DeletePoliciesOK) GetPayload() *models.PoliciesDeleteResponse {
	return o.Payload
}

func (o *DeletePoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.PoliciesDeleteResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeletePoliciesBadRequest creates a DeletePoliciesBadRequest with default headers values
func NewDeletePoliciesBadRequest() *DeletePoliciesBadRequest {
	return &DeletePoliciesBadRequest{}
}

/* DeletePoliciesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DeletePoliciesBadRequest struct {

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

// IsSuccess returns true when this delete policies bad request response has a 2xx status code
func (o *DeletePoliciesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete policies bad request response has a 3xx status code
func (o *DeletePoliciesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policies bad request response has a 4xx status code
func (o *DeletePoliciesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete policies bad request response has a 5xx status code
func (o *DeletePoliciesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete policies bad request response a status code equal to that given
func (o *DeletePoliciesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete policies bad request response
func (o *DeletePoliciesBadRequest) Code() int {
	return 400
}

func (o *DeletePoliciesBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/policies/v1][%d] deletePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *DeletePoliciesBadRequest) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/policies/v1][%d] deletePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *DeletePoliciesBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DeletePoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeletePoliciesForbidden creates a DeletePoliciesForbidden with default headers values
func NewDeletePoliciesForbidden() *DeletePoliciesForbidden {
	return &DeletePoliciesForbidden{}
}

/* DeletePoliciesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeletePoliciesForbidden struct {

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

// IsSuccess returns true when this delete policies forbidden response has a 2xx status code
func (o *DeletePoliciesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete policies forbidden response has a 3xx status code
func (o *DeletePoliciesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policies forbidden response has a 4xx status code
func (o *DeletePoliciesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete policies forbidden response has a 5xx status code
func (o *DeletePoliciesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete policies forbidden response a status code equal to that given
func (o *DeletePoliciesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete policies forbidden response
func (o *DeletePoliciesForbidden) Code() int {
	return 403
}

func (o *DeletePoliciesForbidden) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/policies/v1][%d] deletePoliciesForbidden  %+v", 403, o.Payload)
}

func (o *DeletePoliciesForbidden) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/policies/v1][%d] deletePoliciesForbidden  %+v", 403, o.Payload)
}

func (o *DeletePoliciesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeletePoliciesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeletePoliciesTooManyRequests creates a DeletePoliciesTooManyRequests with default headers values
func NewDeletePoliciesTooManyRequests() *DeletePoliciesTooManyRequests {
	return &DeletePoliciesTooManyRequests{}
}

/* DeletePoliciesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type DeletePoliciesTooManyRequests struct {

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

// IsSuccess returns true when this delete policies too many requests response has a 2xx status code
func (o *DeletePoliciesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete policies too many requests response has a 3xx status code
func (o *DeletePoliciesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policies too many requests response has a 4xx status code
func (o *DeletePoliciesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete policies too many requests response has a 5xx status code
func (o *DeletePoliciesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete policies too many requests response a status code equal to that given
func (o *DeletePoliciesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete policies too many requests response
func (o *DeletePoliciesTooManyRequests) Code() int {
	return 429
}

func (o *DeletePoliciesTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/policies/v1][%d] deletePoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeletePoliciesTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/policies/v1][%d] deletePoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeletePoliciesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeletePoliciesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeletePoliciesInternalServerError creates a DeletePoliciesInternalServerError with default headers values
func NewDeletePoliciesInternalServerError() *DeletePoliciesInternalServerError {
	return &DeletePoliciesInternalServerError{}
}

/* DeletePoliciesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type DeletePoliciesInternalServerError struct {

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

// IsSuccess returns true when this delete policies internal server error response has a 2xx status code
func (o *DeletePoliciesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete policies internal server error response has a 3xx status code
func (o *DeletePoliciesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policies internal server error response has a 4xx status code
func (o *DeletePoliciesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete policies internal server error response has a 5xx status code
func (o *DeletePoliciesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this delete policies internal server error response a status code equal to that given
func (o *DeletePoliciesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the delete policies internal server error response
func (o *DeletePoliciesInternalServerError) Code() int {
	return 500
}

func (o *DeletePoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/policies/v1][%d] deletePoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *DeletePoliciesInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /filevantage/entities/policies/v1][%d] deletePoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *DeletePoliciesInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DeletePoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
