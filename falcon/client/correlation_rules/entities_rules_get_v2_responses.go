// Code generated by go-swagger; DO NOT EDIT.

package correlation_rules

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

// EntitiesRulesGetV2Reader is a Reader for the EntitiesRulesGetV2 structure.
type EntitiesRulesGetV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *EntitiesRulesGetV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewEntitiesRulesGetV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewEntitiesRulesGetV2BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewEntitiesRulesGetV2Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewEntitiesRulesGetV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewEntitiesRulesGetV2NotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewEntitiesRulesGetV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewEntitiesRulesGetV2InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /correlation-rules/entities/rules/v2] entities.rules.get.v2", response, response.Code())
	}
}

// NewEntitiesRulesGetV2OK creates a EntitiesRulesGetV2OK with default headers values
func NewEntitiesRulesGetV2OK() *EntitiesRulesGetV2OK {
	return &EntitiesRulesGetV2OK{}
}

/*
EntitiesRulesGetV2OK describes a response with status code 200, with default header values.

OK
*/
type EntitiesRulesGetV2OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIGetEntitiesRulesResponseV1
}

// IsSuccess returns true when this entities rules get v2 o k response has a 2xx status code
func (o *EntitiesRulesGetV2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this entities rules get v2 o k response has a 3xx status code
func (o *EntitiesRulesGetV2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities rules get v2 o k response has a 4xx status code
func (o *EntitiesRulesGetV2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this entities rules get v2 o k response has a 5xx status code
func (o *EntitiesRulesGetV2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this entities rules get v2 o k response a status code equal to that given
func (o *EntitiesRulesGetV2OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the entities rules get v2 o k response
func (o *EntitiesRulesGetV2OK) Code() int {
	return 200
}

func (o *EntitiesRulesGetV2OK) Error() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2OK  %+v", 200, o.Payload)
}

func (o *EntitiesRulesGetV2OK) String() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2OK  %+v", 200, o.Payload)
}

func (o *EntitiesRulesGetV2OK) GetPayload() *models.APIGetEntitiesRulesResponseV1 {
	return o.Payload
}

func (o *EntitiesRulesGetV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APIGetEntitiesRulesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEntitiesRulesGetV2BadRequest creates a EntitiesRulesGetV2BadRequest with default headers values
func NewEntitiesRulesGetV2BadRequest() *EntitiesRulesGetV2BadRequest {
	return &EntitiesRulesGetV2BadRequest{}
}

/*
EntitiesRulesGetV2BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type EntitiesRulesGetV2BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIGetEntitiesRulesResponseV1
}

// IsSuccess returns true when this entities rules get v2 bad request response has a 2xx status code
func (o *EntitiesRulesGetV2BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities rules get v2 bad request response has a 3xx status code
func (o *EntitiesRulesGetV2BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities rules get v2 bad request response has a 4xx status code
func (o *EntitiesRulesGetV2BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities rules get v2 bad request response has a 5xx status code
func (o *EntitiesRulesGetV2BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this entities rules get v2 bad request response a status code equal to that given
func (o *EntitiesRulesGetV2BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the entities rules get v2 bad request response
func (o *EntitiesRulesGetV2BadRequest) Code() int {
	return 400
}

func (o *EntitiesRulesGetV2BadRequest) Error() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2BadRequest  %+v", 400, o.Payload)
}

func (o *EntitiesRulesGetV2BadRequest) String() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2BadRequest  %+v", 400, o.Payload)
}

func (o *EntitiesRulesGetV2BadRequest) GetPayload() *models.APIGetEntitiesRulesResponseV1 {
	return o.Payload
}

func (o *EntitiesRulesGetV2BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APIGetEntitiesRulesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEntitiesRulesGetV2Unauthorized creates a EntitiesRulesGetV2Unauthorized with default headers values
func NewEntitiesRulesGetV2Unauthorized() *EntitiesRulesGetV2Unauthorized {
	return &EntitiesRulesGetV2Unauthorized{}
}

/*
EntitiesRulesGetV2Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type EntitiesRulesGetV2Unauthorized struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIGetEntitiesRulesResponseV1
}

// IsSuccess returns true when this entities rules get v2 unauthorized response has a 2xx status code
func (o *EntitiesRulesGetV2Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities rules get v2 unauthorized response has a 3xx status code
func (o *EntitiesRulesGetV2Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities rules get v2 unauthorized response has a 4xx status code
func (o *EntitiesRulesGetV2Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities rules get v2 unauthorized response has a 5xx status code
func (o *EntitiesRulesGetV2Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this entities rules get v2 unauthorized response a status code equal to that given
func (o *EntitiesRulesGetV2Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the entities rules get v2 unauthorized response
func (o *EntitiesRulesGetV2Unauthorized) Code() int {
	return 401
}

func (o *EntitiesRulesGetV2Unauthorized) Error() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2Unauthorized  %+v", 401, o.Payload)
}

func (o *EntitiesRulesGetV2Unauthorized) String() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2Unauthorized  %+v", 401, o.Payload)
}

func (o *EntitiesRulesGetV2Unauthorized) GetPayload() *models.APIGetEntitiesRulesResponseV1 {
	return o.Payload
}

func (o *EntitiesRulesGetV2Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APIGetEntitiesRulesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEntitiesRulesGetV2Forbidden creates a EntitiesRulesGetV2Forbidden with default headers values
func NewEntitiesRulesGetV2Forbidden() *EntitiesRulesGetV2Forbidden {
	return &EntitiesRulesGetV2Forbidden{}
}

/*
EntitiesRulesGetV2Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type EntitiesRulesGetV2Forbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIGetEntitiesRulesResponseV1
}

// IsSuccess returns true when this entities rules get v2 forbidden response has a 2xx status code
func (o *EntitiesRulesGetV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities rules get v2 forbidden response has a 3xx status code
func (o *EntitiesRulesGetV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities rules get v2 forbidden response has a 4xx status code
func (o *EntitiesRulesGetV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities rules get v2 forbidden response has a 5xx status code
func (o *EntitiesRulesGetV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this entities rules get v2 forbidden response a status code equal to that given
func (o *EntitiesRulesGetV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the entities rules get v2 forbidden response
func (o *EntitiesRulesGetV2Forbidden) Code() int {
	return 403
}

func (o *EntitiesRulesGetV2Forbidden) Error() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2Forbidden  %+v", 403, o.Payload)
}

func (o *EntitiesRulesGetV2Forbidden) String() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2Forbidden  %+v", 403, o.Payload)
}

func (o *EntitiesRulesGetV2Forbidden) GetPayload() *models.APIGetEntitiesRulesResponseV1 {
	return o.Payload
}

func (o *EntitiesRulesGetV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APIGetEntitiesRulesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEntitiesRulesGetV2NotFound creates a EntitiesRulesGetV2NotFound with default headers values
func NewEntitiesRulesGetV2NotFound() *EntitiesRulesGetV2NotFound {
	return &EntitiesRulesGetV2NotFound{}
}

/*
EntitiesRulesGetV2NotFound describes a response with status code 404, with default header values.

Not Found
*/
type EntitiesRulesGetV2NotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIGetEntitiesRulesResponseV1
}

// IsSuccess returns true when this entities rules get v2 not found response has a 2xx status code
func (o *EntitiesRulesGetV2NotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities rules get v2 not found response has a 3xx status code
func (o *EntitiesRulesGetV2NotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities rules get v2 not found response has a 4xx status code
func (o *EntitiesRulesGetV2NotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities rules get v2 not found response has a 5xx status code
func (o *EntitiesRulesGetV2NotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this entities rules get v2 not found response a status code equal to that given
func (o *EntitiesRulesGetV2NotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the entities rules get v2 not found response
func (o *EntitiesRulesGetV2NotFound) Code() int {
	return 404
}

func (o *EntitiesRulesGetV2NotFound) Error() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2NotFound  %+v", 404, o.Payload)
}

func (o *EntitiesRulesGetV2NotFound) String() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2NotFound  %+v", 404, o.Payload)
}

func (o *EntitiesRulesGetV2NotFound) GetPayload() *models.APIGetEntitiesRulesResponseV1 {
	return o.Payload
}

func (o *EntitiesRulesGetV2NotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APIGetEntitiesRulesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEntitiesRulesGetV2TooManyRequests creates a EntitiesRulesGetV2TooManyRequests with default headers values
func NewEntitiesRulesGetV2TooManyRequests() *EntitiesRulesGetV2TooManyRequests {
	return &EntitiesRulesGetV2TooManyRequests{}
}

/*
EntitiesRulesGetV2TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type EntitiesRulesGetV2TooManyRequests struct {

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

// IsSuccess returns true when this entities rules get v2 too many requests response has a 2xx status code
func (o *EntitiesRulesGetV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities rules get v2 too many requests response has a 3xx status code
func (o *EntitiesRulesGetV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities rules get v2 too many requests response has a 4xx status code
func (o *EntitiesRulesGetV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities rules get v2 too many requests response has a 5xx status code
func (o *EntitiesRulesGetV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this entities rules get v2 too many requests response a status code equal to that given
func (o *EntitiesRulesGetV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the entities rules get v2 too many requests response
func (o *EntitiesRulesGetV2TooManyRequests) Code() int {
	return 429
}

func (o *EntitiesRulesGetV2TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *EntitiesRulesGetV2TooManyRequests) String() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *EntitiesRulesGetV2TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *EntitiesRulesGetV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewEntitiesRulesGetV2InternalServerError creates a EntitiesRulesGetV2InternalServerError with default headers values
func NewEntitiesRulesGetV2InternalServerError() *EntitiesRulesGetV2InternalServerError {
	return &EntitiesRulesGetV2InternalServerError{}
}

/*
EntitiesRulesGetV2InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type EntitiesRulesGetV2InternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIGetEntitiesRulesResponseV1
}

// IsSuccess returns true when this entities rules get v2 internal server error response has a 2xx status code
func (o *EntitiesRulesGetV2InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities rules get v2 internal server error response has a 3xx status code
func (o *EntitiesRulesGetV2InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities rules get v2 internal server error response has a 4xx status code
func (o *EntitiesRulesGetV2InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this entities rules get v2 internal server error response has a 5xx status code
func (o *EntitiesRulesGetV2InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this entities rules get v2 internal server error response a status code equal to that given
func (o *EntitiesRulesGetV2InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the entities rules get v2 internal server error response
func (o *EntitiesRulesGetV2InternalServerError) Code() int {
	return 500
}

func (o *EntitiesRulesGetV2InternalServerError) Error() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2InternalServerError  %+v", 500, o.Payload)
}

func (o *EntitiesRulesGetV2InternalServerError) String() string {
	return fmt.Sprintf("[GET /correlation-rules/entities/rules/v2][%d] entitiesRulesGetV2InternalServerError  %+v", 500, o.Payload)
}

func (o *EntitiesRulesGetV2InternalServerError) GetPayload() *models.APIGetEntitiesRulesResponseV1 {
	return o.Payload
}

func (o *EntitiesRulesGetV2InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APIGetEntitiesRulesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
