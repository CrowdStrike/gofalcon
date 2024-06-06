// Code generated by go-swagger; DO NOT EDIT.

package container_alerts

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

// SearchAndReadContainerAlertsReader is a Reader for the SearchAndReadContainerAlerts structure.
type SearchAndReadContainerAlertsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SearchAndReadContainerAlertsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSearchAndReadContainerAlertsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewSearchAndReadContainerAlertsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSearchAndReadContainerAlertsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewSearchAndReadContainerAlertsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/combined/container-alerts/v1] SearchAndReadContainerAlerts", response, response.Code())
	}
}

// NewSearchAndReadContainerAlertsOK creates a SearchAndReadContainerAlertsOK with default headers values
func NewSearchAndReadContainerAlertsOK() *SearchAndReadContainerAlertsOK {
	return &SearchAndReadContainerAlertsOK{}
}

/*
SearchAndReadContainerAlertsOK describes a response with status code 200, with default header values.

OK
*/
type SearchAndReadContainerAlertsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.AlertsContainerAlertsEntityResponse
}

// IsSuccess returns true when this search and read container alerts o k response has a 2xx status code
func (o *SearchAndReadContainerAlertsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this search and read container alerts o k response has a 3xx status code
func (o *SearchAndReadContainerAlertsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search and read container alerts o k response has a 4xx status code
func (o *SearchAndReadContainerAlertsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this search and read container alerts o k response has a 5xx status code
func (o *SearchAndReadContainerAlertsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this search and read container alerts o k response a status code equal to that given
func (o *SearchAndReadContainerAlertsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the search and read container alerts o k response
func (o *SearchAndReadContainerAlertsOK) Code() int {
	return 200
}

func (o *SearchAndReadContainerAlertsOK) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/container-alerts/v1][%d] searchAndReadContainerAlertsOK  %+v", 200, o.Payload)
}

func (o *SearchAndReadContainerAlertsOK) String() string {
	return fmt.Sprintf("[GET /container-security/combined/container-alerts/v1][%d] searchAndReadContainerAlertsOK  %+v", 200, o.Payload)
}

func (o *SearchAndReadContainerAlertsOK) GetPayload() *models.AlertsContainerAlertsEntityResponse {
	return o.Payload
}

func (o *SearchAndReadContainerAlertsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.AlertsContainerAlertsEntityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSearchAndReadContainerAlertsForbidden creates a SearchAndReadContainerAlertsForbidden with default headers values
func NewSearchAndReadContainerAlertsForbidden() *SearchAndReadContainerAlertsForbidden {
	return &SearchAndReadContainerAlertsForbidden{}
}

/*
SearchAndReadContainerAlertsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SearchAndReadContainerAlertsForbidden struct {

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

// IsSuccess returns true when this search and read container alerts forbidden response has a 2xx status code
func (o *SearchAndReadContainerAlertsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search and read container alerts forbidden response has a 3xx status code
func (o *SearchAndReadContainerAlertsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search and read container alerts forbidden response has a 4xx status code
func (o *SearchAndReadContainerAlertsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this search and read container alerts forbidden response has a 5xx status code
func (o *SearchAndReadContainerAlertsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this search and read container alerts forbidden response a status code equal to that given
func (o *SearchAndReadContainerAlertsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the search and read container alerts forbidden response
func (o *SearchAndReadContainerAlertsForbidden) Code() int {
	return 403
}

func (o *SearchAndReadContainerAlertsForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/container-alerts/v1][%d] searchAndReadContainerAlertsForbidden  %+v", 403, o.Payload)
}

func (o *SearchAndReadContainerAlertsForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/combined/container-alerts/v1][%d] searchAndReadContainerAlertsForbidden  %+v", 403, o.Payload)
}

func (o *SearchAndReadContainerAlertsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *SearchAndReadContainerAlertsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSearchAndReadContainerAlertsTooManyRequests creates a SearchAndReadContainerAlertsTooManyRequests with default headers values
func NewSearchAndReadContainerAlertsTooManyRequests() *SearchAndReadContainerAlertsTooManyRequests {
	return &SearchAndReadContainerAlertsTooManyRequests{}
}

/*
SearchAndReadContainerAlertsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type SearchAndReadContainerAlertsTooManyRequests struct {

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

// IsSuccess returns true when this search and read container alerts too many requests response has a 2xx status code
func (o *SearchAndReadContainerAlertsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search and read container alerts too many requests response has a 3xx status code
func (o *SearchAndReadContainerAlertsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search and read container alerts too many requests response has a 4xx status code
func (o *SearchAndReadContainerAlertsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this search and read container alerts too many requests response has a 5xx status code
func (o *SearchAndReadContainerAlertsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this search and read container alerts too many requests response a status code equal to that given
func (o *SearchAndReadContainerAlertsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the search and read container alerts too many requests response
func (o *SearchAndReadContainerAlertsTooManyRequests) Code() int {
	return 429
}

func (o *SearchAndReadContainerAlertsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/container-alerts/v1][%d] searchAndReadContainerAlertsTooManyRequests  %+v", 429, o.Payload)
}

func (o *SearchAndReadContainerAlertsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/combined/container-alerts/v1][%d] searchAndReadContainerAlertsTooManyRequests  %+v", 429, o.Payload)
}

func (o *SearchAndReadContainerAlertsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *SearchAndReadContainerAlertsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSearchAndReadContainerAlertsInternalServerError creates a SearchAndReadContainerAlertsInternalServerError with default headers values
func NewSearchAndReadContainerAlertsInternalServerError() *SearchAndReadContainerAlertsInternalServerError {
	return &SearchAndReadContainerAlertsInternalServerError{}
}

/*
SearchAndReadContainerAlertsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type SearchAndReadContainerAlertsInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.CoreEntitiesResponse
}

// IsSuccess returns true when this search and read container alerts internal server error response has a 2xx status code
func (o *SearchAndReadContainerAlertsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search and read container alerts internal server error response has a 3xx status code
func (o *SearchAndReadContainerAlertsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search and read container alerts internal server error response has a 4xx status code
func (o *SearchAndReadContainerAlertsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this search and read container alerts internal server error response has a 5xx status code
func (o *SearchAndReadContainerAlertsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this search and read container alerts internal server error response a status code equal to that given
func (o *SearchAndReadContainerAlertsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the search and read container alerts internal server error response
func (o *SearchAndReadContainerAlertsInternalServerError) Code() int {
	return 500
}

func (o *SearchAndReadContainerAlertsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/container-alerts/v1][%d] searchAndReadContainerAlertsInternalServerError  %+v", 500, o.Payload)
}

func (o *SearchAndReadContainerAlertsInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/combined/container-alerts/v1][%d] searchAndReadContainerAlertsInternalServerError  %+v", 500, o.Payload)
}

func (o *SearchAndReadContainerAlertsInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *SearchAndReadContainerAlertsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.CoreEntitiesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
