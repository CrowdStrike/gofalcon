// Code generated by go-swagger; DO NOT EDIT.

package firewall_management

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

// UpsertNetworkLocationsReader is a Reader for the UpsertNetworkLocations structure.
type UpsertNetworkLocationsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpsertNetworkLocationsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpsertNetworkLocationsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpsertNetworkLocationsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpsertNetworkLocationsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpsertNetworkLocationsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpsertNetworkLocationsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /fwmgr/entities/network-locations/v1] upsert-network-locations", response, response.Code())
	}
}

// NewUpsertNetworkLocationsOK creates a UpsertNetworkLocationsOK with default headers values
func NewUpsertNetworkLocationsOK() *UpsertNetworkLocationsOK {
	return &UpsertNetworkLocationsOK{}
}

/*
UpsertNetworkLocationsOK describes a response with status code 200, with default header values.

OK
*/
type UpsertNetworkLocationsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.FwmgrMsaspecQueryResponse
}

// IsSuccess returns true when this upsert network locations o k response has a 2xx status code
func (o *UpsertNetworkLocationsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this upsert network locations o k response has a 3xx status code
func (o *UpsertNetworkLocationsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this upsert network locations o k response has a 4xx status code
func (o *UpsertNetworkLocationsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this upsert network locations o k response has a 5xx status code
func (o *UpsertNetworkLocationsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this upsert network locations o k response a status code equal to that given
func (o *UpsertNetworkLocationsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the upsert network locations o k response
func (o *UpsertNetworkLocationsOK) Code() int {
	return 200
}

func (o *UpsertNetworkLocationsOK) Error() string {
	return fmt.Sprintf("[PUT /fwmgr/entities/network-locations/v1][%d] upsertNetworkLocationsOK  %+v", 200, o.Payload)
}

func (o *UpsertNetworkLocationsOK) String() string {
	return fmt.Sprintf("[PUT /fwmgr/entities/network-locations/v1][%d] upsertNetworkLocationsOK  %+v", 200, o.Payload)
}

func (o *UpsertNetworkLocationsOK) GetPayload() *models.FwmgrMsaspecQueryResponse {
	return o.Payload
}

func (o *UpsertNetworkLocationsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.FwmgrMsaspecQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpsertNetworkLocationsBadRequest creates a UpsertNetworkLocationsBadRequest with default headers values
func NewUpsertNetworkLocationsBadRequest() *UpsertNetworkLocationsBadRequest {
	return &UpsertNetworkLocationsBadRequest{}
}

/*
UpsertNetworkLocationsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type UpsertNetworkLocationsBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.FwmgrMsaspecResponseFields
}

// IsSuccess returns true when this upsert network locations bad request response has a 2xx status code
func (o *UpsertNetworkLocationsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this upsert network locations bad request response has a 3xx status code
func (o *UpsertNetworkLocationsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this upsert network locations bad request response has a 4xx status code
func (o *UpsertNetworkLocationsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this upsert network locations bad request response has a 5xx status code
func (o *UpsertNetworkLocationsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this upsert network locations bad request response a status code equal to that given
func (o *UpsertNetworkLocationsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the upsert network locations bad request response
func (o *UpsertNetworkLocationsBadRequest) Code() int {
	return 400
}

func (o *UpsertNetworkLocationsBadRequest) Error() string {
	return fmt.Sprintf("[PUT /fwmgr/entities/network-locations/v1][%d] upsertNetworkLocationsBadRequest  %+v", 400, o.Payload)
}

func (o *UpsertNetworkLocationsBadRequest) String() string {
	return fmt.Sprintf("[PUT /fwmgr/entities/network-locations/v1][%d] upsertNetworkLocationsBadRequest  %+v", 400, o.Payload)
}

func (o *UpsertNetworkLocationsBadRequest) GetPayload() *models.FwmgrMsaspecResponseFields {
	return o.Payload
}

func (o *UpsertNetworkLocationsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.FwmgrMsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpsertNetworkLocationsForbidden creates a UpsertNetworkLocationsForbidden with default headers values
func NewUpsertNetworkLocationsForbidden() *UpsertNetworkLocationsForbidden {
	return &UpsertNetworkLocationsForbidden{}
}

/*
UpsertNetworkLocationsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpsertNetworkLocationsForbidden struct {

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

// IsSuccess returns true when this upsert network locations forbidden response has a 2xx status code
func (o *UpsertNetworkLocationsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this upsert network locations forbidden response has a 3xx status code
func (o *UpsertNetworkLocationsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this upsert network locations forbidden response has a 4xx status code
func (o *UpsertNetworkLocationsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this upsert network locations forbidden response has a 5xx status code
func (o *UpsertNetworkLocationsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this upsert network locations forbidden response a status code equal to that given
func (o *UpsertNetworkLocationsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the upsert network locations forbidden response
func (o *UpsertNetworkLocationsForbidden) Code() int {
	return 403
}

func (o *UpsertNetworkLocationsForbidden) Error() string {
	return fmt.Sprintf("[PUT /fwmgr/entities/network-locations/v1][%d] upsertNetworkLocationsForbidden  %+v", 403, o.Payload)
}

func (o *UpsertNetworkLocationsForbidden) String() string {
	return fmt.Sprintf("[PUT /fwmgr/entities/network-locations/v1][%d] upsertNetworkLocationsForbidden  %+v", 403, o.Payload)
}

func (o *UpsertNetworkLocationsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpsertNetworkLocationsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpsertNetworkLocationsTooManyRequests creates a UpsertNetworkLocationsTooManyRequests with default headers values
func NewUpsertNetworkLocationsTooManyRequests() *UpsertNetworkLocationsTooManyRequests {
	return &UpsertNetworkLocationsTooManyRequests{}
}

/*
UpsertNetworkLocationsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type UpsertNetworkLocationsTooManyRequests struct {

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

// IsSuccess returns true when this upsert network locations too many requests response has a 2xx status code
func (o *UpsertNetworkLocationsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this upsert network locations too many requests response has a 3xx status code
func (o *UpsertNetworkLocationsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this upsert network locations too many requests response has a 4xx status code
func (o *UpsertNetworkLocationsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this upsert network locations too many requests response has a 5xx status code
func (o *UpsertNetworkLocationsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this upsert network locations too many requests response a status code equal to that given
func (o *UpsertNetworkLocationsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the upsert network locations too many requests response
func (o *UpsertNetworkLocationsTooManyRequests) Code() int {
	return 429
}

func (o *UpsertNetworkLocationsTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /fwmgr/entities/network-locations/v1][%d] upsertNetworkLocationsTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpsertNetworkLocationsTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /fwmgr/entities/network-locations/v1][%d] upsertNetworkLocationsTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpsertNetworkLocationsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpsertNetworkLocationsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpsertNetworkLocationsInternalServerError creates a UpsertNetworkLocationsInternalServerError with default headers values
func NewUpsertNetworkLocationsInternalServerError() *UpsertNetworkLocationsInternalServerError {
	return &UpsertNetworkLocationsInternalServerError{}
}

/*
UpsertNetworkLocationsInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type UpsertNetworkLocationsInternalServerError struct {

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

// IsSuccess returns true when this upsert network locations internal server error response has a 2xx status code
func (o *UpsertNetworkLocationsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this upsert network locations internal server error response has a 3xx status code
func (o *UpsertNetworkLocationsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this upsert network locations internal server error response has a 4xx status code
func (o *UpsertNetworkLocationsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this upsert network locations internal server error response has a 5xx status code
func (o *UpsertNetworkLocationsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this upsert network locations internal server error response a status code equal to that given
func (o *UpsertNetworkLocationsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the upsert network locations internal server error response
func (o *UpsertNetworkLocationsInternalServerError) Code() int {
	return 500
}

func (o *UpsertNetworkLocationsInternalServerError) Error() string {
	return fmt.Sprintf("[PUT /fwmgr/entities/network-locations/v1][%d] upsertNetworkLocationsInternalServerError  %+v", 500, o.Payload)
}

func (o *UpsertNetworkLocationsInternalServerError) String() string {
	return fmt.Sprintf("[PUT /fwmgr/entities/network-locations/v1][%d] upsertNetworkLocationsInternalServerError  %+v", 500, o.Payload)
}

func (o *UpsertNetworkLocationsInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpsertNetworkLocationsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
