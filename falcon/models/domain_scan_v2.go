// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DomainScanV2 domain scan v2
//
// swagger:model domain.ScanV2
type DomainScanV2 struct {

	// affected hosts count
	// Required: true
	AffectedHostsCount *int32 `json:"affected_hosts_count"`

	// cid
	Cid string `json:"cid,omitempty"`

	// cloud ml level detection
	CloudMlLevelDetection int32 `json:"cloud_ml_level_detection,omitempty"`

	// cloud ml level prevention
	CloudMlLevelPrevention int32 `json:"cloud_ml_level_prevention,omitempty"`

	// cloud pup adware level detection
	CloudPupAdwareLevelDetection int32 `json:"cloud_pup_adware_level_detection,omitempty"`

	// cloud pup adware level prevention
	CloudPupAdwareLevelPrevention int32 `json:"cloud_pup_adware_level_prevention,omitempty"`

	// completed host count
	// Required: true
	CompletedHostCount *int32 `json:"completed_host_count"`

	// cpu priority
	CPUPriority int32 `json:"cpu_priority,omitempty"`

	// created by
	CreatedBy string `json:"created_by,omitempty"`

	// created on
	// Format: date-time
	CreatedOn strfmt.DateTime `json:"created_on,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// endpoint notification
	EndpointNotification bool `json:"endpoint_notification,omitempty"`

	// file paths
	FilePaths []string `json:"file_paths"`

	// filecount
	Filecount *DomainFileCountV2 `json:"filecount,omitempty"`

	// host groups
	HostGroups []string `json:"host_groups"`

	// hosts
	Hosts []string `json:"hosts"`

	// id
	// Required: true
	ID *string `json:"id"`

	// incomplete host count
	// Required: true
	IncompleteHostCount *int32 `json:"incomplete_host_count"`

	// initiated from
	InitiatedFrom string `json:"initiated_from,omitempty"`

	// last updated
	// Format: date-time
	LastUpdated strfmt.DateTime `json:"last_updated,omitempty"`

	// max duration
	MaxDuration int32 `json:"max_duration,omitempty"`

	// metadata
	Metadata []string `json:"metadata"`

	// missing host count
	// Required: true
	MissingHostCount *int32 `json:"missing_host_count"`

	// not started host count
	// Required: true
	NotStartedHostCount *int32 `json:"not_started_host_count"`

	// pause duration
	PauseDuration int32 `json:"pause_duration,omitempty"`

	// policy setting
	PolicySetting []int64 `json:"policy_setting"`

	// preemption priority
	PreemptionPriority int32 `json:"preemption_priority,omitempty"`

	// profile id
	ProfileID string `json:"profile_id,omitempty"`

	// quarantine
	Quarantine bool `json:"quarantine,omitempty"`

	// scan completed on
	// Format: date-time
	ScanCompletedOn strfmt.DateTime `json:"scan_completed_on,omitempty"`

	// scan exclusions
	ScanExclusions []string `json:"scan_exclusions"`

	// scan inclusions
	ScanInclusions []string `json:"scan_inclusions"`

	// scan started on
	// Format: date-time
	ScanStartedOn strfmt.DateTime `json:"scan_started_on,omitempty"`

	// sensor ml level detection
	SensorMlLevelDetection int32 `json:"sensor_ml_level_detection,omitempty"`

	// sensor ml level prevention
	SensorMlLevelPrevention int32 `json:"sensor_ml_level_prevention,omitempty"`

	// severity
	Severity int64 `json:"severity,omitempty"`

	// started host count
	// Required: true
	StartedHostCount *int32 `json:"started_host_count"`

	// status
	Status string `json:"status,omitempty"`

	// targeted host count
	// Required: true
	TargetedHostCount *int32 `json:"targeted_host_count"`
}

// Validate validates this domain scan v2
func (m *DomainScanV2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAffectedHostsCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCompletedHostCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedOn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFilecount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIncompleteHostCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastUpdated(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMissingHostCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNotStartedHostCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScanCompletedOn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScanStartedOn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStartedHostCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTargetedHostCount(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainScanV2) validateAffectedHostsCount(formats strfmt.Registry) error {

	if err := validate.Required("affected_hosts_count", "body", m.AffectedHostsCount); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateCompletedHostCount(formats strfmt.Registry) error {

	if err := validate.Required("completed_host_count", "body", m.CompletedHostCount); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateCreatedOn(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedOn) { // not required
		return nil
	}

	if err := validate.FormatOf("created_on", "body", "date-time", m.CreatedOn.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateFilecount(formats strfmt.Registry) error {
	if swag.IsZero(m.Filecount) { // not required
		return nil
	}

	if m.Filecount != nil {
		if err := m.Filecount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("filecount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("filecount")
			}
			return err
		}
	}

	return nil
}

func (m *DomainScanV2) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateIncompleteHostCount(formats strfmt.Registry) error {

	if err := validate.Required("incomplete_host_count", "body", m.IncompleteHostCount); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateLastUpdated(formats strfmt.Registry) error {
	if swag.IsZero(m.LastUpdated) { // not required
		return nil
	}

	if err := validate.FormatOf("last_updated", "body", "date-time", m.LastUpdated.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateMissingHostCount(formats strfmt.Registry) error {

	if err := validate.Required("missing_host_count", "body", m.MissingHostCount); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateNotStartedHostCount(formats strfmt.Registry) error {

	if err := validate.Required("not_started_host_count", "body", m.NotStartedHostCount); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateScanCompletedOn(formats strfmt.Registry) error {
	if swag.IsZero(m.ScanCompletedOn) { // not required
		return nil
	}

	if err := validate.FormatOf("scan_completed_on", "body", "date-time", m.ScanCompletedOn.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateScanStartedOn(formats strfmt.Registry) error {
	if swag.IsZero(m.ScanStartedOn) { // not required
		return nil
	}

	if err := validate.FormatOf("scan_started_on", "body", "date-time", m.ScanStartedOn.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateStartedHostCount(formats strfmt.Registry) error {

	if err := validate.Required("started_host_count", "body", m.StartedHostCount); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanV2) validateTargetedHostCount(formats strfmt.Registry) error {

	if err := validate.Required("targeted_host_count", "body", m.TargetedHostCount); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this domain scan v2 based on the context it is used
func (m *DomainScanV2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateFilecount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainScanV2) contextValidateFilecount(ctx context.Context, formats strfmt.Registry) error {

	if m.Filecount != nil {

		if swag.IsZero(m.Filecount) { // not required
			return nil
		}

		if err := m.Filecount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("filecount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("filecount")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainScanV2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainScanV2) UnmarshalBinary(b []byte) error {
	var res DomainScanV2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
