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

// PatterndispositionPatternDisposition patterndisposition pattern disposition
//
// swagger:model patterndisposition.PatternDisposition
type PatterndispositionPatternDisposition struct {

	// blocking unsupported or disabled
	// Required: true
	BlockingUnsupportedOrDisabled *bool `json:"blocking_unsupported_or_disabled"`

	// bootup safeguard enabled
	// Required: true
	BootupSafeguardEnabled *bool `json:"bootup_safeguard_enabled"`

	// containment file system
	// Required: true
	ContainmentFileSystem *bool `json:"containment_file_system"`

	// critical process disabled
	// Required: true
	CriticalProcessDisabled *bool `json:"critical_process_disabled"`

	// detect
	// Required: true
	Detect *bool `json:"detect"`

	// fs operation blocked
	// Required: true
	FsOperationBlocked *bool `json:"fs_operation_blocked"`

	// handle operation downgraded
	// Required: true
	HandleOperationDowngraded *bool `json:"handle_operation_downgraded"`

	// inddet mask
	// Required: true
	InddetMask *bool `json:"inddet_mask"`

	// indicator
	// Required: true
	Indicator *bool `json:"indicator"`

	// kill action failed
	// Required: true
	KillActionFailed *bool `json:"kill_action_failed"`

	// kill parent
	// Required: true
	KillParent *bool `json:"kill_parent"`

	// kill process
	// Required: true
	KillProcess *bool `json:"kill_process"`

	// kill subprocess
	// Required: true
	KillSubprocess *bool `json:"kill_subprocess"`

	// mfa required
	// Required: true
	MfaRequired *bool `json:"mfa_required"`

	// operation blocked
	// Required: true
	OperationBlocked *bool `json:"operation_blocked"`

	// policy disabled
	// Required: true
	PolicyDisabled *bool `json:"policy_disabled"`

	// prevention provisioning enabled
	// Required: true
	PreventionProvisioningEnabled *bool `json:"prevention_provisioning_enabled"`

	// process blocked
	// Required: true
	ProcessBlocked *bool `json:"process_blocked"`

	// quarantine file
	// Required: true
	QuarantineFile *bool `json:"quarantine_file"`

	// quarantine machine
	// Required: true
	QuarantineMachine *bool `json:"quarantine_machine"`

	// registry operation blocked
	// Required: true
	RegistryOperationBlocked *bool `json:"registry_operation_blocked"`

	// response action already applied
	// Required: true
	ResponseActionAlreadyApplied *bool `json:"response_action_already_applied"`

	// response action failed
	// Required: true
	ResponseActionFailed *bool `json:"response_action_failed"`

	// response action triggered
	// Required: true
	ResponseActionTriggered *bool `json:"response_action_triggered"`

	// rooting
	// Required: true
	Rooting *bool `json:"rooting"`

	// sensor only
	// Required: true
	SensorOnly *bool `json:"sensor_only"`

	// suspend parent
	// Required: true
	SuspendParent *bool `json:"suspend_parent"`

	// suspend process
	// Required: true
	SuspendProcess *bool `json:"suspend_process"`
}

// Validate validates this patterndisposition pattern disposition
func (m *PatterndispositionPatternDisposition) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBlockingUnsupportedOrDisabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBootupSafeguardEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContainmentFileSystem(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCriticalProcessDisabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDetect(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFsOperationBlocked(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHandleOperationDowngraded(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInddetMask(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIndicator(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKillActionFailed(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKillParent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKillProcess(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKillSubprocess(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMfaRequired(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOperationBlocked(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyDisabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePreventionProvisioningEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProcessBlocked(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateQuarantineFile(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateQuarantineMachine(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRegistryOperationBlocked(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResponseActionAlreadyApplied(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResponseActionFailed(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResponseActionTriggered(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRooting(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSensorOnly(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSuspendParent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSuspendProcess(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PatterndispositionPatternDisposition) validateBlockingUnsupportedOrDisabled(formats strfmt.Registry) error {

	if err := validate.Required("blocking_unsupported_or_disabled", "body", m.BlockingUnsupportedOrDisabled); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateBootupSafeguardEnabled(formats strfmt.Registry) error {

	if err := validate.Required("bootup_safeguard_enabled", "body", m.BootupSafeguardEnabled); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateContainmentFileSystem(formats strfmt.Registry) error {

	if err := validate.Required("containment_file_system", "body", m.ContainmentFileSystem); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateCriticalProcessDisabled(formats strfmt.Registry) error {

	if err := validate.Required("critical_process_disabled", "body", m.CriticalProcessDisabled); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateDetect(formats strfmt.Registry) error {

	if err := validate.Required("detect", "body", m.Detect); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateFsOperationBlocked(formats strfmt.Registry) error {

	if err := validate.Required("fs_operation_blocked", "body", m.FsOperationBlocked); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateHandleOperationDowngraded(formats strfmt.Registry) error {

	if err := validate.Required("handle_operation_downgraded", "body", m.HandleOperationDowngraded); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateInddetMask(formats strfmt.Registry) error {

	if err := validate.Required("inddet_mask", "body", m.InddetMask); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateIndicator(formats strfmt.Registry) error {

	if err := validate.Required("indicator", "body", m.Indicator); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateKillActionFailed(formats strfmt.Registry) error {

	if err := validate.Required("kill_action_failed", "body", m.KillActionFailed); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateKillParent(formats strfmt.Registry) error {

	if err := validate.Required("kill_parent", "body", m.KillParent); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateKillProcess(formats strfmt.Registry) error {

	if err := validate.Required("kill_process", "body", m.KillProcess); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateKillSubprocess(formats strfmt.Registry) error {

	if err := validate.Required("kill_subprocess", "body", m.KillSubprocess); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateMfaRequired(formats strfmt.Registry) error {

	if err := validate.Required("mfa_required", "body", m.MfaRequired); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateOperationBlocked(formats strfmt.Registry) error {

	if err := validate.Required("operation_blocked", "body", m.OperationBlocked); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validatePolicyDisabled(formats strfmt.Registry) error {

	if err := validate.Required("policy_disabled", "body", m.PolicyDisabled); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validatePreventionProvisioningEnabled(formats strfmt.Registry) error {

	if err := validate.Required("prevention_provisioning_enabled", "body", m.PreventionProvisioningEnabled); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateProcessBlocked(formats strfmt.Registry) error {

	if err := validate.Required("process_blocked", "body", m.ProcessBlocked); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateQuarantineFile(formats strfmt.Registry) error {

	if err := validate.Required("quarantine_file", "body", m.QuarantineFile); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateQuarantineMachine(formats strfmt.Registry) error {

	if err := validate.Required("quarantine_machine", "body", m.QuarantineMachine); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateRegistryOperationBlocked(formats strfmt.Registry) error {

	if err := validate.Required("registry_operation_blocked", "body", m.RegistryOperationBlocked); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateResponseActionAlreadyApplied(formats strfmt.Registry) error {

	if err := validate.Required("response_action_already_applied", "body", m.ResponseActionAlreadyApplied); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateResponseActionFailed(formats strfmt.Registry) error {

	if err := validate.Required("response_action_failed", "body", m.ResponseActionFailed); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateResponseActionTriggered(formats strfmt.Registry) error {

	if err := validate.Required("response_action_triggered", "body", m.ResponseActionTriggered); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateRooting(formats strfmt.Registry) error {

	if err := validate.Required("rooting", "body", m.Rooting); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateSensorOnly(formats strfmt.Registry) error {

	if err := validate.Required("sensor_only", "body", m.SensorOnly); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateSuspendParent(formats strfmt.Registry) error {

	if err := validate.Required("suspend_parent", "body", m.SuspendParent); err != nil {
		return err
	}

	return nil
}

func (m *PatterndispositionPatternDisposition) validateSuspendProcess(formats strfmt.Registry) error {

	if err := validate.Required("suspend_process", "body", m.SuspendProcess); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this patterndisposition pattern disposition based on context it is used
func (m *PatterndispositionPatternDisposition) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PatterndispositionPatternDisposition) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PatterndispositionPatternDisposition) UnmarshalBinary(b []byte) error {
	var res PatterndispositionPatternDisposition
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
