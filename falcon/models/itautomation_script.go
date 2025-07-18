// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ItautomationScript itautomation script
//
// swagger:model itautomation.Script
type ItautomationScript struct {

	// The type of action to perform
	// Enum: [script command script_file]
	ActionType string `json:"action_type,omitempty"`

	// The script content to execute. Example: echo 'Hello, World!'
	Content string `json:"content,omitempty"`

	// The list of file IDs to execute. Example: ['f64b95555ef54ea682619ce880d267cc', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6']
	FileIds []string `json:"file_ids"`

	// The scripting language to use
	// Enum: [bash zsh powershell python]
	Language string `json:"language,omitempty"`

	// The arguments to execute the script file with.
	ScriptArgs string `json:"script_args,omitempty"`

	// The file ID of the script file to execute. Example: f64b95555ef54ea682619ce880d267cc
	ScriptFileID string `json:"script_file_id,omitempty"`
}

// Validate validates this itautomation script
func (m *ItautomationScript) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateActionType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLanguage(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var itautomationScriptTypeActionTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["script","command","script_file"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		itautomationScriptTypeActionTypePropEnum = append(itautomationScriptTypeActionTypePropEnum, v)
	}
}

const (

	// ItautomationScriptActionTypeScript captures enum value "script"
	ItautomationScriptActionTypeScript string = "script"

	// ItautomationScriptActionTypeCommand captures enum value "command"
	ItautomationScriptActionTypeCommand string = "command"

	// ItautomationScriptActionTypeScriptFile captures enum value "script_file"
	ItautomationScriptActionTypeScriptFile string = "script_file"
)

// prop value enum
func (m *ItautomationScript) validateActionTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, itautomationScriptTypeActionTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *ItautomationScript) validateActionType(formats strfmt.Registry) error {
	if swag.IsZero(m.ActionType) { // not required
		return nil
	}

	// value enum
	if err := m.validateActionTypeEnum("action_type", "body", m.ActionType); err != nil {
		return err
	}

	return nil
}

var itautomationScriptTypeLanguagePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["bash","zsh","powershell","python"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		itautomationScriptTypeLanguagePropEnum = append(itautomationScriptTypeLanguagePropEnum, v)
	}
}

const (

	// ItautomationScriptLanguageBash captures enum value "bash"
	ItautomationScriptLanguageBash string = "bash"

	// ItautomationScriptLanguageZsh captures enum value "zsh"
	ItautomationScriptLanguageZsh string = "zsh"

	// ItautomationScriptLanguagePowershell captures enum value "powershell"
	ItautomationScriptLanguagePowershell string = "powershell"

	// ItautomationScriptLanguagePython captures enum value "python"
	ItautomationScriptLanguagePython string = "python"
)

// prop value enum
func (m *ItautomationScript) validateLanguageEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, itautomationScriptTypeLanguagePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *ItautomationScript) validateLanguage(formats strfmt.Registry) error {
	if swag.IsZero(m.Language) { // not required
		return nil
	}

	// value enum
	if err := m.validateLanguageEnum("language", "body", m.Language); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this itautomation script based on context it is used
func (m *ItautomationScript) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ItautomationScript) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ItautomationScript) UnmarshalBinary(b []byte) error {
	var res ItautomationScript
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
