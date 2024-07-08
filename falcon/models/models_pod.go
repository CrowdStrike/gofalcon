// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ModelsPod models pod
//
// swagger:model models.Pod
type ModelsPod struct {

	// agents
	// Required: true
	Agents []ModelsPodAgents `json:"agents"`

	// allow privilege escalation
	// Required: true
	AllowPrivilegeEscalation *bool `json:"allow_privilege_escalation"`

	// annotations list
	// Required: true
	AnnotationsList []string `json:"annotations_list"`

	// automount service token
	// Required: true
	AutomountServiceToken *bool `json:"automount_service_token"`

	// cid
	// Required: true
	Cid *string `json:"cid"`

	// cloud account id
	// Required: true
	CloudAccountID *string `json:"cloud_account_id"`

	// cloud name
	// Required: true
	CloudName *string `json:"cloud_name"`

	// cloud region
	// Required: true
	CloudRegion *string `json:"cloud_region"`

	// cluster id
	// Required: true
	ClusterID *string `json:"cluster_id"`

	// cluster name
	// Required: true
	ClusterName *string `json:"cluster_name"`

	// container count
	// Required: true
	ContainerCount *int32 `json:"container_count"`

	// containers
	// Required: true
	Containers []ModelsPodContainers `json:"containers"`

	// created at
	// Required: true
	CreatedAt *string `json:"created_at"`

	// deleted at
	DeletedAt string `json:"deleted_at,omitempty"`

	// first seen
	// Required: true
	FirstSeen *string `json:"first_seen"`

	// host ipc
	// Required: true
	HostIpc *bool `json:"host_ipc"`

	// host network
	// Required: true
	HostNetwork *bool `json:"host_network"`

	// host pid
	// Required: true
	HostPid *bool `json:"host_pid"`

	// image pull secrets
	// Required: true
	ImagePullSecrets []string `json:"image_pull_secrets"`

	// ipv4
	// Required: true
	IPV4 *string `json:"ipv4"`

	// ipv6
	// Required: true
	IPV6 *string `json:"ipv6"`

	// labels
	// Required: true
	Labels map[string]string `json:"labels"`

	// labels list
	// Required: true
	LabelsList []string `json:"labels_list"`

	// last seen
	// Required: true
	LastSeen *string `json:"last_seen"`

	// namespace
	// Required: true
	Namespace *string `json:"namespace"`

	// node ipv4
	// Required: true
	NodeIPV4 *string `json:"node_ipv4"`

	// node name
	// Required: true
	NodeName *string `json:"node_name"`

	// node selector
	// Required: true
	NodeSelector *string `json:"node_selector"`

	// node uid
	// Required: true
	NodeUID *string `json:"node_uid"`

	// owner id
	// Required: true
	OwnerID *string `json:"owner_id"`

	// owner type
	// Required: true
	OwnerType *string `json:"owner_type"`

	// pod external id
	// Required: true
	PodExternalID *string `json:"pod_external_id"`

	// pod id
	// Required: true
	PodID *string `json:"pod_id"`

	// pod name
	// Required: true
	PodName *string `json:"pod_name"`

	// ports
	// Required: true
	Ports []ModelsPodPorts `json:"ports"`

	// privileged
	// Required: true
	Privileged *bool `json:"privileged"`

	// resource status
	// Required: true
	ResourceStatus *string `json:"resource_status"`

	// root write access
	// Required: true
	RootWriteAccess *bool `json:"root_write_access"`

	// run as root group
	// Required: true
	RunAsRootGroup *bool `json:"run_as_root_group"`

	// run as root user
	// Required: true
	RunAsRootUser *bool `json:"run_as_root_user"`

	// scheduler name
	// Required: true
	SchedulerName *string `json:"scheduler_name"`

	// service account name
	// Required: true
	ServiceAccountName *string `json:"service_account_name"`

	// share process namespace
	// Required: true
	ShareProcessNamespace *bool `json:"share_process_namespace"`

	// volume mounts
	// Required: true
	VolumeMounts *string `json:"volume_mounts"`
}

// Validate validates this models pod
func (m *ModelsPod) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAgents(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAllowPrivilegeEscalation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAnnotationsList(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAutomountServiceToken(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudAccountID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudRegion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClusterID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClusterName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContainerCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContainers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFirstSeen(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHostIpc(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHostNetwork(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHostPid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateImagePullSecrets(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIPV4(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIPV6(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLabelsList(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastSeen(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNamespace(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNodeIPV4(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNodeName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNodeSelector(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNodeUID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOwnerID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOwnerType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePodExternalID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePodID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePodName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePorts(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrivileged(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRootWriteAccess(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRunAsRootGroup(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRunAsRootUser(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSchedulerName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServiceAccountName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateShareProcessNamespace(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVolumeMounts(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsPod) validateAgents(formats strfmt.Registry) error {

	if err := validate.Required("agents", "body", m.Agents); err != nil {
		return err
	}

	for i := 0; i < len(m.Agents); i++ {

		if m.Agents[i] != nil {
			if err := m.Agents[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("agents" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("agents" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ModelsPod) validateAllowPrivilegeEscalation(formats strfmt.Registry) error {

	if err := validate.Required("allow_privilege_escalation", "body", m.AllowPrivilegeEscalation); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateAnnotationsList(formats strfmt.Registry) error {

	if err := validate.Required("annotations_list", "body", m.AnnotationsList); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateAutomountServiceToken(formats strfmt.Registry) error {

	if err := validate.Required("automount_service_token", "body", m.AutomountServiceToken); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateCid(formats strfmt.Registry) error {

	if err := validate.Required("cid", "body", m.Cid); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateCloudAccountID(formats strfmt.Registry) error {

	if err := validate.Required("cloud_account_id", "body", m.CloudAccountID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateCloudName(formats strfmt.Registry) error {

	if err := validate.Required("cloud_name", "body", m.CloudName); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateCloudRegion(formats strfmt.Registry) error {

	if err := validate.Required("cloud_region", "body", m.CloudRegion); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateClusterID(formats strfmt.Registry) error {

	if err := validate.Required("cluster_id", "body", m.ClusterID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateClusterName(formats strfmt.Registry) error {

	if err := validate.Required("cluster_name", "body", m.ClusterName); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateContainerCount(formats strfmt.Registry) error {

	if err := validate.Required("container_count", "body", m.ContainerCount); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateContainers(formats strfmt.Registry) error {

	if err := validate.Required("containers", "body", m.Containers); err != nil {
		return err
	}

	for i := 0; i < len(m.Containers); i++ {

		if m.Containers[i] != nil {
			if err := m.Containers[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("containers" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("containers" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ModelsPod) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("created_at", "body", m.CreatedAt); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateFirstSeen(formats strfmt.Registry) error {

	if err := validate.Required("first_seen", "body", m.FirstSeen); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateHostIpc(formats strfmt.Registry) error {

	if err := validate.Required("host_ipc", "body", m.HostIpc); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateHostNetwork(formats strfmt.Registry) error {

	if err := validate.Required("host_network", "body", m.HostNetwork); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateHostPid(formats strfmt.Registry) error {

	if err := validate.Required("host_pid", "body", m.HostPid); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateImagePullSecrets(formats strfmt.Registry) error {

	if err := validate.Required("image_pull_secrets", "body", m.ImagePullSecrets); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateIPV4(formats strfmt.Registry) error {

	if err := validate.Required("ipv4", "body", m.IPV4); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateIPV6(formats strfmt.Registry) error {

	if err := validate.Required("ipv6", "body", m.IPV6); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateLabels(formats strfmt.Registry) error {

	if err := validate.Required("labels", "body", m.Labels); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateLabelsList(formats strfmt.Registry) error {

	if err := validate.Required("labels_list", "body", m.LabelsList); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateLastSeen(formats strfmt.Registry) error {

	if err := validate.Required("last_seen", "body", m.LastSeen); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateNamespace(formats strfmt.Registry) error {

	if err := validate.Required("namespace", "body", m.Namespace); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateNodeIPV4(formats strfmt.Registry) error {

	if err := validate.Required("node_ipv4", "body", m.NodeIPV4); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateNodeName(formats strfmt.Registry) error {

	if err := validate.Required("node_name", "body", m.NodeName); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateNodeSelector(formats strfmt.Registry) error {

	if err := validate.Required("node_selector", "body", m.NodeSelector); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateNodeUID(formats strfmt.Registry) error {

	if err := validate.Required("node_uid", "body", m.NodeUID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateOwnerID(formats strfmt.Registry) error {

	if err := validate.Required("owner_id", "body", m.OwnerID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateOwnerType(formats strfmt.Registry) error {

	if err := validate.Required("owner_type", "body", m.OwnerType); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validatePodExternalID(formats strfmt.Registry) error {

	if err := validate.Required("pod_external_id", "body", m.PodExternalID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validatePodID(formats strfmt.Registry) error {

	if err := validate.Required("pod_id", "body", m.PodID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validatePodName(formats strfmt.Registry) error {

	if err := validate.Required("pod_name", "body", m.PodName); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validatePorts(formats strfmt.Registry) error {

	if err := validate.Required("ports", "body", m.Ports); err != nil {
		return err
	}

	for i := 0; i < len(m.Ports); i++ {

		if m.Ports[i] != nil {
			if err := m.Ports[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ports" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ports" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ModelsPod) validatePrivileged(formats strfmt.Registry) error {

	if err := validate.Required("privileged", "body", m.Privileged); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateResourceStatus(formats strfmt.Registry) error {

	if err := validate.Required("resource_status", "body", m.ResourceStatus); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateRootWriteAccess(formats strfmt.Registry) error {

	if err := validate.Required("root_write_access", "body", m.RootWriteAccess); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateRunAsRootGroup(formats strfmt.Registry) error {

	if err := validate.Required("run_as_root_group", "body", m.RunAsRootGroup); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateRunAsRootUser(formats strfmt.Registry) error {

	if err := validate.Required("run_as_root_user", "body", m.RunAsRootUser); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateSchedulerName(formats strfmt.Registry) error {

	if err := validate.Required("scheduler_name", "body", m.SchedulerName); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateServiceAccountName(formats strfmt.Registry) error {

	if err := validate.Required("service_account_name", "body", m.ServiceAccountName); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateShareProcessNamespace(formats strfmt.Registry) error {

	if err := validate.Required("share_process_namespace", "body", m.ShareProcessNamespace); err != nil {
		return err
	}

	return nil
}

func (m *ModelsPod) validateVolumeMounts(formats strfmt.Registry) error {

	if err := validate.Required("volume_mounts", "body", m.VolumeMounts); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this models pod based on the context it is used
func (m *ModelsPod) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAgents(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateContainers(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePorts(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsPod) contextValidateAgents(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Agents); i++ {

		if swag.IsZero(m.Agents[i]) { // not required
			return nil
		}

		if err := m.Agents[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("agents" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("agents" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *ModelsPod) contextValidateContainers(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Containers); i++ {

		if swag.IsZero(m.Containers[i]) { // not required
			return nil
		}

		if err := m.Containers[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("containers" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("containers" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *ModelsPod) contextValidatePorts(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Ports); i++ {

		if swag.IsZero(m.Ports[i]) { // not required
			return nil
		}

		if err := m.Ports[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ports" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ports" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ModelsPod) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsPod) UnmarshalBinary(b []byte) error {
	var res ModelsPod
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
