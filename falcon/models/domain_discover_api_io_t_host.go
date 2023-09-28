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

// DomainDiscoverAPIIoTHost Represents information about a managed, an unmanaged or an unsupported asset.
//
// swagger:model domain.DiscoverAPIIoTHost
type DomainDiscoverAPIIoTHost struct {

	// The version of the Falcon sensor that's installed on the asset.
	AgentVersion string `json:"agent_version,omitempty"`

	// The agent ID of the Falcon sensor installed on the asset.
	Aid string `json:"aid,omitempty"`

	// The Amount of available disk space on the asset in GB
	AvailableDiskSpace int32 `json:"available_disk_space,omitempty"`

	// The average memory usage in the last 15 minutes on the asset
	AverageMemoryUsage int32 `json:"average_memory_usage,omitempty"`

	// The average processor usage in the last 15 minutes on the asset
	AverageProcessorUsage int32 `json:"average_processor_usage,omitempty"`

	// The id of the bios on the asset
	BiosID string `json:"bios_id,omitempty"`

	// The name of the asset's BIOS manufacturer.
	BiosManufacturer string `json:"bios_manufacturer,omitempty"`

	// The asset's BIOS version.
	BiosVersion string `json:"bios_version,omitempty"`

	// The business criticality of the IoT asset.
	BusinessCriticality string `json:"business_criticality,omitempty"`

	// The asset's customer ID.
	// Required: true
	Cid *string `json:"cid"`

	// The name of the city where the asset is located.
	City string `json:"city,omitempty"`

	// The external ID of the IoT Device in 3rd Party System(Claroty).
	ClarotyID string `json:"claroty_id,omitempty"`

	// Whether the asset is exposed to the internet (Yes or Unknown)
	ComputedInternetExposure string `json:"computed_internet_exposure,omitempty"`

	// External IP that is exposed to the Internet
	ComputedInternetExposureExternalIP string `json:"computed_internet_exposure_external_ip,omitempty"`

	// Timestamp when the asset was last seen as exposed to the Internet
	ComputedInternetExposureLastSeen string `json:"computed_internet_exposure_last_seen,omitempty"`

	// The level of confidence that the asset is a corporate asset (25 = low confidence, 50 = medium confidence, 75 = high confidence).
	Confidence int32 `json:"confidence,omitempty"`

	// The name of the country where the asset is located.
	Country string `json:"country,omitempty"`

	// The Detailed processor name
	CPUProcessorName string `json:"cpu_processor_name,omitempty"`

	// The credential guard status of the asset
	CredentialGuardStatus bool `json:"credential_guard_status,omitempty"`

	// The last seen local IPv4 address of the asset.
	CurrentLocalIP string `json:"current_local_ip,omitempty"`

	// The asset's data providers.
	DataProviders []string `json:"data_providers"`

	// The number of data providers for the asset.
	DataProvidersCount int32 `json:"data_providers_count,omitempty"`

	// The Device Class of IoT Asset
	DeviceClass string `json:"device_class,omitempty"`

	// The Device Family of IoT Asset
	DeviceFamily string `json:"device_family,omitempty"`

	// The device guard status of the asset
	DeviceGuardStatus bool `json:"device_guard_status,omitempty"`

	// The slots of IoT Asset
	DeviceSlots []*DomainDiscoverAPIDeviceSlot `json:"device_slots"`

	// The Device Type of IoT Asset
	DeviceType string `json:"device_type,omitempty"`

	// The number of sources that discovered the asset.
	DiscovererCount int32 `json:"discoverer_count,omitempty"`

	// A list of agent IDs of the Falcon sensors installed on the source hosts that discovered the asset via ICS Asset discovery mechanism
	DiscovererIcsCollectorIds []string `json:"discoverer_ics_collector_ids"`

	// The product type descriptions of the sources that discovered the asset.
	DiscovererProductTypeDescs []string `json:"discoverer_product_type_descs"`

	// The names and sizes of the disks on the asset
	DiskSizes []*DomainDiscoverAPIDiskSize `json:"disk_sizes"`

	// The ID generated by dragos asset discovery mechanism
	DragosID string `json:"dragos_id,omitempty"`

	// The list of encrypted drives on the asset
	EncryptedDrives []string `json:"encrypted_drives"`

	// The count of encrypted drives on the asset
	EncryptedDrivesCount int32 `json:"encrypted_drives_count,omitempty"`

	// The encryption status of the asset
	EncryptionStatus string `json:"encryption_status,omitempty"`

	// The type of asset (managed, unmanaged, unsupported).
	EntityType string `json:"entity_type,omitempty"`

	// The external IPv4 address of the asset.
	ExternalIP string `json:"external_ip,omitempty"`

	// Lists the data providers for each property in the response (Cannot be used for filtering, sorting, or querying).
	FieldMetadata map[string]DomainDiscoverAPIFieldMetadata `json:"field_metadata,omitempty"`

	// The first time the asset was seen in your environment.
	FirstSeenTimestamp string `json:"first_seen_timestamp,omitempty"`

	// The host management groups the asset is part of.
	Groups []string `json:"groups"`

	// The asset's hostname .
	Hostname string `json:"hostname,omitempty"`

	// The ID generated by ICS collector asset discovery mechanism
	IcsID string `json:"ics_id,omitempty"`

	// The unique ID of the asset.
	// Required: true
	ID *string `json:"id"`

	// Whether the asset is exposed to the internet (Yes or Unknown)
	InternetExposure string `json:"internet_exposure,omitempty"`

	// The iommu protection status of the host
	IommuProtectionStatus string `json:"iommu_protection_status,omitempty"`

	// The kernel dma protection status of the asset
	KernelDmaProtectionStatus bool `json:"kernel_dma_protection_status,omitempty"`

	// For Linux and Mac hosts: the major version, minor version, and patch version of the kernel for the asset. For Windows hosts: the build number of the asset.
	KernelVersion string `json:"kernel_version,omitempty"`

	// The agent ID of the Falcon sensor installed on the source host that most recently discovered the asset via ICS Asset discovery mechanism
	LastDiscovererIcsCollectorID string `json:"last_discoverer_ics_collector_id,omitempty"`

	// The most recent time the asset was seen in your environment.
	LastSeenTimestamp string `json:"last_seen_timestamp,omitempty"`

	// The IoT asset's IP address list
	LocalIPAddresses []string `json:"local_ip_addresses"`

	// The number of historical local IPv4 addresses the asset has had.
	LocalIpsCount int32 `json:"local_ips_count,omitempty"`

	// The Number of Logical Cores on the asset
	LogicalCoreCount int32 `json:"logical_core_count,omitempty"`

	// The IoT asset's MAC address list
	MacAddresses []string `json:"mac_addresses"`

	// The domain name the asset is currently joined to (applies only to Windows hosts).
	MachineDomain string `json:"machine_domain,omitempty"`

	// The max memory usage in the last 15 minutes on the asset
	MaxMemoryUsage int32 `json:"max_memory_usage,omitempty"`

	// The max processor usage in the last 15 minutes on the asset
	MaxProcessorUsage int32 `json:"max_processor_usage,omitempty"`

	// The Total memory.
	MemoryTotal int64 `json:"memory_total,omitempty"`

	// The path, used and available space on mounted disks
	MountStorageInfo []*DomainDiscoverAPIMountStorageInfo `json:"mount_storage_info"`

	// The network ID to which device is connected.
	NetworkID string `json:"network_id,omitempty"`

	// The asset's network interfaces.
	NetworkInterfaces []*DomainDiscoverAPINetworkInterface `json:"network_interfaces"`

	// The number of active physical drives available on the system
	NumberOfDiskDrives int32 `json:"number_of_disk_drives,omitempty"`

	// Whether the asset is at end of support (Yes, No, or Unknown)
	OsIsEol string `json:"os_is_eol,omitempty"`

	// The OS version of the asset.
	OsVersion string `json:"os_version,omitempty"`

	// The organizational unit of the asset (applies only to Windows hosts).
	Ou string `json:"ou,omitempty"`

	// The number of physical CPU cores available on the system
	PhysicalCoreCount int32 `json:"physical_core_count,omitempty"`

	// The platform name of the asset (Windows, Mac, Linux).
	PlatformName string `json:"platform_name,omitempty"`

	// The number of physical processors available on the system
	ProcessorPackageCount int32 `json:"processor_package_count,omitempty"`

	// The product type of the asset represented as a number (1 = Workstation, 2 = Domain Controller, 3 = Server).
	ProductType string `json:"product_type,omitempty"`

	// The product type of the asset (Workstation, Domain Controller, Server).
	ProductTypeDesc string `json:"product_type_desc,omitempty"`

	// The list of protocols supported by the device
	Protocols []string `json:"protocols"`

	// The purdue level of IoT Asset
	PurdueLevel string `json:"purdue_level,omitempty"`

	// Whether the asset is in reduced functionality mode (Yes or No)
	ReducedFunctionalityMode string `json:"reduced_functionality_mode,omitempty"`

	// The secure boot enabled status of the asset
	SecureBootEnabledStatus bool `json:"secure_boot_enabled_status,omitempty"`

	// The secure boot requested status of the asset
	SecureBootRequestedStatus bool `json:"secure_boot_requested_status,omitempty"`

	// The secure memory overwrite requested status of the asset
	SecureMemoryOverwriteRequestedStatus string `json:"secure_memory_overwrite_requested_status,omitempty"`

	// The site name of the domain the asset is joined to (applies only to Windows hosts).
	SiteName string `json:"site_name,omitempty"`

	// The subnet to which device is connected.
	Subnet string `json:"subnet,omitempty"`

	// The system guard status of the asset
	SystemGuardStatus string `json:"system_guard_status,omitempty"`

	// The asset's system manufacturer.
	SystemManufacturer string `json:"system_manufacturer,omitempty"`

	// The asset's system product name.
	SystemProductName string `json:"system_product_name,omitempty"`

	// The asset's system serial number.
	SystemSerialNumber string `json:"system_serial_number,omitempty"`

	// The sensor and cloud tags of the asset.
	Tags []string `json:"tags"`

	// The count of bios files measured by the firmware image
	TotalBiosFiles int32 `json:"total_bios_files,omitempty"`

	// The Total amount of disk space available on the asset in GB
	TotalDiskSpace int32 `json:"total_disk_space,omitempty"`

	// The uefi memory protection status of the asset
	UefiMemoryProtectionStatus string `json:"uefi_memory_protection_status,omitempty"`

	// The list of unencrypted drives on the asset
	UnencryptedDrives []string `json:"unencrypted_drives"`

	// The count of unencrypted drives on the asset
	UnencryptedDrivesCount int32 `json:"unencrypted_drives_count,omitempty"`

	// The Current amount of used disk space on the asset in GB
	UsedDiskSpace int32 `json:"used_disk_space,omitempty"`

	// The Virtual Zone name in which device is installed.
	VirtualZone string `json:"virtual_zone,omitempty"`

	// The virtualization based security status of the asset
	VirtualizationBasedSecurityStatus bool `json:"virtualization_based_security_status,omitempty"`

	// The VLAN IDs to which device is connected.
	Vlan []string `json:"vlan"`

	// The external ID of the IoT Device in 3rd Party System(Claroty Xdome)
	XdomeID string `json:"xdome_id,omitempty"`
}

// Validate validates this domain discover API io t host
func (m *DomainDiscoverAPIIoTHost) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeviceSlots(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDiskSizes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFieldMetadata(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMountStorageInfo(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNetworkInterfaces(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainDiscoverAPIIoTHost) validateCid(formats strfmt.Registry) error {

	if err := validate.Required("cid", "body", m.Cid); err != nil {
		return err
	}

	return nil
}

func (m *DomainDiscoverAPIIoTHost) validateDeviceSlots(formats strfmt.Registry) error {
	if swag.IsZero(m.DeviceSlots) { // not required
		return nil
	}

	for i := 0; i < len(m.DeviceSlots); i++ {
		if swag.IsZero(m.DeviceSlots[i]) { // not required
			continue
		}

		if m.DeviceSlots[i] != nil {
			if err := m.DeviceSlots[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("device_slots" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("device_slots" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainDiscoverAPIIoTHost) validateDiskSizes(formats strfmt.Registry) error {
	if swag.IsZero(m.DiskSizes) { // not required
		return nil
	}

	for i := 0; i < len(m.DiskSizes); i++ {
		if swag.IsZero(m.DiskSizes[i]) { // not required
			continue
		}

		if m.DiskSizes[i] != nil {
			if err := m.DiskSizes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("disk_sizes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("disk_sizes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainDiscoverAPIIoTHost) validateFieldMetadata(formats strfmt.Registry) error {
	if swag.IsZero(m.FieldMetadata) { // not required
		return nil
	}

	for k := range m.FieldMetadata {

		if err := validate.Required("field_metadata"+"."+k, "body", m.FieldMetadata[k]); err != nil {
			return err
		}
		if val, ok := m.FieldMetadata[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("field_metadata" + "." + k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("field_metadata" + "." + k)
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainDiscoverAPIIoTHost) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *DomainDiscoverAPIIoTHost) validateMountStorageInfo(formats strfmt.Registry) error {
	if swag.IsZero(m.MountStorageInfo) { // not required
		return nil
	}

	for i := 0; i < len(m.MountStorageInfo); i++ {
		if swag.IsZero(m.MountStorageInfo[i]) { // not required
			continue
		}

		if m.MountStorageInfo[i] != nil {
			if err := m.MountStorageInfo[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("mount_storage_info" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("mount_storage_info" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainDiscoverAPIIoTHost) validateNetworkInterfaces(formats strfmt.Registry) error {
	if swag.IsZero(m.NetworkInterfaces) { // not required
		return nil
	}

	for i := 0; i < len(m.NetworkInterfaces); i++ {
		if swag.IsZero(m.NetworkInterfaces[i]) { // not required
			continue
		}

		if m.NetworkInterfaces[i] != nil {
			if err := m.NetworkInterfaces[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("network_interfaces" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("network_interfaces" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this domain discover API io t host based on the context it is used
func (m *DomainDiscoverAPIIoTHost) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDeviceSlots(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDiskSizes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFieldMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMountStorageInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNetworkInterfaces(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainDiscoverAPIIoTHost) contextValidateDeviceSlots(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.DeviceSlots); i++ {

		if m.DeviceSlots[i] != nil {

			if swag.IsZero(m.DeviceSlots[i]) { // not required
				return nil
			}

			if err := m.DeviceSlots[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("device_slots" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("device_slots" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainDiscoverAPIIoTHost) contextValidateDiskSizes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.DiskSizes); i++ {

		if m.DiskSizes[i] != nil {

			if swag.IsZero(m.DiskSizes[i]) { // not required
				return nil
			}

			if err := m.DiskSizes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("disk_sizes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("disk_sizes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainDiscoverAPIIoTHost) contextValidateFieldMetadata(ctx context.Context, formats strfmt.Registry) error {

	for k := range m.FieldMetadata {

		if val, ok := m.FieldMetadata[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	return nil
}

func (m *DomainDiscoverAPIIoTHost) contextValidateMountStorageInfo(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.MountStorageInfo); i++ {

		if m.MountStorageInfo[i] != nil {

			if swag.IsZero(m.MountStorageInfo[i]) { // not required
				return nil
			}

			if err := m.MountStorageInfo[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("mount_storage_info" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("mount_storage_info" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainDiscoverAPIIoTHost) contextValidateNetworkInterfaces(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.NetworkInterfaces); i++ {

		if m.NetworkInterfaces[i] != nil {

			if swag.IsZero(m.NetworkInterfaces[i]) { // not required
				return nil
			}

			if err := m.NetworkInterfaces[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("network_interfaces" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("network_interfaces" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainDiscoverAPIIoTHost) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainDiscoverAPIIoTHost) UnmarshalBinary(b []byte) error {
	var res DomainDiscoverAPIIoTHost
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
