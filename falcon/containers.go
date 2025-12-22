package falcon

import (
	"fmt"
)

type SensorType string

const (
	SidecarSensor         SensorType = "falcon-container"
	ImageSensor           SensorType = "falcon-imageanalyzer"
	RegionedImageSensor   SensorType = "falcon-imageanalyzer-regioned"
	KacSensor             SensorType = "falcon-kac"
	NodeSensor            SensorType = "falcon-sensor"
	RegionedNodeSensor    SensorType = "falcon-sensor-regioned"
	RegionedKacSensor     SensorType = "falcon-kac-regioned"
	RegionedSidecarSensor SensorType = "falcon-container-regioned"
	Snapshot              SensorType = "falcon-snapshot"
	FCSCli                SensorType = "fcs"
	SHRAController        SensorType = "falcon-jobcontroller"
	SHRAExecutor          SensorType = "falcon-registryassessmentexecutor"
)

// FalconContainerUploadURI parses cloud string (example: us-1, us-2, eu-1, us-gov-1, etc) and returns a URI for uploading a container image for ImageAssessment.
func FalconContainerUploadURI(falconCloud CloudType) string {
	switch falconCloud {
	default:
		fallthrough
	case CloudUs1:
		return "container-upload.us-1.crowdstrike.com"
	case CloudUs2:
		return "container-upload.us-2.crowdstrike.com"
	case CloudEu1:
		return "container-upload.eu-1.crowdstrike.com"
	case CloudUsGov1:
		return "container-upload.laggar.gcw.crowdstrike.com"
	case CloudGov1:
		return "container-upload.laggar.gcw.crowdstrike.com"
	case CloudUsGov2:
		return "container-upload.us-gov-2.crowdstrike.mil"
	case CloudGov2:
		return "container-upload.us-gov-2.crowdstrike.mil"
	}
}

// FalconContainerSensorImageURI returns a URI for downloading a container sensor image. Defaults to the falcon-sensor image.
// When the Falcon Cloud CloudType is set to CloudAutoDiscover, be sure to provide the results of ApiConfig.Cloud after the client
// has been initialized to ensure the correct CloudType is used and not CloudAutoDiscover.
func FalconContainerSensorImageURI(falconCloud CloudType, sensorType SensorType) string {
	switch sensorType {
	case SidecarSensor:
		return fmt.Sprintf("%s/falcon-container/release/falcon-container", registryFQDN(falconCloud))
	case ImageSensor:
		return fmt.Sprintf("%s/falcon-imageanalyzer/release/falcon-imageanalyzer", registryFQDN(falconCloud))
	case RegionedImageSensor:
		return fmt.Sprintf("%s/falcon-imageanalyzer/%s/release/falcon-imageanalyzer", registryFQDN(falconCloud), registryCloud(falconCloud))
	case KacSensor:
		return fmt.Sprintf("%s/falcon-kac/release/falcon-kac", registryFQDN(falconCloud))
	case NodeSensor:
		return fmt.Sprintf("%s/falcon-sensor/release/falcon-sensor", registryFQDN(falconCloud))
	case RegionedNodeSensor:
		return fmt.Sprintf("%s/falcon-sensor/%s/release/falcon-sensor", registryFQDN(falconCloud), registryCloud(falconCloud))
	case RegionedKacSensor:
		return fmt.Sprintf("%s/falcon-kac/%s/release/falcon-kac", registryFQDN(falconCloud), registryCloud(falconCloud))
	case RegionedSidecarSensor:
		return fmt.Sprintf("%s/falcon-container/%s/release/falcon-sensor", registryFQDN(falconCloud), registryCloud(falconCloud))
	case Snapshot:
		return fmt.Sprintf("%s/falcon-snapshot/%s/release/cs-snapshotscanner", registryFQDN(falconCloud), registryCloud(falconCloud))
	case FCSCli:
		return fmt.Sprintf("%s/fcs/%s/release/cs-fcs", registryFQDN(falconCloud), registryCloud(falconCloud))
	case SHRAController:
		return fmt.Sprintf("%s/falcon-selfhostedregistryassessment/release/falcon-jobcontroller", registryFQDN(falconCloud))
	case SHRAExecutor:
		return fmt.Sprintf("%s/falcon-selfhostedregistryassessment/release/falcon-registryassessmentexecutor", registryFQDN(falconCloud))
	default:
		return fmt.Sprintf("%s/falcon-sensor/release/falcon-sensor", registryFQDN(falconCloud))
	}
}

func registryFQDN(cloud CloudType) string {
	switch cloud {
	case CloudUsGov1:
		return "registry.laggar.gcw.crowdstrike.com"
	case CloudGov1:
		return "registry.laggar.gcw.crowdstrike.com"
	case CloudUsGov2:
		return "registry.us-gov-2.crowdstrike.mil"
	case CloudGov2:
		return "registry.us-gov-2.crowdstrike.mil"
	default:
		return "registry.crowdstrike.com"
	}
}

func registryCloud(cloud CloudType) string {
	switch cloud {
	case CloudUsGov1:
		return "gov1"
	case CloudUsGov2:
		return "gov2"
	default:
		return cloud.String()
	}
}
