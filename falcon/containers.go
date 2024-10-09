package falcon

import (
	"fmt"
)

type SensorType string

const (
	SidecarSensor SensorType = "falcon-container"
	ImageSensor   SensorType = "falcon-imageanalyzer"
	KacSensor     SensorType = "falcon-kac"
	NodeSensor    SensorType = "falcon-sensor"
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
	case CloudGov2:
		return "container-upload.us-gov-2.crowdstrike.mil"
	}
}

// FalconContainerSensorImageURI returns a URI for downloading a container sensor image. Defaults to the falcon-sensor image.
func FalconContainerSensorImageURI(falconCloud CloudType, sensorType SensorType) string {
	switch sensorType {
	case SidecarSensor:
		return fmt.Sprintf("%s/falcon-container/%s/release/falcon-sensor", registryFQDN(falconCloud), registryCloud(falconCloud))
	case ImageSensor:
		return fmt.Sprintf("%s/falcon-imageanalyzer/%s/release/falcon-imageanalyzer", registryFQDN(falconCloud), registryCloud(falconCloud))
	case KacSensor:
		return fmt.Sprintf("%s/falcon-kac/%s/release/falcon-kac", registryFQDN(falconCloud), registryCloud(falconCloud))
	case NodeSensor:
		return fmt.Sprintf("%s/falcon-sensor/%s/release/falcon-sensor", registryFQDN(falconCloud), registryCloud(falconCloud))
	default:
		return fmt.Sprintf("%s/falcon-sensor/%s/release/falcon-sensor", registryFQDN(falconCloud), registryCloud(falconCloud))
	}
}

func registryFQDN(cloud CloudType) string {
	switch cloud {
	case CloudUsGov1:
		return "registry.laggar.gcw.crowdstrike.com"
	case CloudGov1:
		return "registry.laggar.gcw.crowdstrike.com"
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
	default:
		return cloud.String()
	}
}
