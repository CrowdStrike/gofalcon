# gofalcon
![Build CI](https://github.com/CrowdStrike/gofalcon/workflows/Build%20CI/badge.svg)
[![CodeQL](https://github.com/CrowdStrike/gofalcon/actions/workflows/codeql.yml/badge.svg)](https://github.com/CrowdStrike/gofalcon/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/crowdstrike/gofalcon)](https://goreportcard.com/report/github.com/crowdstrike/gofalcon)
[![Go Reference](https://pkg.go.dev/badge/github.com/crowdstrike/gofalcon.svg)](https://pkg.go.dev/github.com/crowdstrike/gofalcon)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/CrowdStrike/gofalcon)

Golang-based SDK to CrowdStrike's Falcon APIs.

Gofalcon documentation is available on [pkg.go.dev](https://pkg.go.dev/github.com/crowdstrike/gofalcon). Users are advised to consult this gofalcon documentation together with the comprehensive CrowdStrike API documentation published on [Developer Center](https://developer.crowdstrike.com/docs/openapi). The easiest way to learn about the SDK is to consult the set of [examples](examples) built on top of the SDK. What follows is a subset of these examples that can be found useful as stand-alone programs.

| Example                                                                       | Description                                                                                                                         |
| :--------                                                                     | :------------                                                                                                                       |
| [falcon_sensor_download](examples/falcon_sensor_download)                     | stand-alone tool that can be used to download CrowdStrike Falcon Sensor                                                             |
| [falcon_event_stream](examples/falcon_event_stream)                           | stand-alone tool that can be used to stream events as they happen in CrowdStrike Falcon Console                                     |
| [falcon_cleanup_pods](examples/falcon_cleanup_pods)                           | stand-alone tool that can be used to clean-up inactive pods from CrowdStrike Falcon Console                                         |
| [falcon_cspm_ioms](examples/falcon_cspm_ioms)                                 | stand-alone tool that leverages CrowdStrike Cloud Security Posture Management (CSPM) to list indicators of misconfigurations (IOMs) |
| [falcon_detection_details](examples/falcon_detection_details)                 | stand-alone tool that outputs inventory of all Falcon Detections based on custom filter                                             |
| [falcon_discover_host_details](examples/falcon_discover_host_details)         | stand-alone tool that can be used for auditing purposes and for gaining timely visibility into your environment                     |
| [falcon_get_cid](examples/falcon_get_cid)                                     | stand-alone tool that can be used to get Customer ID based on the API key pair                                                      |
| [falcon_iocs](examples/falcon_iocs)                                           | stand-alone tool that can be used to add, delete or list Custom IOCs in the CrowdStrike Falcon Console                              |
| [falcon_intel_indicators](examples/falcon_intel_indicators)                   | stand-alone tool that queries CrowdStrike Intelligence Indicators                                                                   |
| [falcon_intel_rules_download](examples/falcon_intel_rules_download)           | stand-alone tool that downloads CrowdStrike Falcon Intelligence Rule files                                                          |
| [falcon_host_details](examples/falcon_host_details)                           | stand-alone tool that outputs inventory of hosts registered to CrowdStrike Falcon platform                                          |
| [falcon_registry_token](examples/falcon_registry_token)                       | helper to generate container registry logic information for `docker login`                                                          |
| [falcon_rtr_read_only_command](examples/falcon_rtr_read_only_command)         | stand-alone example to run basic read-only RTR (Real-Time Response) command against a specific agent                                |
| [falcon_rtr_admin_create_and_run_script](examples/falcon_rtr_admin_create_and_run_script) | stand-alone example of running custom script on the specific agent using RTR (Real-Time Response) API                               |
| [falcon_vulnerabilities](examples/falcon_vulnerabilities) | stand-alone tool that outputs inventory of vulnerabilities affecting your environment                                               |
| [falcon_supported_kernels](examples/falcon_supported_kernels)                 | stand-alone tool that outputs short list recent Linux kernels supported by CrowdStrike Falcon for a given distribution              |
| [falcon_zta](examples/falcon_zta)                                             | stand-alone tool that utilises Hosts and ZTA APIs and outputs ZTA findings for your environment                                     |
| [customize_transport](examples/customize_transport)                           | use a falcon.TransportDecorator to modify all outgoing HTTP requests to the Falcon API |

Gofalcon is a community-driven, open source project designed to aid developers in utilizing the CrowdStrike APIs effectively within their applications. While not a formal CrowdStrike product, Gofalcon is maintained by CrowdStrike and supported in partnership with the open source developer community.

Gofalcon is periodically refreshed to reflect the newest additions to the CrowdStrike API. Users of the SDK are advised to track the latest releases rather closely to ensure proper function in the unlikely event of an incompatible change to a CrowdStrike API.

## Installation
```
go get github.com/crowdstrike/gofalcon/falcon
```

## Usage Example

Various real-life examples can be found in the [examples/](examples/) directory. The bare minimum example follows.

```go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/incidents"
)

func main() {
	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId: os.Getenv("FALCON_CLIENT_ID"),
		ClientSecret: os.Getenv("FALCON_CLIENT_SECRET"),
		Context: context.Background(),
	})
	if err != nil {
		panic(err)
	}

	desc := "timestamp.desc"
	res, err := client.Incidents.CrowdScore(&incidents.CrowdScoreParams{
		Context: context.Background(),
		Sort: &desc,
	})
	if err != nil {
		panic(err)
	}
	payload := res.GetPayload()
	fmt.Printf("As of %s your CrowdScore is %d.\n",
		payload.Resources[0].Timestamp.String(), *payload.Resources[0].Score)
}
```

## Versioning

This module adheres to the Go Module version numbering system, as described in detail at [Go Module version numbering](https://go.dev/doc/modules/version-numbers).

It is important to note that since this module is currently in the `v0.x.x` stage, backward compatibility cannot be guaranteed between minor versions (`vMAJOR.MINOR.PATCH`). Any breaking changes that may occur between versions will be explicitly mentioned in the release notes. It is highly recommended to pin the version of this module in your `go.mod` file to a specific patch version, and to update it only after reviewing the release notes and thorough testing.

