
# gofalcon ![Build CI](https://github.com/CrowdStrike/gofalcon/workflows/Build%20CI/badge.svg) [![Go Reference](https://pkg.go.dev/badge/github.com/crowdstrike/gofalcon.svg)](https://pkg.go.dev/github.com/crowdstrike/gofalcon)
Golang-based SDK to CrowdStrike's Falcon APIs.

Detailed API documentation is available on [pkg.go.dev](https://pkg.go.dev/github.com/crowdstrike/gofalcon). The easiest way to learn about the SDK is to consult set of [examples](examples) built on top of the SDK. What follows is a sub-set of these examples that can be found useful as stand-alone programs.

 * [falcon_sensor_download](examples/falcon_sensor_download) - stand-alone tool that can be used to download CrowdStrike Falcon Sensor
 * [falcon_event_stream](examples/falcon_event_stream) - stand-alone tool that can be used to stream events as they happen in CrowdStrike Falcon Console
 * [falcon_cleanup_pods](examples/falcon_cleanup_pods) - stand-alone tool that can be used to clean-up inactive pods from CrowdStrike Falcon Console
 * [falcon_iocs](examples/falcon_iocs) - stand-alone tool that can be used to add, delete or list Custom IOCs in the CrowdStrike Falcon Console
 * [falcon_host_details](examples/falcon_host_details) - stand-alone tool that outputs inventory of hosts registered to CrowdStrike Falcon platform

Gofalcon is an open source project, not CrowdStrike product. As such it carries
no formal support, expressed or implied.

gofalcon is periodically refreshed to reflect newest additions to the CrowdStrike API. Users of the SDK are advised to track the latest releases rather closely to ensure proper function; should the unlikely event of incompatible change to CrowdStrike API occur.

## Installation
```
go get github.com/CrowdStrike/gofalcon/falcon
```

## Usage Example

Various real-life examples can be found in the [examples/](examples/) directory. The bare minimum example follows.

```go
package main

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/incidents"
)

func main() {
	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId: "FILL-IN-HERE",
		ClientSecret: "FILL-IN-HERE",
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
