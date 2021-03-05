
# gofalcon ![Build CI](https://github.com/CrowdStrike/gofalcon/workflows/Build%20CI/badge.svg) [![Go Reference](https://pkg.go.dev/badge/github.com/crowdstrike/gofalcon.svg)](https://pkg.go.dev/github.com/crowdstrike/gofalcon)
Golang-based SDK to CrowdStrike's Falcon APIs.

Gofalcon is an open source project, not CrowdStrike product. As such it carries
no formal support, expressed or implied.

This is pre-release version of the SDK.

## Installation
```
go get github.com/CrowdStrike/gofalcon/falcon
```

## Usage Example

Various real-life examples can be found in the [examples/](examples/) directory. The bare minimum example follows.

```
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
