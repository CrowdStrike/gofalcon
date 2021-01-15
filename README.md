
# gofalcon ![Build CI](https://github.com/CrowdStrike/gofalcon/workflows/Build%20CI/badge.svg)
Golang-based SDK to CrowdStrike's Falcon APIs.

Gofalcon is an open source project, not CrowdStrike product. As such it carries
no formal support, expressed or implied.

This is pre-release version of the SDK.

## Installation
```
go get github.com/CrowdStrike/gofalcon/falcon
```

## Usage Example
```
package main

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
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

More examples can be found in the [examples/](https://github.com/CrowdStrike/gofalcon/tree/main/examples) directory.
