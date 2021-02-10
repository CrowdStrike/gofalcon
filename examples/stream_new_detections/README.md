# New Detection Streaming

Stream new detections as they are happening in CrowdStrike Falcon Console.
This limited example uses active polling to the API to pick-up new detections.

To learn more about detection and how to generate your first detection visit [CrowdStrike Blog](https://www.crowdstrike.com/blog/tech-center/generate-your-first-detection/)

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/stream_new_detections
```

## Example Run

```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" stream_new_detections
```
