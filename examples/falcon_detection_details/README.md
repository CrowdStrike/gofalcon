# Falcon Detection Details

Stand-alone tool that uses Detects API to query all the detection details and output JSON to the stdout. This tool can be used together with JSON parsing tools like `jq` in order to build reports of your liking.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_detection_details
```

## Exemplary Usage

Get full details of all the detections

```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_detection_details
```

Get total number of all detections

```
falcon_detection_details | jq length
```

List command-line of the processes that triggered detection.
```
falcon_detection_details  | jq 'map(.behaviors[].cmdline)'
```

List affected hostnames and the command-lines together as a key-value dictionary. (Note: this will only show the very latest detection per each hostname, when the hostname was associated with multiple detections)
```
falcon_detection_details  | jq -r ' map( { (.device.hostname) : .behaviors[].cmdline } ) | add'
```

List detections that have not yet been assigned to a responsible person
```
$ falcon_detection_details --filter="assigned_to_uid:NULL"
```

Please refer to [Falcon Detection Monitoring API documentation](https://falcon.crowdstrike.com/documentation/86/detections-monitoring-apis) to learn more about FQL filter parameter, the meaning of the entity properties, and best practices.
Further, please refer to [jq tool manual](https://stedolan.github.io/jq/manual/) to learn how to effectively post-process JSON outputs in command-line.

