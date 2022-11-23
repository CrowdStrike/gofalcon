# Falcon Threat Intelligence Indicators

This page represents a stand-alone tool that uses Falcon Intelligence API to query the Intel Indicators and outputs those vulnerabilities in JSON format to the stdout. This tool can be used together with JSON parsing tools like `jq` in order to build reports of your liking.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_intel_indicators
```

## Exemplary Usage

Interactive Run:
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_intel_indicators
Missing --filter attribute. Please provide FQL (Falcon Query Language) expression for Intelligence Indicators search.
filter:
```

Providing FQL filter on command-line and counting the results.
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_intel_indicators \
      --filter="type:'url'+malicious_confidence:'Medium'"  | jq length
```

Filter out all the IOCs that have been deleted:
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_intel_indicators \
      --filter="deleted:false"  | jq length
```

Please Refer to [Falcon Intel API documentation](https://falcon.crowdstrike.com/documentation/72/intel-apis) to learn more about FQL filter, about the meaning of the indicator entity properties, and best practices. Further, please refer to [jq tool manual](https://stedolan.github.io/jq/manual/) to learn how to effectively post-process JSON outputs in command-line.
