# Falcon Host Details

Stand-alone tool that uses Host API to query all the host details and output JSON to the stdout. This tool can be used together with JSON parsing tools like `jq` in order to build reports of your liking.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_host_details
```

## Exemplary Usage

Get full details of all the hosts

```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_host_details
```

Get total number of hosts

```
falcon_host_details | jq length
```

List hostnames of all hosts
```
falcon_host_details  | jq 'map(.hostname)'
```

List hosts and agent versions as key-value dictionary
```
falcon_host_details  | jq -r ' map( { (.hostname) : .agent_version } ) | add'
```
