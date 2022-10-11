# Falcon Host Details

Stand-alone tool that uses Host devices scroll API to query all the host details and output JSON to the stdout. This tool can be used together with JSON parsing tools like `jq` in order to build reports of your liking.

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

List hosts of particular operating system (using FQL (Falcon Query Language))
```
falcon_host_details --filter="platform_name:'Windows'"
```

List Kubernetes pods (protected by CrowdStrike Falcon Container) that have been running during past 7 days, show only pod names, agent versions and cloud information.
```
week_ago=$(date -d "7 days ago" '+%Y-%m-%d' 2>/dev/null || date -v-1w +%F)
falcon_host_details --filter="product_type_desc:'Pod'+last_seen:>='${week_ago}'" \
    | jq -r 'map({(.device_id): {"agent_version": .agent_version, "cloud": .service_provider, "pod_name": .pod_name}}) | add'
```

Please refer to [Falcon Hosts API documentation](https://falcon.crowdstrike.com/documentation/84/host-and-host-group-management-apis) to learn more about FQL filter parameter, about the meaning of the entity properties, and best practices.
Further, please refer to [jq tool manual](https://stedolan.github.io/jq/manual/) to learn how to effectively post-process JSON outputs in command-line.

