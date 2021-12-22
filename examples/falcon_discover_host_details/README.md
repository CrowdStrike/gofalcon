# Falcon Discover Host Details

Stand-alone tool that uses Falcon Discover Host API to gain timely visibility into your environment.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_discover_host_details
```

## Exemplary Usage

Get full details of all the Falcon Discover assets
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_discover_host_details
```

Get total number of hosts
```
falcon_discover_host_details | jq length
```

Get full details of assets without Agent ID assigned
```
falcon_discover_host_details | jq -r 'map(select(has("aid") | not))'
```

Example using server side filtering to fetch subset of the assets
```
falcon_discover_host_details --filter='platform_name:"Windows"' | jq length
```

Please refer to [Falcon Discover API documentation](https://falcon.crowdstrike.com/documentation/197/falcon-discover-apis) to learn more about FQL filter parameter, about the meaning of the entity properties and best practices.
Further, please refer to [jq tool manual](https://stedolan.github.io/jq/manual/) to learn how to effectively post-process JSON outputs in command-line.
