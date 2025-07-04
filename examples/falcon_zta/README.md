# Falcon ZTA

CrowdStrike Falcon ZTA API is available to determine the Falcon ZTA stats for each of the Falcon managed endpoints that can be integrated with existing customer workflows. 

This page describes stand-alone tool that uses Falcon ZTA API. To learn more about Falcon ZTA please visit [product announcement](https://www.crowdstrike.com/press-releases/crowdstrike-extends-zero-trust-to-endpoint-devices/). To learn more about the concepts of Zero Trust visit [cybersecurity-101](https://www.crowdstrike.com/cybersecurity-101/zero-trust-security/).

This stand-alone tool uses host devices API and ZeroTrustAssessment API and outputs JSON to the stdout. This tool can be used together with JSON parsing tools like `jq` in order to build reports of your liking.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_zta
```

## Exemplary Usage

Get summary ZTA statistics for your environment as a whole
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_zta --statistics
```

Get ZTA details of each of the hosts
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_zta
```

Get ZTA details for sub-set of hosts specified by FQL (Falcon Query Language). In this case, we query zta details for all the hosts running Linux.

```
falcon_zta --filter="platform_name:'Linux'"
```

Get ZTA details for all hosts and transform the data to only show overall score:

```
falcon_zta | jq -r 'map( { (.aid) : .assessment.overall } ) | add'
```

Get ZTA details for all the hosts that have been seen in the last 45 days and sort it by ZTA overall score from the worst to the best.

```
week_ago=$(date -jf %s $(( $(date +%s) - 86400 * 7 )) +%Y-%m-%d)
falcon_zta --filter="last_seen:>='${week_ago}'" | jq -r 'sort_by(.assessment.overall)'
```

Get ZTA details for the hosts last last seen this year and filter out those with the zta score bellow certain threshold.
```
go run ./examples/falcon_zta --filter="last_seen:>='2022-01-01'" | jq -r '.[] | select(.assessment.overall < 40)'
```

Please refer to [Falcon Zero Trust Assessment APIs](https://falcon.crowdstrike.com/documentation/156/zero-trust-assessment-apis) documentation to learn more about specific fields returned by this API.

Please refer to [Falcon Hosts API documentation](https://falcon.crowdstrike.com/documentation/84/host-and-host-group-management-apis) to learn more about FQL filter parameter, about the meaning of the entity properties, and best practices.
Further, please refer to [jq tool manual](https://stedolan.github.io/jq/manual/) to learn how to effectively post-process JSON outputs in command-line.
