# Falcon Spotlight Vulnerabilities

[Falcon Spotlight](https://www.crowdstrike.com/endpoint-security-products/falcon-spotlight-vulnerability-management/) is CrowdStrike service that provides real-time visibility across your enterprise — giving you relevant and timely information you need to reduce your exposure to attacks with zero impact on your endpoints.

This page represents a stand-alone tool that uses Falcon Spotlight API to query the vulnerabilities affecting your environment and outputs those vulnerabilities in JSON format to the stdout. This tool can be used together with JSON parsing tools like `jq` in order to build reports of your liking.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_vulnerabilities
```

## Exemplary Usage

Interactive Run:
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_vulnerabilities
Missing --filter attribute. Please provide FQL (Falcon Query Language) expression for vulnerability search.
Examples:
    created_timestamp:>'2019-11-25T22:36:12Z'
    closed_timestamp:>'2019-11-25T22:36:12Z'
    aid:'abcde123456789a34a1af416424d6231'
    status:'open'
    cve.severity:'CRITICAL'
    cve.severity:'HIGH'+status:!'closed'
    last_seen_within:'10'
filter: status:!'closed'
```

List critical severity vulnerabilities affecting your environment
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_vulnerabilities --filter="cve.severity:'CRITICAL'"
....
```

Count critical severity vulnerabilities affecting your environment
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_vulnerabilities --filter="cve.severity:'CRITICAL'" \
      | jq length
34
```

List all critical severity vulnerabilities alongside hostname of affected systems:
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
    falcon_vulnerabilities --filter="cve.severity:'CRITICAL'" \
      | jq -r 'map( {"cve":.cve.id, "hostname": .host_info.hostname})'
```

Index all critical severity vulnerabilities based on hostname of systems it affects:
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
    falcon_vulnerabilities --filter="cve.severity:'CRITICAL'" \
    | jq -r 'map( {"cve":.cve.id, "hostname": .host_info.hostname} ) | group_by(.hostname)[] | {(.[0].hostname): [.[] | .cve]}'
```

List vulnerabilities except those of low and medium severity, **sort** by the time last updated timestamp.
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
    falcon_vulnerabilities --filter='cve.severity:!["LOW","MEDIUM"]' --sort="updated_timestamp.desc"
```

Please Refer to [Falcon Spotlight API documentation](https://falcon.crowdstrike.com/documentation/98/spotlight-apis) to learn more about FQL filter and FQL sort parameters, about the meaning of the vulnerability entity properties, and best practices. Further, please refer to [jq tool manual](https://stedolan.github.io/jq/manual/) to learn how to effectively post-process JSON outputs in command-line.
