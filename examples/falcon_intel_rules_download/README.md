# Falcon Intelligence Rules Download

Minimalist example to show download CrowdStrike Falcon Intelligence Rules through API. This example can be run interactively or in script when all information is passed in through command-line.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_intel_rules_download
```

## Example Run

Download rules file interactively
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 falcon_intel_rules_download
Missing--rule-type argument. Valid options are [snort-suricata-master snort-suricata-update snort-suricata-changelog yara-master yara-update yara-changelog common-event-format netwitness]. 
Requested Rule type: snort-suricata-master
Downloading file snort-suricata-master.tar.gz
```
