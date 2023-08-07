# Gofalcon examples

Enclosing directory contains various examples of use of CrowdStrike Falcon Golang SDK.
Some of these examples ready to be used as stand-alone programs.

 * [simple](simple/) - minimal example that authenticates to Falcon platform and fetches [CrowdScore](https://www.crowdstrike.com/blog/tech-center/crowdscore-efficiency/)
 * [falcon_iocs](falcon_iocs) - stand-alone tool that can be used to add, delete or list Custom IOCs in the CrowdStrike Falcon Console
 * [falcon_sensor_download](falcon_sensor_download/) - stand-alone tool that can be used to download CrowdStrike Falcon Sensor
 * [falcon_cleanup_pods](falcon_cleanup_pods) - stand-alone tool that can be used to clean-up inactive pods from CrowdStrike Falcon interface
 * [falcon_cspm_ioms](falcon_cspm_ioms) - stand-alone tool that leverages CrowdStrike Cloud Security Posture Management (CSPM) to list indicators of misconfigurations (IOMs)
 * [falcon_detection_details](falcon_detection_details) - stand-alone tool that outputs inventory of all Falcon Detections based on custom filter
 * [falcon_event_stream](falcon_event_stream/) - stand-alone tool that can be used to stream events as they happen in CrowdStrike Console
 * [falcon_get_cid](falcon_get_cid) - stand-alone tool that can be used to get Customer ID based on the API key pair
 * [falcon_discover_host_details](falcon_discover_host_details) - stand-alone tool that can be used for auditing purposes and for gaining timely visibility into your environment
 * [falcon_host_details](falcon_host_details) - stand-alone tool that outputs inventory of hosts registered to CrowdStrike Falcon platform
 * [falcon_intel_indicators](falcon_intel_indicators) - stand-alone tool that queries CrowdStrike Intelligence Indicators
 * [falcon_intel_rules_download](falcon_intel_rules_download) - stand-alone tool that downloads CrowdStrike Falcon Intelligence Rule files
 * [falcon_registry_token](falcon_registry_token) - helper to generate container registry logic information for `docker login`
 * [falcon_rtr_read_only_command](falcon_rtr_read_only_command) - stand-alone example to run basic read-only RTR (Real-Time Response) command against a specific agent
 * [falcon_rtr_admin_create_and_run_script](falcon_rtr_admin_create_and_run_script) - stand-alone example of running custom script on the specific agent using RTR (Real-Time Response) API
 * [falcon_rtr_batch_read_only_command](falcon_rtr_batch_read_only_command) - stand-alone example to run basic read-only RTR (Real-Time Response) command against several agents at once.
 * [falcon_vulnerabilities](falcon_vulnerabilities) - stand-alone tool that outputs inventory of vulnerabilities affecting your environment
 * [falcon_supported_kernels](falcon_supported_kernels) - stand-alone tool that outputs short list recent Linux kernels supported by CrowdStrike Falcon for a given distribution
 * [falcon_zta](falcon_zta) - stand-alone tool that utilises Hosts and ZTA APIs and outputs ZTA findings for your environment
 * [stream_new_detections](stream_new_detections/) - small utility to poll for a new detections in CrowdStrike Console
 * [oauth_token](oauth_token/) - a example tool to obtain OAuth2 token for use outside of gofalcon

## Installation

Many of the examples are useful and valuable as a stand-alone tools. The following instructions can be used to install them all at once

### Installation using local golang install

```
go get -u github.com/crowdstrike/gofalcon/examples/...
```

### Installation using packaging system (rpm/deb)

```
curl -sSfL https://raw.githubusercontent.com/crowdstrike/gofalcon/main/examples/install | sudo sh -s
```
