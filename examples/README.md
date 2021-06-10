# Gofalcon examples

Enclosing directory contains various examples of use of CrowdStrike Falcon Golang SDK.
Some of these examples ready to be used as stand-alone programs.

 * [simple](simple/) - minimal example that authenticates to Falcon platform and fetches [CrowdScore](https://www.crowdstrike.com/blog/tech-center/crowdscore-efficiency/)
 * [falcon_iocs](falcon_iocs) - stand-alone tool that can be used to add, delete or list Custom IOCs in the CrowdStrike Falcon Console
 * [falcon_sensor_download](falcon_sensor_download/) - stand-alone tool that can be used to download CrowdStrike Falcon Sensor
 * [falcon_cleanup_pods](falcon_cleanup_pods) - stand-alone tool that can be used to clean-up inactive pods from CrowdStrike Falcon interface
 * [falcon_event_stream](falcon_event_stream/) - stand-alone tool that can be used to stream events as they happen in CrowdStrike Console
 * [stream_new_detections](stream_new_detections/) - small utility to poll for a new detections in CrowdStrike Console
 * [oauth_token](oauth_token/) - a example tool to obtain OAuth2 token for use outside of gofalcon
