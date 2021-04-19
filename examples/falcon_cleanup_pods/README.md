# Falcon Cleanup Pods

Stand-alone tool that uses Host API to find pods (Kubernetes Pods) that has been inactive for a given number of days and hide them. Pods are then archived and can be recreated if needed.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_cleanup_pods
```

## Example Run

Dry run to figure out what pods will be removed
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_cleanup_pods  --inactive-days 19 --dry-run
Querying Pods that has not been active since 2021-03-31
Found 2 pods that have been inactive
(DRY-RUN) Removing pod 14ac2155450b4adcb972c04da569d70a (name=command-control-via-remote-access-obfuscated-78c9467668-95mqj, inactive_since=2021-03-30T20:16:44Z)
(DRY-RUN) Removing pod 7d124fc6994f439c89687d95149fb326 (name=credential-access-via-credential-dumping-5ffc6fc76-gkc7h, inactive_since=2021-03-30T21:38:07Z)
```

Remove pods that has been inactive for 14 days
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_cleanup_pods
Querying Pods that has not been active since 2021-03-31
Found 10 pods that have been inactive
Removing pod 14ac2155450b4adcb972c04da569d70a (name=command-control-via-remote-access-obfuscated-78c9467668-95mqj, inactive_since=2021-03-30T20:16:44Z)
....
```
