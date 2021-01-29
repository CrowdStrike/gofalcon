# Simple

Minimalist example to show case authentication and initialisation of client library. Upon successful authentication the very latest [CrowdStrike Score](https://www.crowdstrike.com/blog/tech-center/crowdscore-efficiency/) is shown.

Example run:
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" \
        go run github.com/crowdstrike/gofalcon/examples/simple
As of 2021-01-29T13:47:55.362Z your CrowdScore is 0.
```
