# Authentication with Access Token

Minimalist example to showcase authentication and initialization of client library using an existing access token. The very latest [CrowdStrike Score](https://www.crowdstrike.com/blog/tech-center/crowdscore-efficiency/) is shown.

Example run:
```
FALCON_ACCESS_TOKEN="abc" \
FALCON_CLOUD="us-1" \
        go run github.com/crowdstrike/gofalcon/examples/simple_access_token
```

Example output:
```
As of 2021-01-29T13:47:55.362Z your CrowdScore is 0.
```
