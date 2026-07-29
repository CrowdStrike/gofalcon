# Authentication with Access Token

Minimalist example to showcase authentication and initialization of client library using an existing access token. Upon successful authentication a short list of hosts registered to the Falcon platform is shown.

Example run:
```
FALCON_ACCESS_TOKEN="abc" \
FALCON_CLOUD="us-1" \
        go run github.com/crowdstrike/gofalcon/examples/simple_access_token
```

Example output:
```
Found 2 host(s):
 - 1234567890abcdef1234567890abcdef
 - fedcba0987654321fedcba0987654321
```
