# Simple

Minimalist example to show case authentication and initialisation of client library. Upon successful authentication a short list of hosts registered to the Falcon platform is shown.

Example run:
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" \
        go run github.com/crowdstrike/gofalcon/examples/simple
Found 2 host(s):
 - 1234567890abcdef1234567890abcdef
 - fedcba0987654321fedcba0987654321
```
