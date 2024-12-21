# Customize Transport

This example builds on the falcon_host_details example to demonstrate the use of a `falcon.TransportDecorator` to customize HTTP client requests to the Falcon API for all calls.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/customize_transport
```

## Exemplary Usage

Get full details of all the hosts, with information about rate limits.

```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      FALCON_RATE_LIMIT_THRESHOLD="100" customize_transport
```

The Falcon API rate limit information provided by the `falcon.TransportDecorator` in this example will appear at the beginning of the output.
