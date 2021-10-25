This is stand-alone tool that can be used to get Customer ID based on the API key pair.

The ability to derive CID from API key pair is useful in various occasions like new sensor registration. 

## Build
```
go get github.com/crowdstrike/gofalcon/examples/falcon_registry_token
```

## Setup Environment Variables
```
export FALCON_CLIENT_ID="your_falcon_id"
export FALCON_CLIENT_SECRET="your_falcon_secret"
export FALCON_CLOUD="us-1, us-2, eu-1, us-gov-1, etc"
```

## Usage
```
$ FALCON_CID=$(falcon_get_cid)
```
