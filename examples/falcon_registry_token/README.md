This is a working standalone example of a program to fetch registry token for CrowdStrike Container Registry.

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
falcon_registry_token | docker login --username $(echo $CID | awk -F-  '{print("fc-" tolower($1))}') --password-stdin registry.crowdstrike.com 
```
