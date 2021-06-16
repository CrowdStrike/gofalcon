This is a working standalone example of a program to manage CrowdStrike IOCs from the CLI

## Build
```
go build falcon_ioc.go
```

## Setup Environment Variables
```
export FALCON_CLIENT_ID="your_falcon_id"
export FALCON_CLIENT_SECRET="your_falcon_secret"
export FALCON_CLOUD="us-1, us-2, eu-1, us-gov-1, etc"
```

## Usage
```
./falcon_ioc --add "123.123.132.231"
./falcon_ioc --add "73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac" --description "evilprogram.exe"
./falcon_ioc --add "blockexample.com"
./falcon_ioc --delete "blockexample.com"
./falcon_ioc --list
./falcon_ioc --show "123.123.132.231"
```
