This is a working standalone example of a program to run a basic read-only RTR command against a specific agent.

## Build
```
go get github.com/crowdstrike/gofalcon/examples/falcon_rtr_read_only_command
```

## Setup Environment Variables
```
# Highly recommended to set at least the client ID and secret
# as environment variables. Credentials should not be entered
# on the command line, so as not to pollute the command history.
export FALCON_CLIENT_ID="your_falcon_id"
export FALCON_CLIENT_SECRET="your_falcon_secret"
export FALCON_CLOUD="us-1, us-2, eu-1, us-gov-1, etc"

# AID and command are more likely to vary and are not sensitive,
# so are a more natural fit for command line arguments.
export FALCON_AGENT_ID="def"
export FALCON_RTR_COMMAND="users"
```

## Usage
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_rtr_read_only_command --aid "def" --cmd "users"
```
