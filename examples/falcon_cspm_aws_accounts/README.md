# Falcon CSPM Registered AWS Accounts

Stand-alone tool that uses cloud security posture management (CSPM) to list registered AWS accounts.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_cspm_aws_accounts
```

## Example Run

Lists registered AWS accounts and their status.

```
Output:
AWS Account ID: 123123123121 Account Status Event_DiscoverAccountStatusProvisioned
AWS Account ID: 123123123122 Account Status Event_DiscoverAccountStatusOperational
AWS Account ID: 123123123123 Account Status Event_DiscoverAccountStatusOperational
```