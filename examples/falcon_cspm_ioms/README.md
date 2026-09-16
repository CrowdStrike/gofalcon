# Falcon CSPM Indicators of Misconfigurations

Stand-alone tool that uses cloud security posture management (CSPM) to list events for indicators of misconfigurations (IOMs).

## Installation

```
go install github.com/crowdstrike/gofalcon/examples/falcon_cspm_ioms@latest
```

## Example Run

List detected CSPM IOMs and parse results with jq
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_cspm_ioms | jq '.[]'
{
  "cid": "00000000000000000000000000000000",
  "cloud": {
    "account_id": "0000000000",
    "account_name": "marketing",
    "provider": "GCP",
    "region": "global"
  },
  "environment": [
    "production"
  ],
  "evaluation": {
    "attack_types": [
      "Lateral Movement"
    ],
    "first_detected": "2021-03-02T12:28:13Z",
    "last_detected": "2021-03-02T12:28:13Z",
    "findings": [
      {
        "name": "Role",
        "value": "iam.serviceAccountUser, iam.serviceAccountAdmin"
      }
    ],
    "rule": {
      "id": "463",
      "name": "IAM users have overly permissive service account privileges",
      "policy_id": 463,
      "remediation": "Restrict the service account roles granted to the IAM user.",
      "severity": "High"
    },
    "severity": "High",
    "status": "Reoccurring"
  },
  "id": "00000000-0000-0000-0000-000000000000",
  "resource": {
    "creation_time": "2021-03-02T12:28:13Z",
    "resource_id": "user:username@domain.loc",
    "resource_name": "username@domain.loc",
    "resource_type": "IAM User Account",
    "service": "IAM",
    "service_category": "Identity",
    "status": "Reoccurring"
  }
}
```

