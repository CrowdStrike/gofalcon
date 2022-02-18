# Falcon CSPM Indicators of Misconfigurations

Stand-alone tool that uses cloud security posture management (CSPM) to list events for indicators of misconfigurations (IOMs).

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_cspm_ioms
```

## Example Run

List detected CSPM IOMs and parse results with jq
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_cspm_ioms | jq '.[]'
{
  "account_id": "0000000000",
  "account_name": "0000000000",
  "azure_tenant_id": "N/A",
  "cid": "00000000000000000000000000000000",
  "cloud_provider": "GCP",
  "finding": "Role: iam.serviceAccountUser, iam.serviceAccountAdmin",
  "policy_id": "463",
  "policy_statement": "IAM users have overly permissive service account privileges",
  "region": "global",
  "report_date_time": "2021-03-02 12:28:13",
  "resource_attributes": "{\"Project ID\" : \"marketing\", \"Member\" : \"user:username@domain.loc\", \"Role(s)\" : \"owner, iam.serviceAccountUser, iam.serviceAccountAdmin\"}",
  "resource_create_time": "N/A",
  "resource_id": "user:username@domain.loc",
  "resource_id_type": "IAM User Account",
  "resource_url": "N/A",
  "service": "IAM",
  "severity": "High",
  "status": "Reoccurring",
  "tags": "N/A"
}
```
