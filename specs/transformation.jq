  # Fix the file downloads: invalid swagger for file downloads
    .definitions."domain.DownloadItem"."type"="string"
  | .definitions."domain.DownloadItem"."format"="binary"
  | .paths."/intel/entities/report-files/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  | .paths."/intel/entities/rules-latest-files/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  | .paths."/intel/entities/rules-files/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  | .paths."/real-time-response/entities/extracted-file-contents/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  # Fix overflow on json number (more than 63 bits are needed hold this field)
  | .definitions."domain.APIEvaluationLogicItemV1".properties.id."x-go-type"={type: "Number", import: {package: "encoding/json"}, hints: {noValidation: true}}
  | .definitions."domain.APISimplifiedEvaluationLogicItemV1".properties.id."x-go-type"={type: "Number", import: {package: "encoding/json"}, hints: {noValidation: true}}
  # Rename msaspec.Error back to msa.APIError. These are two names for the same type.
  | walk(
    if type == "object" and has("$ref") and ."$ref" == "#/definitions/msaspec.Error" then ."$ref" = "#/definitions/msa.APIError" else . end
    | if type == "object" and has("$ref") and ."$ref" == "#/definitions/msaspec.MetaInfo" then ."$ref" = "#/definitions/msa.MetaInfo" else . end
    )
  | del(.definitions."msaspec.Error")
  # Rename msaspec.Paging to msa.Paging. These are two names for the same type.
  | walk(
    if type == "object" and has("$ref") and ."$ref" == "#/definitions/msaspec.Paging" then ."$ref" = "#/definitions/msa.Paging" else . end
    )
  | del(.definitions."msaspec.Paging")
  | .definitions."domain.RuleMetaInfo".properties.pagination."$ref" = "#/definitions/msa.Paging"
  | .definitions."domain.MsaMetaInfo".properties.pagination."$ref" = "#/definitions/msa.Paging"
  # Rename msaspec.MetaInfo to msa.MetaInfo. These are two names for the same type.
  | del(.definitions."msaspec.MetaInfo")

  # Misc fixes
  | .paths."/intel/entities/rules-latest-files/v1".get.parameters |= . + [{type: "string", description: "Download Only if changed since", name: "If-Modified-Since", "in": "header"}]
  | .paths."/intel/entities/rules-latest-files/v1".get.responses."304" = {description: "Not Modified"}
  | .paths."/oauth2/token".post.responses."201".headers["X-CS-Region"] = {type: "string"}
  | .paths."/policy/queries/sensor-update-kernels/{distinct_field}/v1" = .paths."/policy/queries/sensor-update-kernels/{distinct-field}/v1"
  | del(.paths."/policy/queries/sensor-update-kernels/{distinct-field}/v1")
  | .paths."/policy/queries/sensor-update-kernels/{distinct_field}/v1".get.parameters[0].name = "distinct_field"

  # IOA Rule Groups Combined API has incorrect swagger response object: list of ids instead of list of objects
  | .paths."/ioarules/queries/rule-groups-full/v1".get.responses."200" = .paths."/ioarules/entities/rule-groups/v1".get.responses."200"
  | .paths."/policy/entities/ioa-exclusions/v1".post.responses."201" = .paths."/policy/entities/ioa-exclusions/v1".post.responses."200"
  | del(.paths."/policy/entities/ioa-exclusions/v1".post.responses."200")

  # Add response code "202" to "/devices/entities/devices/tags/v1" endpoint
  | .paths."/devices/entities/devices/tags/v1".patch.responses."202" = .paths."/devices/entities/devices/tags/v1".patch.responses."200"


  # CGP should be Gcp
  | .paths."/cloud-connect-gcp/entities/account/v1".get.operationId = "GetD4CGcpAccount"
  | .paths."/cloud-connect-gcp/entities/account/v1".post.operationId = "CreateD4CGcpAccount"
  | .paths."/cloud-connect-gcp/entities/user-scripts/v1".get.operationId = "GetD4CGcpUserScripts"

  # Rename spotlight-vulnerabilities and spotlight-evaluation-logic collections back to vulnerabilities & vulnerabilities-evaluation-logic
  # looks like spotlight is staying to reverting it again... keeping this code incase it can be used some other time.
  # | walk(
  #     if type == "object" and .tags and (.tags | index("spotlight-vulnerabilities")) then
  #       .tags |= map(gsub("spotlight-vulnerabilities"; "vulnerabilities"))
  #     elif type == "object" and .tags and (.tags | index("spotlight-evaluation-logic")) then
  #       .tags |= map(gsub("spotlight-evaluation-logic"; "vulnerabilities-evaluation-logic"))
  #     else
  #       .
  #     end
  #   )

# Fix saas security - check for paths starting with /saas-security/
| .paths |= with_entries(
    if .key | startswith("/saas-security/") then
      .value |= walk(
        if type == "object" and has("tags") and (.tags | type) == "array" then
          .tags = ["saas security"]
        else
          .
        end
      )
    else
      .
    end
  )


  # Revert msaspec.QueryResponse back to msa.QueryResponse for falconcomplete-dashboard
  | if .paths."/falcon-complete-dashboards/queries/alerts/v1".get.responses."200".schema."$ref" = "#/definitions/msaspec.QueryResponse" then .paths."/falcon-complete-dashboards/queries/alerts/v1".get.responses."200".schema |= {"$ref": "#/definitions/msa.QueryResponse"} else . end
  | if .paths."/falcon-complete-dashboards/queries/devicecount-collections/v1".get.responses."200".schema."$ref" = "#/definitions/msaspec.QueryResponse" then .paths."/falcon-complete-dashboards/queries/devicecount-collections/v1".get.responses."200".schema |= {"$ref": "#/definitions/msa.QueryResponse"} else . end
  | if .paths."/falcon-complete-dashboards/queries/allowlist/v1".get.responses."200".schema."$ref" = "#/definitions/msaspec.QueryResponse" then .paths."/falcon-complete-dashboards/queries/allowlist/v1".get.responses."200".schema |= {"$ref": "#/definitions/msa.QueryResponse"} else . end
  | if .paths."/falcon-complete-dashboards/queries/blocklist/v1".get.responses."200".schema."$ref" = "#/definitions/msaspec.QueryResponse" then .paths."/falcon-complete-dashboards/queries/blocklist/v1".get.responses."200".schema |= {"$ref": "#/definitions/msa.QueryResponse"} else . end
  | if .paths."/falcon-complete-dashboards/queries/detects/v1".get.responses."200".schema."$ref" = "#/definitions/msaspec.QueryResponse" then .paths."/falcon-complete-dashboards/queries/detects/v1".get.responses."200".schema |= {"$ref": "#/definitions/msa.QueryResponse"} else . end
  | if .paths."/falcon-complete-dashboards/queries/escalations/v1".get.responses."200".schema."$ref" = "#/definitions/msaspec.QueryResponse" then .paths."/falcon-complete-dashboards/queries/escalations/v1".get.responses."200".schema |= {"$ref": "#/definitions/msa.QueryResponse"} else . end
  | if .paths."/falcon-complete-dashboards/queries/incidents/v1".get.responses."200".schema."$ref" = "#/definitions/msaspec.QueryResponse" then .paths."/falcon-complete-dashboards/queries/incidents/v1".get.responses."200".schema |= {"$ref": "#/definitions/msa.QueryResponse"} else . end
  | if .paths."/falcon-complete-dashboards/queries/remediations/v1".get.responses."200".schema."$ref" = "#/definitions/msaspec.QueryResponse" then .paths."/falcon-complete-dashboards/queries/remediations/v1".get.responses."200".schema |= {"$ref": "#/definitions/msa.QueryResponse"} else . end

  # Revert changes.GetChangesResponse back to public.GetChangesResponse for filevantage
  | if .paths."/filevantage/entities/changes/v2".get.responses."200".schema."$ref" = "#/definitions/changes.GetChangesResponse" then
      .paths."/filevantage/entities/changes/v2".get.responses."200".schema = {"$ref": "#/definitions/public.GetChangesResponse"}
      |.definitions."public.GetChangesResponse" = .definitions."changes.GetChangesResponse"
      |del(.definitions."changes.GetChangesResponse") else . end

  # Make message-center use consistent return type
  | if .paths."/message-center/aggregates/cases/GET/v1".post.responses."403".schema."$ref" = "#/definitions/msa.ReplyMetaOnly" then
      .paths."/message-center/aggregates/cases/GET/v1".post.responses."403".schema = {"$ref": "#/definitions/msaspec.ResponseFields"}
    else . end

  # Custom Storage "custom-type" rename
  | .definitions."CustomStorageObjectKeys" = .definitions."CustomType_1255839303"
  | del(.definitions."CustomType_1255839303")
  | if .paths."/customobjects/v1/collections/{collection_name}/{collection_version}/objects".get.responses."200".schema."$ref" = "#/definitions/CustomType_1255839303" then
      .paths."/customobjects/v1/collections/{collection_name}/{collection_version}/objects".get.responses."200".schema = {"$ref": "#/definitions/CustomStorageObjectKeys"}  else . end
  | if .paths."/customobjects/v1/collections/{collection_name}/objects".get.responses."200".schema."$ref" = "#/definitions/CustomType_1255839303" then
      .paths."/customobjects/v1/collections/{collection_name}/objects".get.responses."200".schema = {"$ref": "#/definitions/CustomStorageObjectKeys"}  else . end
  | if .paths."/customobjects/v1/collections".get.responses."200".schema."$ref" = "#/definitions/CustomType_1255839303" then
      .paths."/customobjects/v1/collections".get.responses."200".schema = {"$ref": "#/definitions/CustomStorageObjectKeys"}  else . end
  | if .paths."/customobjects/v1/collections/{collection_name}/schemas".get.responses."200".schema."$ref" = "#/definitions/CustomType_1255839303" then
      .paths."/customobjects/v1/collections/{collection_name}/schemas".get.responses."200".schema = {"$ref": "#/definitions/CustomStorageObjectKeys"}  else . end

  | .definitions."CustomStorageResponse" = .definitions."CustomType_3191042536"
  | del(.definitions."CustomType_3191042536")
  | if .paths."/customobjects/v1/collections/{collection_name}/objects".post.responses."200".schema."$ref" = "#/definitions/CustomType_3191042536" then
      .paths."/customobjects/v1/collections/{collection_name}/objects".post.responses."200".schema = {"$ref": "#/definitions/CustomStorageResponse"}  else . end
  | if .paths."/customobjects/v1/collections/{collection_name}/objects/{object_key}".put.responses."200".schema."$ref" = "#/definitions/CustomType_3191042536" then
      .paths."/customobjects/v1/collections/{collection_name}/objects/{object_key}".put.responses."200".schema = {"$ref": "#/definitions/CustomStorageResponse"}  else . end
  | if .paths."/customobjects/v1/collections/{collection_name}/objects/{object_key}".delete.responses."200".schema."$ref" = "#/definitions/CustomType_3191042536" then
      .paths."/customobjects/v1/collections/{collection_name}/objects/{object_key}".delete.responses."200".schema = {"$ref": "#/definitions/CustomStorageResponse"}  else . end
  | if .paths."/customobjects/v1/collections/{collection_name}/objects/{object_key}/metadata".get.responses."200".schema."$ref" = "#/definitions/CustomType_3191042536" then
      .paths."/customobjects/v1/collections/{collection_name}/objects/{object_key}/metadata".get.responses."200".schema = {"$ref": "#/definitions/CustomStorageResponse"}  else . end
  | if .paths."/customobjects/v1/collections/{collection_name}/{collection_version}/objects".post.responses."200".schema."$ref" = "#/definitions/CustomType_3191042536" then
      .paths."/customobjects/v1/collections/{collection_name}/{collection_version}/objects".post.responses."200".schema = {"$ref": "#/definitions/CustomStorageResponse"}  else . end
  | if .paths."/customobjects/v1/collections/{collection_name}/{collection_version}/objects/{object_key}".put.responses."200".schema."$ref" = "#/definitions/CustomType_3191042536" then
      .paths."/customobjects/v1/collections/{collection_name}/{collection_version}/objects/{object_key}".put.responses."200".schema = {"$ref": "#/definitions/CustomStorageResponse"}  else . end
  | if .paths."/customobjects/v1/collections/{collection_name}/{collection_version}/objects/{object_key}".delete.responses."200".schema."$ref" = "#/definitions/CustomType_3191042536" then
      .paths."/customobjects/v1/collections/{collection_name}/{collection_version}/objects/{object_key}".delete.responses."200".schema = {"$ref": "#/definitions/CustomStorageResponse"}  else . end
  | if .paths."/customobjects/v1/collections/{collection_name}/{collection_version}/objects/{object_key}/metadata".get.responses."200".schema."$ref" = "#/definitions/CustomType_3191042536" then
      .paths."/customobjects/v1/collections/{collection_name}/{collection_version}/objects/{object_key}/metadata".get.responses."200".schema = {"$ref": "#/definitions/CustomStorageResponse"}  else . end

  # Better operationId for workflows collection
  | .paths."/workflows/entities/execute/v1".post.operationId = "Execute"
  | .paths."/workflows/entities/execution-actions/v1".post.operationId = "ExecutionAction"
  | .paths."/workflows/entities/execution-results/v1".get.operationId = "ExecutionResults"
  | .paths."/workflows/system-definitions/deprovision/v1".post.operationId = "Deprovision"
  | .paths."/workflows/system-definitions/promote/v1".post.operationId = "Promote"
  | .paths."/workflows/system-definitions/provision/v1".post.operationId = "Provision"

  # Better operationId for foundry-logscale collection
  | .paths."/loggingapi/combined/repos/v1".get.operationId = "ListRepos"
  | .paths."/loggingapi/entities/data-ingestion/ingest/v1".post.operationId = "IngestData"
  | .paths."/loggingapi/entities/saved-searches/execute-dynamic/v1".post.operationId = "ExecuteDynamic"
  | .paths."/loggingapi/entities/saved-searches/execute/v1".get.operationId = "GetSearchResults"
  | .paths."/loggingapi/entities/saved-searches/execute/v1".post.operationId = "Execute"
  | .paths."/loggingapi/entities/saved-searches/ingest/v1".post.operationId = "Populate"
  | .paths."/loggingapi/entities/saved-searches/job-results-download/v1".get.operationId = "DownloadResults"
  | .paths."/loggingapi/entities/views/v1".get.operationId = "ListViews"

  # Better operationId for unidentified-containers collection
  | .paths."/container-security/aggregates/unidentified-containers/count-by-date/v1".get.operationId = "CountByDateRange"
  | .paths."/container-security/aggregates/unidentified-containers/count/v1".get.operationId = "Count"
  | .paths."/container-security/combined/unidentified-containers/v1".get.operationId = "Search"

  # Better operationId for snapshots-registration collection
  | .paths."/snapshots/entities/accounts/v1".post.operationId = "Register"

  # Better operationId for scheduled-reports collection
  | .paths."/reports/entities/scheduled-reports/execution/v1".post.operationId = "Execute"
  | .paths."/reports/entities/scheduled-reports/v1".get.operationId = "QueryById"
  | .paths."/reports/queries/scheduled-reports/v1".get.operationId = "Query"

  # Better operationId for alerts collection
  | .paths."/alerts/queries/alerts/v2".get.operationId = "QueryV2"
  | .paths."/alerts/entities/alerts/v3".patch.operationId = "UpdateV3"
  | .paths."/alerts/aggregates/alerts/v2".post.operationId = "GetAggregateV2"
  | .paths."/alerts/entities/alerts/v2".post.operationId = "GetV2"

  # Better operationId for kubernetes-protection collection
  | .paths."/container-security/combined/clusters/v1".get.operationId = "ClusterCombined"
  | .paths."/container-security/aggregates/clusters/count/v1".get.operationId = "ClusterCount"
  | .paths."/container-security/aggregates/enrichment/clusters/entities/v1".get.operationId = "ClusterEnrichment"
  | .paths."/container-security/aggregates/clusters/count-by-date/v1".get.operationId = "ClustersByDateRangeCount"
  | .paths."/container-security/aggregates/clusters/count-by-kubernetes-version/v1".get.operationId = "ClustersByKubernetesVersionCount"
  | .paths."/container-security/aggregates/clusters/count-by-status/v1".get.operationId = "ClustersByStatusCount"
  | .paths."/container-security/combined/containers/v1".get.operationId = "ContainerCombined"
  | .paths."/container-security/aggregates/containers/count/v1".get.operationId = "ContainerCount"
  | .paths."/container-security/aggregates/containers/count-by-registry/v1".get.operationId = "ContainerCountByRegistry"
  | .paths."/container-security/aggregates/enrichment/containers/entities/v1".get.operationId = "ContainerEnrichment"
  | .paths."/container-security/aggregates/containers/image-detections-count-by-date/v1".get.operationId = "ContainerImageDetectionsCountByDate"
  | .paths."/container-security/aggregates/images/most-used/v1".get.operationId = "ContainerImagesByMostUsed"
  | .paths."/container-security/aggregates/containers/images-by-state/v1".get.operationId = "ContainerImagesByState"
  | .paths."/container-security/aggregates/containers/vulnerability-count-by-severity/v1".get.operationId = "ContainerVulnerabilitiesBySeverityCount"
  | .paths."/container-security/aggregates/containers/count-by-date/v1".get.operationId = "ContainersByDateRangeCount"
  | .paths."/container-security/aggregates/containers/sensor-coverage/v1".get.operationId = "ContainersSensorCoverage"
  | .paths."/container-security/combined/deployments/v1".get.operationId = "DeploymentCombined"
  | .paths."/container-security/aggregates/deployments/count/v1".get.operationId = "DeploymentCount"
  | .paths."/container-security/aggregates/enrichment/deployments/entities/v1".get.operationId = "DeploymentEnrichment"
  | .paths."/container-security/aggregates/deployments/count-by-date/v1".get.operationId = "DeploymentsByDateRangeCount"
  | .paths."/container-security/aggregates/images/count-by-distinct/v1".get.operationId = "DistinctContainerImageCount"
  | .paths."/container-security/aggregates/kubernetes-ioms/count-by-date/v1".get.operationId = "KubernetesIomByDateRange"
  | .paths."/container-security/aggregates/kubernetes-ioms/count/v1".get.operationId = "KubernetesIomCount"
  | .paths."/container-security/entities/kubernetes-ioms/v1".get.operationId = "KubernetesIomEntities"
  | .paths."/container-security/combined/nodes/v1".get.operationId = "NodeCombined"
  | .paths."/container-security/aggregates/nodes/count/v1".get.operationId = "NodeCount"
  | .paths."/container-security/aggregates/enrichment/nodes/entities/v1".get.operationId = "NodeEnrichment"
  | .paths."/container-security/aggregates/nodes/count-by-cloud/v1".get.operationId = "NodesByCloudCount"
  | .paths."/container-security/aggregates/nodes/count-by-container-engine-version/v1".get.operationId = "NodesByContainerEngineVersionCount"
  | .paths."/container-security/aggregates/nodes/count-by-date/v1".get.operationId = "NodesByDateRangeCount"
  | .paths."/container-security/combined/pods/v1".get.operationId = "PodCombined"
  | .paths."/container-security/aggregates/pods/count/v1".get.operationId = "PodCount"
  | .paths."/container-security/aggregates/enrichment/pods/entities/v1".get.operationId = "PodEnrichment"
  | .paths."/container-security/aggregates/pods/count-by-date/v1".get.operationId = "PodsByDateRangeCount"
  | .paths."/container-security/combined/container-images/v1".get.operationId = "RunningContainerImages"
  | .paths."/container-security/aggregates/containers/count-vulnerable-images/v1".get.operationId = "VulnerableContainerImageCount"
  | .paths."/container-security/combined/kubernetes-ioms/v1".get.operationId = "KubernetesIomEntitiesCombined"
  | .paths."/container-security/queries/kubernetes-ioms/v1".get.operationId = "QueryKubernetesIoms"

# Allow an empty string be passed to assignment_rule
 | .definitions."host_groups.UpdateGroupReqV1".properties.assignment_rule += {"x-nullable": true}

 # Allow expiration to be nullable
 | .definitions."api.IndicatorCreateReqV1".properties.expiration += {"x-nullable": true}

 # 202 is a valid response for /real-time-response/entities/scripts/v1 patch
| .paths."/real-time-response/entities/scripts/v1".patch.responses."202" = .paths."/real-time-response/entities/scripts/v1".patch.responses."200"
| del(.paths."/real-time-response/entities/scripts/v1".patch.responses."200")

# 200 is a valid response from /real-time-response/entities/queued-sessions/command/v1
| .paths."/real-time-response/entities/queued-sessions/command/v1".delete.responses."200" = .paths."/real-time-response/entities/put-files/v1".delete.responses."200"

# last_seen and first_seen should be a string
| .definitions."models.Container".properties.first_seen.type = "string"
| .definitions."models.Container".properties.last_seen.type = "string"

# add intel.CVSSv2 model definition
| .definitions."intel.CVSSv2" = {
    "properties": {
        "access_complexity": {"type": "string"},
        "access_vector": {"type": "string"},
        "authentication": {"type": "string"},
        "availability_impact": {"type": "string"},
        "score": {"type": "number", "format": "double"},
        "confidentiality_impact": {"type": "string"},
        "integrity_impact": {"type": "string"},
        "severity": {"type": "string"}
    }
}

# add intel.CVSSv3 model definition
| .definitions."intel.CVSSv3" = {
    "properties": {
        "attack_complexity": {"type": "string"},
        "attack_vector": {"type": "string"},
        "availability_impact": {"type": "string"},
        "score": {"type": "number", "format": "double"},
        "confidentiality_impact": {"type": "string"},
        "integrity_impact": {"type": "string"},
        "privileges_required": {"type": "string"},
        "scope": {"type": "string"},
        "severity": {"type": "string"},
        "user_interaction": {"type": "string"}
    }
}

# update Intel.GetVulnerabilities to use intel.CVSS models
| .definitions."domain.Vulnerability".properties."cvss_v2_base" = {
    "description": "Vulnerability severity score, according to Common Vulnerability Scoring System V2",
    "$ref": "#/definitions/intel.CVSSv2"
}
| .definitions."domain.Vulnerability".properties."cvss_v3_base" = {
    "description": "Vulnerability severity score, according to Common Vulnerability Scoring System V3",
    "$ref": "#/definitions/intel.CVSSv3"
}

# fix Alerts service collection
| .definitions."detectsapi.PostEntitiesAlertsV1Response" = .definitions."detectsapi.PostEntitiesAlertsV1ResponseSwagger"
| del(.definitions."detectsapi.PostEntitiesAlertsV1ResponseSwagger")
| .definitions."detectsapi.PostEntitiesAlertsV1Response".properties.resources.items = {"$ref": "#/definitions/detects.Alert"}
| .paths."/alerts/entities/alerts/v1".post.responses."200".schema = {"$ref": "#/definitions/detectsapi.PostEntitiesAlertsV1Response"}
| .paths."/alerts/entities/alerts/v1".post.responses."400".schema = {"$ref": "#/definitions/detectsapi.PostEntitiesAlertsV1Response"}
| .paths."/alerts/entities/alerts/v1".post.responses."500".schema = {"$ref": "#/definitions/detectsapi.PostEntitiesAlertsV1Response"}
| .definitions."detectsapi.PostEntitiesAlertsV2Response" = .definitions."detectsapi.PostEntitiesAlertsV2ResponseSwagger"
| del(.definitions."detectsapi.PostEntitiesAlertsV2ResponseSwagger")
| .definitions."detectsapi.PostEntitiesAlertsV2Response".properties.resources.items = {"$ref": "#/definitions/detects.Alert"}
| .paths."/alerts/entities/alerts/v2".post.responses."200".schema = {"$ref": "#/definitions/detectsapi.PostEntitiesAlertsV2Response"}
| .paths."/alerts/entities/alerts/v2".post.responses."400".schema = {"$ref": "#/definitions/detectsapi.PostEntitiesAlertsV2Response"}
| .paths."/alerts/entities/alerts/v2".post.responses."500".schema = {"$ref": "#/definitions/detectsapi.PostEntitiesAlertsV2Response"}
| .definitions."detects.Alert" = .definitions."detects.ExternalAlert"
| .definitions."detectsapi.PostCombinedAlertsV1ResponseSwagger".properties.resources.items = {"$ref": "#/definitions/detects.Alert"}
| del(.definitions."detects.ExternalAlert")
| .definitions."detects.Alert".additionalProperties = true
| .definitions."detects.Alert".properties += {
  "alleged_filetype": {"type": "string"},
  "cmdline": {"type": "string"},
  "control_graph_id": {"type": "string"},
  "filename": {"type": "string"},
  "filepath": {"type": "string"},
  "ioc_description": {"type": "string"},
  "ioc_source": {"type": "string"},
  "ioc_type": {"type": "string"},
  "ioc_value": {"type": "string"},
  "md5": {"type": "string"},
  "cloud_indicator": {"type": "string"},
  "context_timestamp": {"type": "string", "format": "date-time"},
  "control_graph_id": {"type": "string"},
  "crawl_edge_ids": {"type": "object", "properties": {"Sensor": {"type": "array", "items": {"type": "string"}}}},
  "crawl_vertex_ids": {"type": "object", "properties": {"Sensor": {"type": "array", "items": {"type": "string"}}}},
  "falcon_host_link": {"type": "string"},
  "filename": {"type": "string"},
  "filepath": {"type": "string"},
  "grandparent_details": {
    "type": "object",
    "properties": {
      "filename": { "type": "string" },
      "cmdline": { "type": "string" },
      "filepath": { "type": "string" },
      "local_process_id": { "type": "string" },
      "md5": { "type": "string" },
      "process_graph_id": { "type": "string" },
      "process_id": { "type": "string" },
      "sha256": { "type": "string" },
      "timestamp": { "type": "string", "format": "date-time" },
      "user_graph_id": { "type": "string" },
      "user_id": { "type": "string" },
      "user_name": { "type": "string" }
    }
  },
  "has_script_or_module_ioce": {"type": "boolean"},
  "indicator_id": {"type": "string"},
  "ioc_context": {
    "type": "array",
    "items": {
      "type": "object",
      "properties": {
        "ioc_description": { "type": "string" },
        "ioc_source": { "type": "string" },
        "ioc_type": { "type": "string" },
        "ioc_value": { "type": "string" },
        "md5": { "type": "string" },
        "sha256": { "type": "string" },
        "type": { "type": "string" }
      }
    }
  },
  "ioc_values": {
    "type": "array",
    "items": { "type": "string" }
  },
  "is_synthetic_quarantine_disposition": {"type": "boolean"},
  "local_process_id": {"type": "string"},
  "logon_domain": {"type": "string"},
  "parent_details": {
    "type": "object",
    "properties": {
      "cmdline": { "type": "string" },
      "filename": { "type": "string" },
      "filepath": { "type": "string" },
      "local_process_id": { "type": "string" },
      "md5": { "type": "string" },
      "process_graph_id": { "type": "string" },
      "process_id": { "type": "string" },
      "sha256": { "type": "string" },
      "timestamp": { "type": "string" },
      "user_graph_id": { "type": "string" },
      "user_id": { "type": "string" },
      "user_name": { "type": "string" }
    }
  },
  "pattern_disposition": { "type": "integer", "x-nullable": true},
  "pattern_disposition_description": { "type": "string" },
  "pattern_disposition_details": {
    "type": "object",
    "properties": {
      "blocking_unsupported_or_disabled": { "type": "boolean", "x-nullable": true },
      "bootup_safeguard_enabled": { "type": "boolean", "x-nullable": true },
      "containment_file_system": { "type": "boolean", "x-nullable": true },
      "critical_process_disabled": { "type": "boolean", "x-nullable": true },
      "detect": { "type": "boolean", "x-nullable": true },
      "fs_operation_blocked": { "type": "boolean", "x-nullable": true },
      "handle_operation_downgraded": { "type": "boolean", "x-nullable": true },
      "inddet_mask": { "type": "boolean", "x-nullable": true },
      "indicator": { "type": "boolean", "x-nullable": true },
      "kill_action_failed": { "type": "boolean", "x-nullable": true },
      "kill_parent": { "type": "boolean", "x-nullable": true },
      "kill_process": { "type": "boolean", "x-nullable": true },
      "kill_subprocess": { "type": "boolean", "x-nullable": true },
      "mfa_required": { "type": "boolean", "x-nullable": true },
      "operation_blocked": { "type": "boolean", "x-nullable": true },
      "policy_disabled": { "type": "boolean", "x-nullable": true },
      "prevention_provisioning_enabled": { "type": "boolean", "x-nullable": true },
      "process_blocked": { "type": "boolean", "x-nullable": true },
      "quarantine_file": { "type": "boolean", "x-nullable": true },
      "quarantine_machine": { "type": "boolean", "x-nullable": true },
      "registry_operation_blocked": { "type": "boolean", "x-nullable": true },
      "response_action_already_applied": { "type": "boolean", "x-nullable": true },
      "response_action_failed": { "type": "boolean", "x-nullable": true },
      "response_action_triggered": { "type": "boolean", "x-nullable": true },
      "rooting": { "type": "boolean", "x-nullable": true },
      "sensor_only": { "type": "boolean", "x-nullable": true },
      "suspend_parent": { "type": "boolean", "x-nullable": true },
      "suspend_process": { "type": "boolean", "x-nullable": true }
    },
    "x-nullable": true
  },
  "parent_process_id": { "type": "string" },
  "poly_id": { "type": "string" },
  "process_end_time": { "type": "string"},
  "process_id": { "type": "string" },
  "process_start_time": { "type": "string"},
  "quarantined_files": {
    "type": "array",
    "items": {
      "type": "object",
      "properties": {
        "filename": { "type": "string" },
        "id": { "type": "string" },
        "sha256": { "type": "string" },
        "state": { "type": "string" }
      }
    }
  },
  "sha1": { "type": "string" },
  "sha256": { "type": "string" },
  "tree_id": { "type": "string" },
  "tree_root": { "type": "string" },
  "triggering_process_graph_id": { "type": "string" },
  "user_id": { "type": "string" },
  "user_name": { "type": "string" },
  "device": {
    "type": "object",
    "properties": {
      "agent_load_flags": {
          "type": "string"
      },
      "agent_local_time": {
          "type": "string",
          "format": "date-time"
      },
      "agent_version": {
          "type": "string"
      },
      "bios_manufacturer": {
          "description": "The manufacturer of the device's BIOS",
          "type": "string"
      },
      "bios_version": {
          "description": "Version of the device's BIOS",
          "type": "string"
      },
      "cid": {
          "type": "string"
      },
      "config_id_base": {
          "type": "string"
      },
      "config_id_build": {
          "type": "string"
      },
      "config_id_platform": {
          "type": "string"
      },
      "device_id": {
        "type": "string"
      },
      "external_ip": {
          "type": "string"
      },
      "first_seen": {
          "description": "Timestamp indicating when the device was first seen",
          "type": "string",
          "format": "date-time"
      },
      "groups": {
          "type": "array",
          "items": {
              "type": "string"
          }
      },
      "hostinfo": {
          "type": "object",
          "properties": {
              "active_directory_dn_display": {
                  "type": "array",
                  "items": {
                      "type": "string"
                  }
              },
              "domain": {
                  "type": "string"
              }
          }
      },
      "hostname": {
          "type": "string"
      },
      "id": {
          "type": "string"
      },
      "last_seen": {
          "type": "string",
          "format": "date-time"
      },
      "local_ip": {
          "description": "Local IP address of the device",
          "type": "string"
      },
      "mac_address": {
          "description": "MAC address of the device",
          "type": "string"
      },
      "machine_domain": {
          "description": "Domain name of the device's machine",
          "type": "string"
      },
      "major_version": {
          "type": "string"
      },
      "minor_version": {
          "type": "string"
      },
      "modified_timestamp": {
          "description": "Timestamp indicating when the device information was last modified",
          "type": "string",
          "format": "date-time"
      },
      "os_version": {
          "description": "Operating system version running on the device",
          "type": "string"
      },
      "ou": {
          "description": "Organizational units the device belongs to",
          "type": "array",
          "items": {
              "type": "string"
          }
      },
      "platform_id": {
          "description": "ID of the platform the device is running on",
          "type": "string"
      },
      "platform_name": {
          "description": "Name of the platform the device is running on",
          "type": "string"
      },
      "pod_labels": {"type": "array", "items": {"type": "string"}},
      "tags": {"type": "array", "items": {"type": "string"}},
      "product_type": {
          "description": "Product type identifier for the device",
          "type": "string"
      },
      "product_type_desc": {
          "description": "Description of the product type for the device",
          "type": "string"
      },
      "site_name": {
          "description": "Site name where the device is located",
          "type": "string"
      },
      "status": {
          "description": "Current status of the device (e.g., normal, inactive)",
          "type": "string"
      },
      "system_manufacturer": {
          "description": "manufacturer of the system hardware",
          "type": "string"
      },
      "system_product_name": {
          "description": "product name of the system hardware",
          "type": "string"
      }
    }
  }
}

# Add new credential definitions for nested response structure
| .definitions."common.Credentials" = {
    "type": "object",
    "properties": {
        "meta": {
            "$ref": "#/definitions/msa.MetaInfo"
        },
        "resources": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string"
                }
            },
            "required": ["token"]
        },
        "errors": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/msa.APIError"
            }
        }
    }
}
| .definitions."common.RegistryCredentialsResponse" = {
    "required": [
        "errors",
        "meta",
        "resources"
    ],
    "properties": {
        "errors": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/msa.APIError"
            }
        },
        "meta": {
            "$ref": "#/definitions/msa.MetaInfo"
        },
        "resources": {
            "$ref": "#/definitions/common.Credentials"
        }
    }
}

# Ngsiem search metadata are ints but are returned from the API as decimals https://github.com/CrowdStrike/gofalcon/issues/505
| .definitions.".costs".properties.liveCost.format = "double" | .definitions.".costs".properties.liveCost.type = "number"
| .definitions.".costs".properties.liveCostRate.format = "double" | .definitions.".costs".properties.liveCostRate.type = "number"
| .definitions.".costs".properties.staticCost.format = "double" | .definitions.".costs".properties.staticCost.type = "number"
| .definitions.".costs".properties.staticCostRate.format = "double" | .definitions.".costs".properties.staticCostRate.type = "number"

# Prevent unnecessary renaming
| .paths."/snapshots/entities/image-registry-credentials/v1".get.operationId = "GetCredentialsMixin0Mixin60"
| .paths."/falconx/queries/submissions/v1".get.operationId = "QuerySubmissions"
| .paths."/scanner/queries/scans/v1".get.operationId = "QuerySubmissionsMixin0"
| .paths."/quickscanpro/entities/files/v1".post.operationId = "UploadFileMixin0Mixin93"
| .paths."/oauth2/token".post.responses."400".schema = {"$ref": "#/definitions/msa.ReplyMetaOnly"}
| .paths."/oauth2/token".post.responses."403".schema = {"$ref": "#/definitions/msa.ReplyMetaOnly"}
| .paths."/oauth2/token".post.responses."500".schema = {"$ref": "#/definitions/msa.ReplyMetaOnly"}
| .paths."/oauth2/revoke".post.responses."200".schema = {"$ref": "#/definitions/msa.ReplyMetaOnly"}
| .paths."/oauth2/revoke".post.responses."400".schema = {"$ref": "#/definitions/msa.ReplyMetaOnly"}
| .paths."/oauth2/revoke".post.responses."403".schema = {"$ref": "#/definitions/msa.ReplyMetaOnly"}
| .paths."/oauth2/revoke".post.responses."500".schema = {"$ref": "#/definitions/msa.ReplyMetaOnly"}


# Changes to azure registration models to support the CrowdStrike terraform provider
| .definitions."azure.AzureRegistrationCreateInput".properties.environment += {"x-nullable": true}
| .definitions."azure.AzureRegistrationCreateInput".properties.environment += {"x-omitempty": false}
| .definitions."azure.AzureRegistrationCreateInput".properties.resource_name_prefix += {"x-nullable": true}
| .definitions."azure.AzureRegistrationCreateInput".properties.resource_name_suffix += {"x-nullable": true}

| .definitions."azure.AzureRegistrationUpdateInput".properties.environment += {"x-nullable": true}
| .definitions."azure.AzureRegistrationUpdateInput".properties.environment += {"x-omitempty": false}
| .definitions."azure.AzureRegistrationUpdateInput".properties.resource_name_prefix += {"x-nullable": true}
| .definitions."azure.AzureRegistrationUpdateInput".properties.resource_name_prefix += {"x-omitempty": false}
| .definitions."azure.AzureRegistrationUpdateInput".properties.resource_name_suffix += {"x-nullable": true}
| .definitions."azure.AzureRegistrationUpdateInput".properties.resource_name_suffix += {"x-omitempty": false}

| .definitions."azure.TenantRegistration".properties.cs_infra_region += {"x-nullable": true}
| .definitions."azure.TenantRegistration".properties.cs_infra_subscription_id += {"x-nullable": true}
| .definitions."azure.TenantRegistration".properties.environment += {"x-nullable": true}
| .definitions."azure.TenantRegistration".properties.resource_name_prefix += {"x-nullable": true}
| .definitions."azure.TenantRegistration".properties.resource_name_suffix += {"x-nullable": true}

# Fix SensorUpdateSettingsReqV2.Build field to not have omitempty tag
| .definitions."sensor_update.SettingsReqV2".properties.build += {"x-omitempty": false}