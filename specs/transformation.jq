  # Fix the file downloads: invalid swagger for file downloads
    .definitions."domain.DownloadItem"."type"="string"
  | .definitions."domain.DownloadItem"."format"="binary"
  | .paths."/intel/entities/report-files/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  | .paths."/intel/entities/rules-latest-files/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  | .paths."/intel/entities/rules-files/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  | .paths."/real-time-response/entities/extracted-file-contents/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  # Fix overflow on json number (more than 63 bits are neede hold this field)
  | .definitions."domain.APIEvaluationLogicItemV1".properties.id."x-go-type"={type: "Number", import: {package: "encoding/json"}, hints: {noValidation: true}}
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
  | if .paths."/customobjects/v1/collections/{collection_name}/objects".get.responses."200".schema."$ref" = "#/definitions/CustomType_1255839303" then 
      .paths."/customobjects/v1/collections/{collection_name}/objects".get.responses."200".schema = {"$ref": "#/definitions/CustomStorageObjectKeys"}  else . end 

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

  # Better operationId for custom-storage collection  
  | .paths."/customobjects/v1/collections/{collection_name}/objects".get.operationId = "list"
  | .paths."/customobjects/v1/collections/{collection_name}/objects".post.operationId = "search"
  | .paths."/customobjects/v1/collections/{collection_name}/objects/{object_key}".get.operationId = "get"
  | .paths."/customobjects/v1/collections/{collection_name}/objects/{object_key}".put.operationId = "upload"
  | .paths."/customobjects/v1/collections/{collection_name}/objects/{object_key}".delete.operationId = "delete"
  | .paths."/customobjects/v1/collections/{collection_name}/objects/{object_key}/metadata".get.operationId = "metadata"

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