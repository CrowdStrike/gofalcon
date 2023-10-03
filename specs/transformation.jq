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


  # Device v1 API has been deprecated since August 2022. And the end point will be removed at some point in the future.
  | del(.paths."/devices/entities/devices/v1")

  # Misc fixes
  | .paths."/intel/entities/rules-latest-files/v1".get.parameters |= . + [{type: "string", description: "Download Only if changed since", name: "If-Modified-Since", "in": "header"}]
  | .paths."/intel/entities/rules-latest-files/v1".get.responses."304" = {description: "Not Modified"}
  | .paths."/oauth2/token".post.responses."201".headers["X-CS-Region"] = {type: "string"}
  | .paths."/policy/queries/sensor-update-kernels/{distinct_field}/v1" = .paths."/policy/queries/sensor-update-kernels/{distinct-field}/v1"
  | del(.paths."/policy/queries/sensor-update-kernels/{distinct-field}/v1")
  | .paths."/policy/queries/sensor-update-kernels/{distinct_field}/v1".get.parameters[0].name = "distinct_field"

  # IOA Rule Groups Combined API has incorrect swagger response object: list of ids instead of list of objects
  | .paths."/ioarules/queries/rule-groups-full/v1".get.responses."200" = .paths."/ioarules/entities/rule-groups/v1".get.responses."200"

  # Add response code "202" to "/devices/entities/devices/tags/v1" endpoint
  | .paths."/devices/entities/devices/tags/v1".patch.responses."202" = .paths."/devices/entities/devices/tags/v1".patch.responses."200"
  

  # CGP should be Gcp
  | .paths."/cloud-connect-gcp/entities/account/v1".get.operationId = "GetD4CGcpAccount"
  | .paths."/cloud-connect-gcp/entities/account/v1".post.operationId = "CreateD4CGcpAccount"
  | .paths."/cloud-connect-gcp/entities/user-scripts/v1".get.operationId = "GetD4CGcpUserScripts"

  # Rename spotlight-vulnerabilities and spotlight-evaluation-logic collections back to vulnerabilities & vulnerabilities-evaluation-logic
  | walk(
      if type == "object" and .tags and (.tags | index("spotlight-vulnerabilities")) then
        .tags |= map(gsub("spotlight-vulnerabilities"; "vulnerabilities")) 
      elif type == "object" and .tags and (.tags | index("spotlight-evaluation-logic")) then
        .tags |= map(gsub("spotlight-evaluation-logic"; "vulnerabilities-evaluation-logic")) 
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
  
  # Better operationId for workflows collection
  | .paths."/workflows/entities/execute/v1".post.operationId = "execute"
  | .paths."/workflows/entities/execution-actions/v1".post.operationId = "executions.action"
  | .paths."/workflows/entities/execution-results/v1".get.operationId = "executions.result"
  | .paths."/workflows/system-definitions/deprovision/v1".post.operationId = "deprovision.system-definition"
  | .paths."/workflows/system-definitions/promote/v1".post.operationId = "promote.system-definition"
  | .paths."/workflows/system-definitions/provision/v1".post.operationId = "provision.system-definition"

  # Better operationId for logscale-management collection
  | .paths."/loggingapi/combined/initialize/v1".post.operationId = "Initialize"
  | .paths."/loggingapi/combined/repos/v1".get.operationId = "ListRepos"
  | .paths."/loggingapi/entities/views/v1".get.operationId = "ListViews"
  | .paths."/loggingapi/entities/views/v1".post.operationId = "CreateView"
 
  # Better operationId for scheduled-reports collection
  | .paths."/reports/entities/scheduled-reports/execution/v1".post.operationId = "Execute"
  | .paths."/reports/entities/scheduled-reports/v1".get.operationId = "QueryById"
  | .paths."/reports/queries/scheduled-reports/v1".get.operationId = "Query"

# Better operationId for saved-searches collection
  | .paths."/loggingapi/combined/saved-searches/v1".get.operationId = "QueryCombined"
  | .paths."/loggingapi/entities/saved-searches-deploy/v1".post.operationId = "Deploy"
  | .paths."/loggingapi/entities/saved-searches-dynamic-execute/v1".post.operationId = "ExecuteDynamic"
  | .paths."/loggingapi/entities/saved-searches-execute/v1".get.operationId = "Result"
  | .paths."/loggingapi/entities/saved-searches-execute/v1".post.operationId = "Execute"
  | .paths."/loggingapi/entities/saved-searches-ingest/v1".post.operationId = "Ingest"
  | .paths."/loggingapi/entities/saved-searches-validate/v1".post.operationId = "Validate"
  | .paths."/loggingapi/entities/saved-searches/v1".get.operationId = "QueryById"
  | .paths."/loggingapi/entities/saved-searches/v1".post.operationId = "CreateSavedSearch"
  | .paths."/loggingapi/entities/saved-searches/v1".delete.operationId = "DeleteSavedSearch"
  | .paths."/loggingapi/entities/saved-searches/v1".patch.operationId = "UpdateSavedSearch"
  | .paths."/loggingapi/queries/saved-searches/v1".get.operationId = "Query"



 
