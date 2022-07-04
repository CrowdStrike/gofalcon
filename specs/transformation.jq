    .definitions."domain.DownloadItem"."type"="string"
  | .definitions."domain.DownloadItem"."format"="binary"
  | .definitions."domain.APIEvaluationLogicItemV1".properties.id.type="string"
  | .paths."/intel/entities/report-files/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  | .paths."/intel/entities/rules-latest-files/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  | .paths."/intel/entities/rules-files/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  | .paths."/intel/entities/rules-latest-files/v1".get.parameters |= . + [{type: "string", description: "Download Only if changed since", name: "If-Modified-Since", "in": "header"}]
  | .paths."/intel/entities/rules-latest-files/v1".get.responses."304" = {description: "Not Modified"}
  | .paths."/oauth2/token".post.responses."201".headers["X-CS-Region"] = {type: "string"}
  | .paths."/policy/queries/sensor-update-kernels/{distinct_field}/v1" = .paths."/policy/queries/sensor-update-kernels/{distinct-field}/v1"
  | del(.paths."/policy/queries/sensor-update-kernels/{distinct-field}/v1")
  | .paths."/policy/queries/sensor-update-kernels/{distinct_field}/v1".get.parameters[0].name = "distinct_field"
  | .paths."/real-time-response/entities/extracted-file-contents/v1"."get"."responses"."200"."schema"={"$ref": "#/definitions/domain.DownloadItem"}
  | .paths."/cloud-connect-azure/entities/download-certificate/v1".get.parameters[1].default = "false"
  | .paths."/cloud-connect-cspm-azure/entities/download-certificate/v1".get.parameters[1].default = "false"