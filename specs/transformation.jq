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
  | del(.definitions."msaspec.Paging")
  | .definitions."domain.RuleMetaInfo".properties.pagination."$ref" = "#/definitions/msa.Paging"
  | .definitions."domain.MsaMetaInfo".properties.pagination."$ref" = "#/definitions/msa.Paging"
  # Rename msaspec.MetaInfo to msa.MetaInfo. These are two names for the same type.
  | del(.definitions."msaspec.MetaInfo")


  # Device v1 API has been deprecated since August 2022. And the end point will be removed at some point in the future.
  | del(.paths."/devices/entities/devices/v1")
  | .paths."/devices/entities/devices//v2".get = .paths."/devices/entities/devices/v2".get
  | .paths."/devices/entities/devices//v2".get.operationId = "GetDeviceDetails"
  | .paths."/devices/entities/devices//v2".get.deprecated = true
  | .paths."/devices/entities/devices//v2".get.summary = "Deprecated: Please use new methods: GetDeviceDetailsV2 or	PostDeviceDetailsV2. This method now redirects to GetDeviceDetailsV2. The original API endpoint will be removed on or sometime after February 9, 2023."
  | .paths."/devices/entities/devices//v2".get.responses."200".schema."$ref" = "#/definitions/domain.DeviceDetailsResponseSwagger"
  | .paths."/devices/entities/devices//v2".get.responses.default.schema."$ref" = "#/definitions/domain.DeviceDetailsResponseSwagger"

  # A patch until DeviceDetails v1 gets removed
  | .definitions."domain.DeviceDetailsResponseSwagger" = .definitions."deviceapi.DeviceDetailsResponseSwagger"
  | .definitions."domain.DeviceSwagger" = .definitions."deviceapi.DeviceSwagger"
  | .definitions."domain.DeviceDetailsResponseSwagger".properties.resources.items."$ref" = "#/definitions/domain.DeviceSwagger"

  # Misc fixes
  | .paths."/intel/entities/rules-latest-files/v1".get.parameters |= . + [{type: "string", description: "Download Only if changed since", name: "If-Modified-Since", "in": "header"}]
  | .paths."/intel/entities/rules-latest-files/v1".get.responses."304" = {description: "Not Modified"}
  | .paths."/oauth2/token".post.responses."201".headers["X-CS-Region"] = {type: "string"}
  | .paths."/policy/queries/sensor-update-kernels/{distinct_field}/v1" = .paths."/policy/queries/sensor-update-kernels/{distinct-field}/v1"
  | del(.paths."/policy/queries/sensor-update-kernels/{distinct-field}/v1")
  | .paths."/policy/queries/sensor-update-kernels/{distinct_field}/v1".get.parameters[0].name = "distinct_field"
  | .paths."/cloud-connect-azure/entities/download-certificate/v1".get.parameters[1].default = "false"
  | .paths."/cloud-connect-cspm-azure/entities/download-certificate/v1".get.parameters[1].default = "false"

  # Needed by rusty-falcon (stricter typing)
  | .definitions."deviceapi.DeviceDetailsResponseSwagger".properties.errors."x-nullable" = true

  # IOA Rule Groups Combined API has incorrect swagger response object: list of ids instead of list of objects
  | .paths."/ioarules/queries/rule-groups-full/v1".get.responses."200" = .paths."/ioarules/entities/rule-groups/v1".get.responses."200"

  # Update the response code value for "/devices/entities/devices/tags/v1" to 202 instead of 200
  | .paths."/devices/entities/devices/tags/v1".patch.responses |= with_entries(if .key == "200" then .key = "202" else . end)
