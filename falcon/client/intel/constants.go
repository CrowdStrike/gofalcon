package intel

type RuleType string

const (
	RuleTypeSnortSuricataMaster    RuleType = "snort-suricata-master"
	RuleTypeSnortSuricataUpdate    RuleType = "snort-suricata-update"
	RuleTypeSnortSuricataChangelog RuleType = "snort-suricata-changelog"
	RuleTypeYaraMaster             RuleType = "yara-master"
	RuleTypeYaraUpdate             RuleType = "yara-update"
	RuleTypeYaraChangelog          RuleType = "yara-changelog"
	RuleTypeCommonEventFormat      RuleType = "common-event-format"
	RuleTypeNetwitness             RuleType = "netwitness"
)

var RuleTypeValidValues = []RuleType{
	RuleTypeSnortSuricataMaster,
	RuleTypeSnortSuricataUpdate,
	RuleTypeSnortSuricataChangelog,
	RuleTypeYaraMaster,
	RuleTypeYaraUpdate,
	RuleTypeYaraChangelog,
	RuleTypeCommonEventFormat,
	RuleTypeNetwitness,
}

func (rt RuleType) Valid() bool {
	for _, item := range RuleTypeValidValues {
		if rt == item {
			return true
		}
	}
	return false
}
