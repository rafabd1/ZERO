package intel

import (
	"encoding/json"
	"os"
	"strings"
)

type TechnologyAliases map[string][]string

func DefaultTechnologyAliases() TechnologyAliases {
	return TechnologyAliases{
		"Cisco ASA":             {"adaptive security appliance", "asa webvpn", "webvpn"},
		"Cisco FTD":             {"firepower threat defense", "ftd webvpn", "webvpn"},
		"Apache HTTP Server":    {"apache http server", "apache httpd", "http_server"},
		"Ivanti Connect Secure": {"connect secure", "pulse connect secure"},
		"Fortinet FortiGate":    {"fortigate", "fortios"},
	}
}

func LoadTechnologyAliases(path string) (TechnologyAliases, error) {
	aliases := DefaultTechnologyAliases()
	if path == "" {
		return aliases, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var custom map[string][]string
	if err := json.Unmarshal(raw, &custom); err != nil {
		return nil, err
	}
	for key, values := range custom {
		aliases[key] = values
	}
	return aliases, nil
}

func (a TechnologyAliases) MatchAliases(value string) []string {
	value = normalizeText(value)
	out := []string{}
	for key, aliases := range a {
		keyText := normalizeText(key)
		if keyText != "" && (value == keyText || containsAllTokens(value, keyText)) {
			for _, alias := range aliases {
				if normalized := normalizeText(alias); normalized != "" {
					out = append(out, normalized)
				}
			}
		}
	}
	return out
}

func containsAllTokens(value, tokens string) bool {
	for _, token := range significantTokens(tokens) {
		if !containsWord(value, token) {
			return false
		}
	}
	return true
}

func containsWord(value, token string) bool {
	return strings.Contains(" "+value+" ", " "+token+" ")
}
