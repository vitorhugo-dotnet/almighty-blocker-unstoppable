package firewallguard

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
)

type appLockerPolicy struct {
	XMLName        xml.Name            `xml:"AppLockerPolicy"`
	Version        string              `xml:"Version,attr"`
	RuleCollection appLockerCollection `xml:"RuleCollection"`
}

type appLockerCollection struct {
	Type            string          `xml:"Type,attr"`
	EnforcementMode string          `xml:"EnforcementMode,attr"`
	Rules           []appLockerRule `xml:"FilePathRule"`
}

type appLockerRule struct {
	ID             string              `xml:"Id,attr"`
	Name           string              `xml:"Name,attr"`
	Description    string              `xml:"Description,attr"`
	UserOrGroupSID string              `xml:"UserOrGroupSid,attr"`
	Action         string              `xml:"Action,attr"`
	Conditions     appLockerConditions `xml:"Conditions"`
}

type appLockerConditions struct {
	FilePath appLockerFilePathCondition `xml:"FilePathCondition"`
}

type appLockerFilePathCondition struct {
	Path string `xml:"Path,attr"`
}

func buildAppLockerPolicy(paths []string) ([]byte, error) {
	clean := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		key := strings.ToLower(path)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		clean = append(clean, path)
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("no ProtonVPN executable paths configured for AppLocker")
	}

	rules := make([]appLockerRule, 0, len(clean))
	for _, path := range clean {
		base := path[strings.LastIndexAny(path, `/\`)+1:]
		rules = append(rules, appLockerRule{
			ID:             appLockerRuleID(path),
			Name:           "Almighty Block ProtonVPN - " + base,
			Description:    "Blocks ProtonVPN executable by path.",
			UserOrGroupSID: "S-1-1-0",
			Action:         "Deny",
			Conditions:     appLockerConditions{FilePath: appLockerFilePathCondition{Path: path}},
		})
	}

	return xml.Marshal(appLockerPolicy{
		Version: "1",
		RuleCollection: appLockerCollection{
			Type:            "Exe",
			EnforcementMode: "Enabled",
			Rules:           rules,
		},
	})
}

func appLockerRuleID(path string) string {
	sum := sha1.Sum([]byte(strings.ToLower(path)))
	bytes := sum[:16]
	bytes[6] = (bytes[6] & 0x0f) | 0x50
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(bytes)
	return "{" + encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:] + "}"
}
