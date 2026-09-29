package firewallguard

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestBuildAppLockerPolicyCreatesStableNarrowDenyRules(t *testing.T) {
	paths := []string{`C:\Program Files\Proton\VPN\ProtonVPN.exe`, `C:\Program Files\Proton\VPN\ProtonVPNService.exe`}
	first, err := buildAppLockerPolicy(paths)
	if err != nil {
		t.Fatalf("buildAppLockerPolicy returned error: %v", err)
	}
	second, err := buildAppLockerPolicy(paths)
	if err != nil {
		t.Fatalf("second buildAppLockerPolicy returned error: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("AppLocker policy output must be deterministic for merge idempotency")
	}

	var policy struct {
		Collections []struct {
			Type            string `xml:"Type,attr"`
			EnforcementMode string `xml:"EnforcementMode,attr"`
			Rules           []struct {
				ID        string `xml:"Id,attr"`
				Action    string `xml:"Action,attr"`
				SID       string `xml:"UserOrGroupSid,attr"`
				Condition struct {
					FilePath struct {
						Path string `xml:"Path,attr"`
					} `xml:"FilePathCondition"`
				} `xml:"Conditions"`
			} `xml:"FilePathRule"`
		} `xml:"RuleCollection"`
	}
	if err := xml.Unmarshal(first, &policy); err != nil {
		t.Fatalf("invalid AppLocker XML: %v", err)
	}
	if len(policy.Collections) != 1 || policy.Collections[0].Type != "Exe" || policy.Collections[0].EnforcementMode != "Enabled" {
		t.Fatalf("unexpected rule collection: %+v", policy.Collections)
	}
	rules := policy.Collections[0].Rules
	if len(rules) != 2 {
		t.Fatalf("expected two executable deny rules, got %d", len(rules))
	}
	for i, rule := range rules {
		if rule.ID == "" || rule.Action != "Deny" || rule.SID != "S-1-1-0" || rule.Condition.FilePath.Path != paths[i] {
			t.Errorf("unexpected AppLocker rule: %+v", rule)
		}
	}
	if strings.Contains(string(first), "Allow") {
		t.Fatal("policy must not add broad allow rules")
	}
}

func TestBuildAppLockerPolicyRejectsEmptyPaths(t *testing.T) {
	if _, err := buildAppLockerPolicy([]string{"", "  "}); err == nil {
		t.Fatal("expected empty executable path list to be rejected")
	}
}
