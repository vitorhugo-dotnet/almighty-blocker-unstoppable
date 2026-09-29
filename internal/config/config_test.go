package config

import (
	"strings"
	"testing"
)

func TestLoadFromBytesIncludesDefaultProtonBlocks(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(`{"blockAddress":["example.com"]}`))
	if err != nil {
		t.Fatalf("LoadFromBytes returned error: %v", err)
	}

	if !containsString(cfg.BlockAddress, "api.protonvpn.ch") {
		t.Fatalf("default Proton API domain missing from blockAddress: %v", cfg.BlockAddress)
	}
	if len(cfg.BlockedPrograms) != 2 {
		t.Fatalf("expected two default blocked programs, got %v", cfg.BlockedPrograms)
	}
	for _, program := range []string{"ProtonVPN.exe", "ProtonVPNService.exe"} {
		if !containsString(cfg.BlockedPrograms, program) {
			t.Errorf("default blocked program %q missing from %v", program, cfg.BlockedPrograms)
		}
	}
}

func TestLoadFromBytesPreservesConfiguredBlockedPrograms(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(`{"blockedPrograms":["C:\\Apps\\ProtonVPN.exe"]}`))
	if err != nil {
		t.Fatalf("LoadFromBytes returned error: %v", err)
	}
	if !containsString(cfg.BlockedPrograms, `C:\Apps\ProtonVPN.exe`) {
		t.Fatalf("configured blocked program path was not preserved: %v", cfg.BlockedPrograms)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}
