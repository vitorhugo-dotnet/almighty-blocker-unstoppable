package domainblock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureOnceAddsBlockedDomainsToManagedHostsBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	guard := newAtPath([]string{"API.ProtonVPN.ch", "192.0.2.1"}, path, false)
	if err := guard.EnforceOnce(); err != nil {
		t.Fatalf("EnforceOnce returned error: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), "0.0.0.0 api.protonvpn.ch") {
		t.Fatalf("managed hosts block did not contain Proton API domain:\n%s", first)
	}
	if strings.Contains(string(first), "192.0.2.1") {
		t.Fatalf("IP entries must not be written to the hosts file:\n%s", first)
	}

	if err := guard.EnforceOnce(); err != nil {
		t.Fatalf("second EnforceOnce returned error: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("hosts block is not idempotent:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}
