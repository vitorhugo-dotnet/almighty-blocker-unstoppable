package domainblock

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"almighty-blocker-unstoppable/internal/logger"
	"almighty-blocker-unstoppable/internal/redirects"
)

const (
	beginMarker   = "# >>> almighty-blocker domain block >>>"
	endMarker     = "# <<< almighty-blocker domain block <<<"
	checkInterval = 15 * time.Second
)

type Guard struct {
	log       *slog.Logger
	path      string
	redirects []string
	warnOnly  bool
}

func New(blockAddress []string, warnOnly bool) *Guard {
	return newAtPath(blockAddress, hostsPath(), warnOnly)
}

func newAtPath(blockAddress []string, path string, warnOnly bool) *Guard {
	entries := make([]string, 0, len(blockAddress))
	seen := make(map[string]struct{}, len(blockAddress))
	for _, value := range blockAddress {
		domain := normalizeDomain(value)
		if domain == "" || net.ParseIP(domain) != nil {
			continue
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		entries = append(entries, "0.0.0.0 "+domain)
	}
	return &Guard{
		log:       logger.New("domain-block-guard"),
		path:      path,
		redirects: entries,
		warnOnly:  warnOnly,
	}
}

func hostsPath() string {
	switch runtime.GOOS {
	case "windows":
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts")
	case "linux":
		return "/etc/hosts"
	default:
		return ""
	}
}

func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func (g *Guard) Run(ctx context.Context) {
	if err := g.EnforceOnce(); err != nil {
		g.log.Error("initial domain block enforcement failed", "error", err)
	}
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := g.EnforceOnce(); err != nil {
				g.log.Error("domain block enforcement failed", "error", err)
			}
		}
	}
}

func (g *Guard) EnforceOnce() error {
	if g.path == "" {
		return fmt.Errorf("domain blocking is unsupported on %s", runtime.GOOS)
	}
	existing, err := os.ReadFile(g.path)
	if err != nil {
		return fmt.Errorf("read hosts file %s: %w", g.path, err)
	}
	updated, err := redirects.BuildManagedContent(string(existing), g.redirects, beginMarker, endMarker)
	if err != nil {
		return err
	}
	if updated == string(existing) {
		return nil
	}
	if g.warnOnly {
		g.log.Warn("blocked domains missing from hosts file", "path", g.path)
		return nil
	}
	if err := os.WriteFile(g.path, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("write hosts file %s: %w", g.path, err)
	}
	return nil
}
