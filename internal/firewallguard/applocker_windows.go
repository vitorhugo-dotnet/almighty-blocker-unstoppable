//go:build windows

package firewallguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func applyAppLocker(paths []string) error {
	policy, err := buildAppLockerPolicy(paths)
	if err != nil {
		return err
	}
	policyFile, err := os.CreateTemp("", "almighty-proton-applocker-*.xml")
	if err != nil {
		return fmt.Errorf("create AppLocker policy file: %w", err)
	}
	policyPath := policyFile.Name()
	defer os.Remove(policyPath)
	if _, err := policyFile.Write(policy); err != nil {
		_ = policyFile.Close()
		return fmt.Errorf("write AppLocker policy file: %w", err)
	}
	if err := policyFile.Close(); err != nil {
		return fmt.Errorf("close AppLocker policy file: %w", err)
	}

	scriptFile, err := os.CreateTemp("", "almighty-proton-applocker-*.ps1")
	if err != nil {
		return fmt.Errorf("create AppLocker script: %w", err)
	}
	scriptPath := scriptFile.Name()
	defer os.Remove(scriptPath)
	script := "$ErrorActionPreference = 'Stop'\n" +
		"Set-Service -Name AppIDSvc -StartupType Automatic\n" +
		"Start-Service -Name AppIDSvc\n" +
		"Set-AppLockerPolicy -XmlPolicy '" + strings.ReplaceAll(policyPath, "'", "''") + "' -Merge\n"
	if _, err := scriptFile.WriteString(script); err != nil {
		_ = scriptFile.Close()
		return fmt.Errorf("write AppLocker script: %w", err)
	}
	if err := scriptFile.Close(); err != nil {
		return fmt.Errorf("close AppLocker script: %w", err)
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	hideWindow(cmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apply AppLocker policy: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func blockedProgramPaths(programs []string) []string {
	seen := make(map[string]struct{})
	paths := make([]string, 0, len(programs)*3)
	add := func(path string) {
		path = filepath.Clean(os.ExpandEnv(path))
		if path == "." || path == "" {
			return
		}
		key := strings.ToLower(path)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		paths = append(paths, path)
	}

	for _, program := range programs {
		program = strings.TrimSpace(program)
		if program == "" {
			continue
		}
		if filepath.IsAbs(program) {
			add(program)
			continue
		}
		for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
			if root != "" {
				add(filepath.Join(root, "Proton", "VPN", program))
			}
		}
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			add(filepath.Join(local, "Programs", "Proton VPN", program))
		}
	}
	return paths
}
