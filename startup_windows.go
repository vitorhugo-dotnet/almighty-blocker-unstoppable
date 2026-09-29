//go:build windows && !noprotection

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const protectedInstallDirectory = "Almighty Blocker"
const protectedExecutableName = "almighty-blocker.exe"

func ensureStartupRegistration(serviceName string, executablePath string, stateDir string) error {
	name := strings.TrimSpace(serviceName)
	if name == "" {
		return nil
	}

	installedPath, err := protectedExecutablePath()
	if err != nil {
		return err
	}

	exists, err := windowsServiceExists(name)
	if err != nil {
		return err
	}
	serviceRunning := false
	if exists {
		serviceRunning, err = windowsServiceRunning(name)
		if err != nil {
			return err
		}
	}

	if !serviceRunning || !fileExists(installedPath) {
		if err := installProtectedExecutable(executablePath, installedPath); err != nil {
			return err
		}
	}
	binPath := fmt.Sprintf("\"%s\" --role=primary --state-dir=\"%s\" --service-name=\"%s\"", installedPath, stateDir, name)

	if !exists {
		create := exec.Command("sc.exe", "create", name, "binPath=", binPath, "start=", "auto", "DisplayName=", "Almighty Blocker")
		hideWindow(create)
		if output, err := create.CombinedOutput(); err != nil {
			return fmt.Errorf("create service %q: %w (%s)", name, err, strings.TrimSpace(string(output)))
		}

		describe := exec.Command("sc.exe", "description", name, "Keeps hosts redirects enforced in background")
		hideWindow(describe)
		if output, err := describe.CombinedOutput(); err != nil {
			return fmt.Errorf("set description for service %q: %w (%s)", name, err, strings.TrimSpace(string(output)))
		}
	} else {
		config := exec.Command("sc.exe", "config", name, "binPath=", binPath, "start=", "auto")
		hideWindow(config)
		if output, err := config.CombinedOutput(); err != nil {
			return fmt.Errorf("update service %q startup config: %w (%s)", name, err, strings.TrimSpace(string(output)))
		}
	}

	return configureServiceRecovery(name)
}

func protectedExecutablePath() (string, error) {
	programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	return filepath.Join(programFiles, protectedInstallDirectory, protectedExecutableName), nil
}

func installProtectedExecutable(source string, destination string) error {
	sourcePath, err := filepath.Abs(source)
	if err != nil {
		return fmt.Errorf("resolve source executable: %w", err)
	}
	destinationPath, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolve protected executable path: %w", err)
	}
	if strings.EqualFold(filepath.Clean(sourcePath), filepath.Clean(destinationPath)) {
		return nil
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read source executable %s: %w", sourcePath, err)
	}
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
		return fmt.Errorf("create protected install directory: %w", err)
	}
	if err := os.WriteFile(destinationPath, data, 0o755); err != nil {
		return fmt.Errorf("install protected executable %s: %w", destinationPath, err)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func windowsServiceRunning(serviceName string) (bool, error) {
	query := exec.Command("sc.exe", "query", serviceName)
	hideWindow(query)
	output, err := query.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("query service %q state: %w (%s)", serviceName, err, strings.TrimSpace(string(output)))
	}
	// The numeric state is stable across localized Windows installations.
	return regexp.MustCompile(`(?m)STATE\s*:\s*4\b`).Match(output), nil
}

func configureServiceRecovery(serviceName string) error {
	failure := exec.Command("sc.exe", "failure", serviceName, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000")
	hideWindow(failure)
	if output, err := failure.CombinedOutput(); err != nil {
		return fmt.Errorf("configure recovery actions for service %q: %w (%s)", serviceName, err, strings.TrimSpace(string(output)))
	}

	failureFlag := exec.Command("sc.exe", "failureflag", serviceName, "1")
	hideWindow(failureFlag)
	if output, err := failureFlag.CombinedOutput(); err != nil {
		return fmt.Errorf("configure non-crash recovery for service %q: %w (%s)", serviceName, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func windowsServiceExists(serviceName string) (bool, error) {
	query := exec.Command("sc.exe", "query", serviceName)
	hideWindow(query)
	output, err := query.CombinedOutput()
	if err == nil {
		return true, nil
	}

	text := strings.ToUpper(string(output))
	if strings.Contains(text, "FAILED 1060") {
		return false, nil
	}

	return false, fmt.Errorf("query service %q: %w (%s)", serviceName, err, strings.TrimSpace(string(output)))
}

// createNoWindow (CREATE_NO_WINDOW) prevents Windows from allocating a console
// for child processes (sc.exe here), so the protected GUI build never flashes a
// terminal window while registering the service.
const createNoWindow = 0x08000000

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
