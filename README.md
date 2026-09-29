# Almighty Blocker Unstoppable

Almighty Blocker is a small daemon that continuously enforces a curated set of host redirects on the local machine and protects that configuration with an optional watchdog and self-defence features.

Key ideas:
- Blocking is enforced through configured encrypted DNS, managed hosts-file entries for domains
  in `blockAddress`, and outbound firewall rules for literal IPs in `torEntryIPs` and `blockAddress`.
- The daemon enforces configured external DNS servers on active interfaces and monitors for tampering.
- The generated bulk hosts block remains reserved; only explicit `blockAddress` domains are managed at runtime.
- A primary/watchdog pair provides automatic restart: the primary does the work, the watchdog monitors its heartbeat and restarts it if it crashes.
- Self-defence (camouflage, DNS guard, automatic service/unit registration) is compiled in by default. To disable these features build with the `noprotection` tag.

## Build

1. Edit `env.json` (see `env-example.json`) to configure remote sources and local files used to produce the compiled blocklist.
2. Generate the embedded hosts data and build binaries:

```bash
go run ./cmd/build
```

This command produces Go constants (`generated_hosts.go` and `generated_env.go`) that are compiled into the binary. Typical outputs are placed under `dist/` (e.g. `dist/almighty-blocker-windows-amd64.exe`, `dist/almighty-blocker-linux-amd64`).

Useful build flags:
- `-refresh-tor-ips`: updates `torEntryIPs` from Onionoo before building (optional seed for first startup).
- `-tor-ip-limit`: max number of unique IP entries kept in `torEntryIPs` (default `0`, unlimited).

Example:

```bash
go run ./cmd/build -refresh-tor-ips -tor-ip-limit 1500 -no-protection
```

## Configuration (env.json)

Fields:
- `sources`: list of remote URLs to fetch plain text block lists from.
- `files`: list of local file paths to include when building the embedded blocklist.
- `DNS`: list of external DNS servers to enforce on the host adapters. Both IPv4 and IPv6 entries are supported and enforced per family. Default is Cloudflare *family* filtering (malware + adult): `1.1.1.3`/`1.0.0.3` and their IPv6 equivalents `2606:4700:4700::1113`/`2606:4700:4700::1003`.
- `upstreamDNS`: legacy compatibility field. If `DNS` is omitted, values from `upstreamDNS` are used when possible.
- `torEntryIPs`: optional list of IPv4/IPv6 addresses of Tor guard/entry nodes to block at the network level. See [Managing torEntryIPs](#managing-torentryips) for how to populate this list.
- `blockAddress`: manual block list. Domains are added to a managed section of the system hosts file and literal IPs are blocked by the firewall. `api.protonvpn.ch` is always included by default. Domain entries avoid static IP lists, which are fragile for services that rotate addresses.
- `blockedPrograms`: executable names or absolute paths blocked by Windows Firewall and AppLocker. ProtonVPN is enabled by default with `ProtonVPN.exe` and `ProtonVPNService.exe`. AppLocker path rules only cover the configured/default paths; copying an executable elsewhere or renaming it can bypass a path rule.

On **Windows 11** every configured DNS server IP is mapped to the Cloudflare family DNS-over-HTTPS endpoint (`https://family.cloudflare-dns.com/dns-query`) with strict, fallback-free auto-upgrade (`netsh dns add encryption ... autoupgrade=yes udpfallback=no`), so resolution is always encrypted and cannot be downgraded to plaintext. On Linux, DoH depends on the host resolver stack (systemd-resolved/NetworkManager) and is not configured by this service.

Example `DNS`:

```json
[
  "1.1.1.3",
  "1.0.0.3",
  "2606:4700:4700::1113",
  "2606:4700:4700::1003"
]
```

`sources` and `files` may be empty. In that case the build still succeeds and generates an empty embedded blocklist.

`env.json` is embedded into the binary at build time and loaded from memory at runtime. The service does not depend on an external `env.json` file after build.

## Managing torEntryIPs

The `torEntryIPs` field lists IP addresses of Tor guard/entry nodes. Blocking these prevents devices on the network from establishing connections to the Tor network.

**Manual:** edit `env.json` and add IP address strings to the `torEntryIPs` array.

**From Onionoo (recommended):** fetch the current list of running guard relays and extract IP addresses:

```bash
curl -s 'https://onionoo.torproject.org/details?flag=Guard&running=true&fields=or_addresses' \
  | jq -r '..|strings|scan("(\\d{1,3}(?:\\.\\d{1,3}){3})")' \
  | awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255' \
  | sort -u
```

Copy the output into the `torEntryIPs` array in `env.json`.

**Runtime sync (default):** the app fetches Onionoo at runtime and periodically refreshes the in-memory Tor IP list. No rebuild is required for updates.

You can still seed `torEntryIPs` via builder (`go run ./cmd/build -refresh-tor-ips`) for the first startup while runtime sync is warming up.

Notes:
- Use only plain IP addresses without ports (e.g. `"1.2.3.4"`, `"2001:db8::1"`).
- The Tor relay list changes frequently; refreshing weekly or daily is recommended.

## Runtime

Flags:
- `--role` — `primary` (default) or `watchdog`. Normal users only start the primary; the watchdog role is spawned and managed automatically.
- `--state-dir` — directory used to exchange heartbeat JSON files between roles (defaults to OS temp dir if empty).
- `--service-name` — OS service/unit identifier used when registering as a service; used by startup-registration and camouflage.

When protection is enabled (default build):
- The primary enforces configured DNS servers on the OS network interfaces.
- The primary blocks domains from `blockAddress` through a managed hosts-file section on Windows and Linux, and enforces literal IPs in `torEntryIPs` and `blockAddress` through the host firewall. Both IPv4 and IPv6 IPs are enforced (iptables/ip6tables on Linux, per-family netsh rules on Windows). On Windows, configured executables are also blocked by outbound program rules and AppLocker deny rules.
- Tor IPs are reconciled continuously: new Onionoo IPs are added and removed IPs are cleaned automatically from Tor-labeled firewall rules.
- A watchdog process monitors the primary through heartbeat files in `--state-dir`. The watchdog may spawn or restart the primary when needed.

When protection is disabled (build with `-tags noprotection`):
- Self-defence features (camouflage, DNS hijack guard, watchdog envelope, automatic service/unit registration) are omitted at build time.
- The binary applies DNS + firewall configuration once at startup and then only logs if settings are changed or removed.

## Services / Installation

Linux (systemd):
- The primary will attempt to ensure a systemd unit file exists and enabled at `/etc/systemd/system/<service-name>.service`. The provided `deploy/systemd/install-systemd.sh` helper can be used to install the unit.
- The unit runs the binary as root so it can manage `/etc/hosts`.

Windows (Service Control Manager):
- On startup the primary checks for a Windows service with the configured name. If missing it will create or update the service using `sc.exe` and set `binPath` to the stable executable under `%ProgramFiles%\Almighty Blocker`, with `--role=primary --state-dir=... --service-name="<name>"`.
- `deploy/windows/install-service.ps1` installs that copy with access for SYSTEM and Administrators to modify it, and read/execute access for Users. Run installation and uninstallation from an elevated PowerShell prompt.
- The Service Control Manager restarts the service after unexpected failures (5, 15, then 60 seconds). An intentional Stop remains effective; Administrators can stop or uninstall the service. This protects the binary from standard-user changes, but is not tamper-proof against administrators.
- Recovery only works while the registered executable exists. If an older install points to a missing binary, reinstall with `deploy/windows/install-service.ps1` and the built executable to repair its path.

Note: service registration requires administrative privileges.

## Developer notes

- Runtime configuration (`env.json`) is embedded into the binary by `cmd/build` as `generated_env.go` and loaded from memory at startup; there is no external config dependency after build.
- `cmd/build` also embeds a blocklist constant (`generated_hosts.go`) from the configured `sources`/`files`, but it is currently inert — hosts-file enforcement is disabled, so the constant is not read at runtime.
- DNS enforcement uses `internal/dnshijack` and firewall enforcement uses `internal/firewallguard`.
- Camouflage randomizes process/service display name on supported platforms. This is a compile-time-enabled feature and can be removed by building with the `noprotection` tag.

## Troubleshooting

- If the DNS server fails to bind (permission or port in use), the binary will abort rather than redirect system DNS to a non-responsive address.
- On Windows, if DNS requests time out to `127.0.0.1` while the process is running, check for port 53 conflicts (commonly `SharedAccess` / Internet Connection Sharing) and stop/disable that service from an elevated shell.
- If domain blocking works in `nslookup` but not in apps or `ping`, verify IPv6 DNS settings too. Set IPv6 DNS to `::1` (or disable IPv6 DNS on the adapter), because many clients prefer IPv6 resolvers and can bypass `127.0.0.1`.
- Check journal logs on Linux: `sudo journalctl -u <service-name> -f`.
- On Windows, run the binary from an elevated PowerShell to see logs or check the event log / service manager for messages.

## Contributing

Pull requests should include tests where applicable and avoid changing build tags unexpectedly. For debugging, rebuild with `go run ./cmd/build` after updating `env.json` sources.

## License

See LICENSE.
