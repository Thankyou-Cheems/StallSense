# StallSense

Practical Windows health audit CLI for freezes, black screens, duplicate app installs, stale startup entries, driver/filter drift, network tunnel conflicts, security-policy surprises, component-health state, and noisy event logs.

The default audit is read-only. The only built-in fix is the narrow PCIe Link State Power Management toggle used for idle-resume GPU troubleshooting.

## Quick Start

```bash
npm install
npm run build
npm run audit -- --days 14
```

## CLI

```bash
node dist/index.js audit [--days N] [--json] [--out path] [--progress] [--probe-tools]
node dist/index.js analyze [--days N] [--json] [--out path]
node dist/index.js fix --pcie-off [--dry-run]
```

Options:

- `--days N`: Event-log window, default `14`.
- `--json`: Print the full JSON report after collection.
- `--out path`: Write the report to a specific JSON path.
- `--progress`: Print section timings and write `<report>.progress.log`.
- `--probe-tools`: Also collect selected developer tool versions. Off by default because some CLIs start background services.
- `--dry-run`: Show fix commands without applying them.

Examples:

```bash
npm run audit -- --days 14
npm run audit -- --json --out report.json
npm run fix -- --pcie-off --dry-run
```

## What It Checks

- Startup: Run/RunOnce, StartupApproved, Startup folders, services, scheduled tasks.
- Persistence: Winlogon, IFEO debuggers, AppInit/AppCert DLLs, WMI permanent subscriptions, browser native messaging hosts, Explorer shell extensions.
- Apps: duplicate uninstall entries, stale uninstallers/icons, broken Start Menu shortcuts, winget/scoop/choco drift.
- Drivers/devices: service drivers, missing driver files, UpperFilters/LowerFilters, third-party kernel drivers.
- Network: WinHTTP/user proxy, DNS, routes, Winsock, firewall profiles, Wintun/TAP/TUN/VPN adapters and services.
- Security policy: Defender, SmartScreen, PowerShell execution policy, RDP, RemoteRegistry, SMB1, local admins, LSA anonymous-access settings.
- Windows health: pending reboot, CBS/servicing state, Windows Update policy, Store/Gaming Services, recent CBS repair lines.
- Stability: Kernel-Power, BugCheck, WHEA, GPU/TDR, virtual display adapters, NVIDIA/overlay processes, minidumps.
- Developer environment: PATH duplicates/missing entries and common toolchain command resolution.

## Notes

- Windows only.
- Run from an elevated terminal for the most complete report.
- Treat findings as evidence, not automatic delete instructions. Export registry keys/tasks before manual cleanup.
- `pc-freeze-troubleshooting.skill` packages the matching Codex skill for agent-assisted diagnosis.
