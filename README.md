# StallSense

Practical Windows health audit CLI for freezes, black screens, duplicate app installs, stale startup entries, driver/filter drift, network tunnel conflicts, security-policy surprises, component-health state, noisy event logs, and timeout-safe repair workflows.

Audits are read-only. When selected checks benefit from Administrator access, the collector automatically relaunches itself through Windows UAC and writes the elevated report back to the same output path. Long repair operations are launched through an asynchronous runner so DISM, SFC, CHKDSK, and Windows Update reset jobs can be started and polled without tying up the calling shell. The legacy built-in fix remains the narrow PCIe Link State Power Management toggle used for idle-resume GPU troubleshooting.

## Quick Start

```bash
npm install
npm run build
npm run quick -- --days 14
```

## CLI

```bash
node dist/index.js audit [--days N] [--quick] [--sections A,B] [--exclude-sections A,B] [--json] [--out path] [--no-elevate] [--progress] [--probe-tools]
node dist/index.js quick [--days N] [--json] [--out path]
node dist/index.js analyze [--days N] [--json] [--out path]
node dist/index.js fix --pcie-off [--dry-run]
node dist/index.js repair [start|status|wait|log|list] [--action name] [--job-id id] [--json]
```

Options:

- `--days N`: Event-log window, default `14`.
- `--quick`: Run the timeout-friendly first-pass section set.
- `--sections A,B`: Run only selected collector sections, such as `EventLogs,GpuStability`.
- `--exclude-sections A,B`: Skip selected sections during a broader run.
- `--no-elevate`: Do not auto-relaunch through UAC; useful for CI or intentionally limited scans.
- `--json`: Print the full JSON report after collection.
- `--out path`: Write the report to a specific JSON path.
- `--progress`: Print section timings and write `<report>.progress.log`.
- `--probe-tools`: Also collect selected developer tool versions. Off by default because some CLIs start background services.
- `--max-system-events N`, `--max-app-events N`: Cap event-log reads.
- `--event-message-max-length N`: Truncate event messages in JSON; `0` disables truncation.
- `--dry-run`: Show fix commands without applying them.

Examples:

```bash
npm run quick -- --days 14
npm run audit -- --quick --days 14
npm run audit -- --sections EventLogs,GpuStability --days 30
npm run audit -- --no-elevate --sections System
npm run audit -- --json --out report.json
npm run repair -- start --action dism-checkhealth
npm run repair -- wait --timeout 50
npm run fix -- --pcie-off --dry-run
```

Repair actions:

- `dism-checkhealth`, `dism-scanhealth`, `dism-restorehealth`, `dism-analyze-store`, `dism-component-cleanup`
- `sfc-scannow`, `chkdsk-schedule`, `wu-reset`, `winsock-reset`, `dns-flush`

Use `repair start` to launch, then `repair status`, `repair wait --timeout 50`, or `repair log` to inspect progress. Most repair actions require an elevated terminal; `dns-flush` does not.

## What It Checks

- Startup: Run/RunOnce, StartupApproved, Startup folders, services, scheduled tasks.
- Persistence: Winlogon, IFEO debuggers, AppInit/AppCert DLLs, WMI permanent subscriptions, browser native messaging hosts, Explorer shell extensions.
- Apps: duplicate uninstall entries, stale uninstallers/icons, broken Start Menu shortcuts, winget/scoop/choco drift.
- Drivers/devices: service drivers, missing driver files, UpperFilters/LowerFilters, third-party kernel drivers.
- Network: WinHTTP/user proxy, DNS, routes, Winsock, firewall profiles, Wintun/TAP/TUN/VPN adapters and services.
- Security policy: Defender, SmartScreen, PowerShell execution policy, RDP, RemoteRegistry, SMB1, local admins, LSA anonymous-access settings.
- Windows health: pending reboot, CBS/servicing state, Windows Update policy, Store/Gaming Services, recent CBS repair lines, low disk space, dirty volumes, SMART, page-file and commit pressure.
- Stability: Kernel-Power, BugCheck, WHEA, GPU/TDR, virtual display adapters, NVIDIA/overlay processes, Reliability Monitor, WER crash census, minidumps, LiveKernelReports.
- Daily operation drift: critical service state for audio, search, update, DNS, firewall, time sync, hosts file overrides, Windows Update/Store/Gaming Services state.
- Developer environment: PATH duplicates/missing entries and common toolchain command resolution.

## Notes

- Windows only.
- The default collector attempts UAC elevation when needed; Windows may still require the interactive user to approve that system prompt.
- Treat findings as evidence, not automatic delete instructions. Export registry keys/tasks before manual cleanup.
- The collector writes a compact `<report>.summary.json` next to the full JSON report; read it first when triaging.
- `pc-freeze-troubleshooting.skill` packages the matching Codex skill for agent-assisted diagnosis and repair planning.
