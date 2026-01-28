# Freeze Risk Analyzer (Windows)

A small TypeScript CLI that scans Windows Event Viewer signals (Kernel-Power 41, GPU driver errors, WHEA) to estimate the risk of idle-resume hangs and suggests targeted fixes.

## Quick Start
```bash
npm install
npm run build
npm run analyze
```

## CLI Usage
```bash
node dist/index.js analyze [--days N] [--json] [--out path]
node dist/index.js fix --pcie-off [--dry-run]
```

Options:
- `--days N`: How many days of System log history to scan (default: 7).
- `--json`: Print a full JSON report to stdout.
- `--out path`: Write the JSON report to a file.
- `fix --pcie-off`: Disable PCIe Link State Power Management for the active power plan.
- `--dry-run`: Print the `powercfg` commands without applying changes.

Examples:
```bash
npm run analyze -- --days 14
npm run analyze -- --json --out report.json
npm run fix -- --pcie-off --dry-run
```

## What It Reports
- Signals: Kernel-Power 41 count, GPU driver errors, WHEA events, last crash time.
- Risk score: low / medium / high based on correlation within 10 minutes.
- Recommended actions: power settings, driver steps, and firmware checks.

## Notes
- Windows only (uses PowerShell + `powercfg`).
- Some fixes may require running in an elevated shell.

## Manual Troubleshooting Guide (If You Prefer Not to Use Fix)

Symptoms:
- After long idle, the screen stays black or never wakes
- Fans keep spinning / power draw stays high
- Keyboard/mouse do not respond
- A short power-button press cuts power immediately

High-impact steps:
1. Disable PCIe power saving (Control Panel -> Power Options -> Advanced):
   - PCI Express -> Link State Power Management: Off
2. GPU power policy:
   - NVIDIA Control Panel -> Manage 3D settings -> Power management mode: Prefer maximum performance
3. Disable Fast Startup:
   - Control Panel -> Power Options -> Choose what the power buttons do -> uncheck Fast Startup

If it still happens:
- Update or roll back GPU drivers (avoid beta drivers).
- Update BIOS / chipset drivers.
- For desktops: check PCIe cabling and PSU stability.
