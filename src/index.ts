import { spawnSync } from "child_process";
import { writeFileSync } from "fs";
import { resolve } from "path";

type SystemInfo = {
  os?: Record<string, unknown> | null;
  cpu?: Record<string, unknown> | null;
  gpu?: Array<Record<string, unknown>> | Record<string, unknown> | null;
  bios?: Record<string, unknown> | null;
  computer?: Record<string, unknown> | null;
  power?: Record<string, unknown> | null;
  warnings?: string[];
};

type EventItem = {
  TimeCreated?: string;
  Id?: number;
  ProviderName?: string;
  LevelDisplayName?: string;
  Message?: string;
};

type Analysis = {
  generatedAt: string;
  days: number;
  risk: {
    score: number;
    level: "low" | "medium" | "high";
    rationale: string[];
  };
  signals: {
    crashCount: number;
    gpuDriverEvents: number;
    wheaEvents: number;
    gpuCorrelationCount: number;
    wheaCorrelationCount: number;
    lastCrashTime?: string;
  };
  recommendations: Array<{ title: string; why: string; how?: string }>;
  system: SystemInfo;
  events: EventItem[];
};

const DEFAULT_DAYS = 7;

function findShell(): string {
  // Prefer pwsh if available; fallback to Windows PowerShell.
  const probe = (exe: string) => {
    const r = spawnSync(exe, ["-NoProfile", "-NonInteractive", "-Command", "Write-Output ok"], {
      encoding: "utf8",
    });
    return !r.error && r.status === 0;
  };
  if (probe("pwsh")) return "pwsh";
  return "powershell";
}

function runPowerShell(script: string): string {
  const shell = findShell();
  const result = spawnSync(shell, [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    script,
  ], {
    encoding: "utf8",
    windowsHide: true,
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    const stderr = (result.stderr || "").trim();
    const stdout = (result.stdout || "").trim();
    throw new Error(`PowerShell failed (${result.status}). ${stderr || stdout}`);
  }
  return (result.stdout || "").trim();
}

function parseJson<T>(text: string, fallback: T): T {
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

function parseArgs(argv: string[]) {
  const args = [...argv];
  const cmd = args.length && !args[0].startsWith("-") ? (args.shift() as string) : "analyze";
  const flags = new Map<string, string | boolean>();
  while (args.length) {
    const a = args.shift() as string;
    if (!a.startsWith("--")) continue;
    const eq = a.indexOf("=");
    if (eq >= 0) {
      flags.set(a.slice(2, eq), a.slice(eq + 1));
    } else {
      const next = args[0];
      if (next && !next.startsWith("--")) {
        flags.set(a.slice(2), args.shift() as string);
      } else {
        flags.set(a.slice(2), true);
      }
    }
  }
  return { cmd, flags };
}

function getFlag(flags: Map<string, string | boolean>, name: string, def?: string) {
  const v = flags.get(name);
  if (v === undefined) return def;
  if (v === true) return "true";
  return String(v);
}

function getBool(flags: Map<string, string | boolean>, name: string): boolean {
  return flags.get(name) === true || flags.get(name) === "true";
}

function getSystemInfo(): SystemInfo {
  const script = `
$ErrorActionPreference = 'SilentlyContinue'
$info = [ordered]@{}
try { $info.os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime) } catch { $info.os = $null }
try { $info.cpu = (Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed) } catch { $info.cpu = $null }
try { $info.gpu = (Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, AdapterRAM, PNPDeviceID) } catch { $info.gpu = $null }
try { $info.bios = (Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion, Manufacturer, ReleaseDate) } catch { $info.bios = $null }
try { $info.computer = (Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, SystemType, TotalPhysicalMemory) } catch { $info.computer = $null }
try {
  $info.power = [ordered]@{}
  $info.power.ActiveScheme = (powercfg /getactivescheme | Out-String).Trim()
  $info.power.SleepStates = (powercfg /a | Out-String).Trim()
  $info.power.FastStartup = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
} catch { $info.power = $null }
$info | ConvertTo-Json -Depth 6
`;
  const out = runPowerShell(script);
  const parsed = parseJson<SystemInfo>(out, { warnings: ["Failed to parse system info JSON"] });
  return parsed;
}

function getEvents(days: number): EventItem[] {
  const script = `
$since = (Get-Date).AddDays(-${days})
$ids = 41,6008,4101,14,17,18,19,20,45,46,47
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since} |
  Where-Object { $ids -contains $_.Id } |
  Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
  Sort-Object TimeCreated |
  Select-Object -Last 500 |
  ConvertTo-Json -Depth 3
`;
  const out = runPowerShell(script);
  const parsed = parseJson<EventItem[] | EventItem>(out, [] as EventItem[]);
  if (Array.isArray(parsed)) return parsed;
  return parsed ? [parsed] : [];
}

function toDate(s?: string): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function isGpuEvent(e: EventItem): boolean {
  const p = (e.ProviderName || "").toLowerCase();
  if (p.includes("nvlddmkm") || p.includes("amdkmdag")) return true;
  if ((e.ProviderName || "").toLowerCase().includes("display") && e.Id === 4101) return true;
  return false;
}

function isWheaEvent(e: EventItem): boolean {
  const p = (e.ProviderName || "").toLowerCase();
  if (p.includes("whea")) return true;
  return e.Id === 17 || e.Id === 18 || e.Id === 19;
}

function analyze(events: EventItem[], days: number, system: SystemInfo): Analysis {
  const crashEvents = events.filter((e) => e.Id === 41);
  const gpuEvents = events.filter(isGpuEvent);
  const wheaEvents = events.filter(isWheaEvent);

  const windowMs = 10 * 60 * 1000;
  let gpuCorrelationCount = 0;
  let wheaCorrelationCount = 0;

  for (const crash of crashEvents) {
    const tCrash = toDate(crash.TimeCreated);
    if (!tCrash) continue;
    const start = tCrash.getTime() - windowMs;
    const gpuNear = gpuEvents.some((e) => {
      const t = toDate(e.TimeCreated);
      return t && t.getTime() >= start && t.getTime() <= tCrash.getTime();
    });
    const wheaNear = wheaEvents.some((e) => {
      const t = toDate(e.TimeCreated);
      return t && t.getTime() >= start && t.getTime() <= tCrash.getTime();
    });
    if (gpuNear) gpuCorrelationCount += 1;
    if (wheaNear) wheaCorrelationCount += 1;
  }

  let score = 0;
  const rationale: string[] = [];

  if (crashEvents.length > 0) {
    score += 2;
    rationale.push("Kernel-Power 41 events indicate unexpected shutdowns.");
  }
  if (gpuCorrelationCount > 0) {
    score += 4;
    rationale.push("GPU driver errors appear within 10 minutes before crashes.");
  } else if (gpuEvents.length > 0) {
    score += 1;
    rationale.push("GPU driver errors detected without direct crash correlation.");
  }
  if (wheaCorrelationCount > 0) {
    score += 3;
    rationale.push("WHEA hardware errors appear shortly before crashes.");
  } else if (wheaEvents.length > 0) {
    score += 1;
    rationale.push("WHEA hardware errors detected without direct crash correlation.");
  }
  if (crashEvents.length >= 2) {
    score += 1;
    rationale.push("Multiple crash events in the selected time range.");
  }

  const level: "low" | "medium" | "high" = score >= 6 ? "high" : score >= 3 ? "medium" : "low";

  const recommendations: Array<{ title: string; why: string; how?: string }> = [];

  if (gpuCorrelationCount > 0 || gpuEvents.length > 0) {
    recommendations.push({
      title: "Disable PCIe Link State Power Management",
      why: "GPU resume hangs are often triggered by PCIe power state transitions.",
      how: "Use: powercfg /setacvalueindex <scheme> SUB_PCIEXPRESS ASPM 0"
    });
    recommendations.push({
      title: "Set NVIDIA power management to Prefer maximum performance",
      why: "Keeps the GPU in a stable power state during idle/resume transitions.",
      how: "NVIDIA Control Panel -> Manage 3D settings -> Global -> Power management mode"
    });
    recommendations.push({
      title: "Clean install or rollback the NVIDIA driver",
      why: "Driver regressions commonly cause nvlddmkm/4101 errors.",
      how: "Use the official NVIDIA driver and select Clean Installation."
    });
    recommendations.push({
      title: "Disable HAGS for testing",
      why: "Hardware-accelerated GPU scheduling can increase TDR risk on some systems.",
      how: "Settings -> System -> Display -> Graphics -> Default graphics settings"
    });
  }

  if (wheaCorrelationCount > 0 || wheaEvents.length > 0) {
    recommendations.push({
      title: "Update BIOS and chipset drivers",
      why: "WHEA errors can be caused by firmware or PCIe stability issues."
    });
    recommendations.push({
      title: "Check power delivery and PCIe cabling",
      why: "Transient PCIe power drops can trigger WHEA and GPU hangs."
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      title: "Collect more signals",
      why: "No strong crash correlation detected in the selected time range.",
      how: "Increase the --days window or reproduce the issue once and re-run."
    });
  }

  const lastCrash = crashEvents.length ? crashEvents[crashEvents.length - 1] : undefined;

  return {
    generatedAt: new Date().toISOString(),
    days,
    risk: { score, level, rationale },
    signals: {
      crashCount: crashEvents.length,
      gpuDriverEvents: gpuEvents.length,
      wheaEvents: wheaEvents.length,
      gpuCorrelationCount,
      wheaCorrelationCount,
      lastCrashTime: lastCrash?.TimeCreated,
    },
    recommendations,
    system,
    events,
  };
}

function printAnalysis(analysis: Analysis, asJson: boolean) {
  if (asJson) {
    console.log(JSON.stringify(analysis, null, 2));
    return;
  }

  console.log("Freeze Risk Analyzer (Windows)");
  console.log(`Generated: ${analysis.generatedAt}`);
  console.log(`Window: last ${analysis.days} days`);
  console.log("\nSignals:");
  console.log(`- Kernel-Power 41: ${analysis.signals.crashCount}`);
  console.log(`- GPU driver errors: ${analysis.signals.gpuDriverEvents}`);
  console.log(`- WHEA errors: ${analysis.signals.wheaEvents}`);
  if (analysis.signals.lastCrashTime) {
    console.log(`- Last crash: ${analysis.signals.lastCrashTime}`);
  }

  console.log("\nRisk:");
  console.log(`- Level: ${analysis.risk.level} (score ${analysis.risk.score})`);
  for (const r of analysis.risk.rationale) {
    console.log(`- ${r}`);
  }

  console.log("\nRecommended actions:");
  analysis.recommendations.forEach((rec, idx) => {
    console.log(`${idx + 1}. ${rec.title}`);
    console.log(`   Why: ${rec.why}`);
    if (rec.how) console.log(`   How: ${rec.how}`);
  });

  console.log("\nFix options:");
  console.log("- Run: node dist/index.js fix --pcie-off");
  console.log("- Manual: NVIDIA Control Panel -> Manage 3D settings -> Power management mode -> Prefer maximum performance");
}

function fixPcieOff(dryRun: boolean) {
  const script = `
$scheme = ([regex]::Match((powercfg /getactivescheme), 'GUID:\\s*([a-fA-F0-9-]+)')).Groups[1].Value
$subgroup = '501a4d13-42af-4429-9fd1-a8218c268e20'
$setting  = 'ee12f906-d277-404b-b6da-e5fa1a576df5'
if (${dryRun ? "$true" : "$false"}) {
  Write-Output "DRY_RUN: powercfg /setacvalueindex $scheme $subgroup $setting 0"
  Write-Output "DRY_RUN: powercfg /setdcvalueindex $scheme $subgroup $setting 0"
  Write-Output "DRY_RUN: powercfg /setactive $scheme"
} else {
  powercfg /setacvalueindex $scheme $subgroup $setting 0
  powercfg /setdcvalueindex $scheme $subgroup $setting 0
  powercfg /setactive $scheme
  powercfg /query $scheme $subgroup $setting | Out-String
}
`;
  const out = runPowerShell(script);
  console.log(out);
}

function printHelp() {
  console.log("Usage:");
  console.log("  node dist/index.js analyze [--days N] [--json] [--out path]");
  console.log("  node dist/index.js fix --pcie-off [--dry-run]");
}

function main() {
  if (process.platform !== "win32") {
    console.error("This tool currently supports Windows only.");
    process.exit(1);
  }

  const { cmd, flags } = parseArgs(process.argv.slice(2));
  if (cmd === "help" || cmd === "--help" || cmd === "-h") {
    printHelp();
    return;
  }

  if (cmd === "fix") {
    const dryRun = getBool(flags, "dry-run");
    const pcieOff = getBool(flags, "pcie-off");
    if (!pcieOff) {
      printHelp();
      process.exit(1);
    }
    fixPcieOff(dryRun);
    console.log("NVIDIA power mode must be set manually in NVIDIA Control Panel.");
    return;
  }

  const days = Number(getFlag(flags, "days", String(DEFAULT_DAYS)));
  const asJson = getBool(flags, "json");
  const outPath = getFlag(flags, "out");

  const system = getSystemInfo();
  const events = getEvents(Number.isFinite(days) ? days : DEFAULT_DAYS);
  const analysis = analyze(events, Number.isFinite(days) ? days : DEFAULT_DAYS, system);

  if (outPath) {
    const target = resolve(String(outPath));
    writeFileSync(target, JSON.stringify(analysis, null, 2), "utf8");
  }

  printAnalysis(analysis, asJson);
}

main();
