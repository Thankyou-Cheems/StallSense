import { spawnSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { basename, resolve } from "path";

type Severity = "High" | "Medium" | "Low" | "Info";

type Finding = {
  Severity?: Severity;
  Category?: string;
  Message?: string;
  Recommendation?: string;
};

type SectionTiming = {
  Section?: string;
  Seconds?: number;
  Status?: string;
};

type AuditDigest = {
  GeneratedAt?: string;
  Mode?: string;
  Days?: number;
  IsAdmin?: boolean;
  Elevation?: string;
  OutputPath?: string;
  FullReportPath?: string;
  Findings?: Finding[];
  FindingCounts?: Partial<Record<Severity, number>>;
  Errors?: Array<{ Area?: string; Message?: string }>;
  ErrorCount?: number;
  SectionsRun?: string[];
  SectionsSkipped?: string[];
  SlowestSections?: SectionTiming[];
};

type HealthReport = AuditDigest & {
  SectionTimings?: SectionTiming[];
  Sections?: Record<string, unknown>;
};

type AuditRun = {
  reportPath: string;
  summary?: AuditDigest;
  report?: HealthReport;
};

type ParsedArgs = {
  cmd: string;
  flags: Map<string, string | boolean>;
  positionals: string[];
};

const DEFAULT_DAYS = 14;
const SEVERITIES = ["High", "Medium", "Low", "Info"] as const;
const SEVERITY_RANK = new Map<string, number>(SEVERITIES.map((severity, index) => [severity, index]));

function parseArgs(argv: string[]): ParsedArgs {
  const args = [...argv];
  const cmd = args.length && !args[0].startsWith("-") ? String(args.shift()) : "audit";
  const flags = new Map<string, string | boolean>();
  const positionals: string[] = [];

  while (args.length) {
    const arg = String(args.shift());
    if (!arg.startsWith("--")) {
      positionals.push(arg);
      continue;
    }

    const eq = arg.indexOf("=");
    if (eq >= 0) {
      flags.set(arg.slice(2, eq), arg.slice(eq + 1));
      continue;
    }

    const key = arg.slice(2);
    const next = args[0];
    flags.set(key, next && !next.startsWith("--") ? String(args.shift()) : true);
  }

  return { cmd, flags, positionals };
}

function flag(flags: Map<string, string | boolean>, name: string, fallback?: string): string | undefined {
  const value = flags.get(name);
  if (value === undefined) return fallback;
  return value === true ? "true" : String(value);
}

function boolFlag(flags: Map<string, string | boolean>, name: string): boolean {
  return flags.get(name) === true || flags.get(name) === "true";
}

function listFlag(flags: Map<string, string | boolean>, name: string): string[] {
  const value = flag(flags, name);
  if (!value || value === "true") return [];
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function findPowerShell(): string {
  for (const exe of ["pwsh", "powershell"]) {
    const result = spawnSync(exe, ["-NoProfile", "-NonInteractive", "-Command", "Write-Output ok"], {
      encoding: "utf8",
      windowsHide: true,
    });
    if (!result.error && result.status === 0) return exe;
  }
  throw new Error("PowerShell is required but was not found.");
}

function runPowerShell(args: string[]): string {
  const result = spawnSync(findPowerShell(), args, {
    encoding: "utf8",
    windowsHide: true,
  });

  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || "").trim();
    throw new Error(`PowerShell failed (${result.status}). ${detail}`);
  }
  return (result.stdout || "").trim();
}

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function auditScriptPath(): string {
  const candidates = [
    resolve(__dirname, "..", "scripts", "collect-windows-health.ps1"),
    resolve(process.cwd(), "scripts", "collect-windows-health.ps1"),
  ];
  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error("collect-windows-health.ps1 was not found. Run from the StallSense package root or reinstall the package.");
  }
  return found;
}

function repairScriptPath(): string {
  const candidates = [
    resolve(__dirname, "..", "scripts", "invoke-windows-repair.ps1"),
    resolve(process.cwd(), "scripts", "invoke-windows-repair.ps1"),
  ];
  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error("invoke-windows-repair.ps1 was not found. Run from the StallSense package root or reinstall the package.");
  }
  return found;
}

function summaryPathFor(reportPath: string): string {
  return reportPath.toLowerCase().endsWith(".json")
    ? `${reportPath.slice(0, -5)}.summary.json`
    : `${reportPath}.summary.json`;
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function appendNumberArg(
  args: string[],
  flags: Map<string, string | boolean>,
  flagName: string,
  psName: string,
): void {
  const value = flag(flags, flagName);
  if (!value || value === "true") return;
  const numberValue = Number(value);
  if (!Number.isFinite(numberValue)) throw new Error(`--${flagName} must be a number.`);
  args.push(psName, String(numberValue));
}

function runAudit(flags: Map<string, string | boolean>, loadFullReport: boolean): AuditRun {
  if (process.platform !== "win32") {
    throw new Error("StallSense currently supports Windows only.");
  }

  const days = Number(flag(flags, "days", String(DEFAULT_DAYS)));
  const outPath = resolve(flag(flags, "out", `stallsense-audit-${timestamp()}.json`) as string);
  const psArgs = [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    auditScriptPath(),
    "-Days",
    String(Number.isFinite(days) ? days : DEFAULT_DAYS),
    "-OutputPath",
    outPath,
  ];

  if (boolFlag(flags, "quick")) psArgs.push("-Quick");
  if (boolFlag(flags, "no-elevate")) psArgs.push("-NoElevate");
  if (boolFlag(flags, "progress")) psArgs.push("-DiagnosticProgress");
  if (boolFlag(flags, "probe-tools")) psArgs.push("-ProbeToolVersions");

  const sections = listFlag(flags, "sections");
  if (sections.length) psArgs.push("-Sections", ...sections);
  const excludeSections = listFlag(flags, "exclude-sections");
  if (excludeSections.length) psArgs.push("-ExcludeSections", ...excludeSections);
  appendNumberArg(psArgs, flags, "max-system-events", "-MaxSystemEvents");
  appendNumberArg(psArgs, flags, "max-app-events", "-MaxAppEvents");
  appendNumberArg(psArgs, flags, "event-message-max-length", "-EventMessageMaxLength");

  const lines = runPowerShell(psArgs).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const summaryLine = [...lines].reverse().find((line) => line.startsWith("SUMMARY="));
  const reportLine = [...lines].reverse().find((line) => line.toLowerCase().endsWith(".json") && !line.startsWith("SUMMARY="));
  const reportPath = resolve(reportLine || outPath);
  const summaryPath = resolve(summaryLine ? summaryLine.slice("SUMMARY=".length) : summaryPathFor(reportPath));
  const run: AuditRun = { reportPath };

  if (existsSync(summaryPath)) {
    run.summary = readJson<AuditDigest>(summaryPath);
    run.summary.FullReportPath = run.summary.FullReportPath || reportPath;
  }

  if (loadFullReport || !run.summary) {
    run.report = readJson<HealthReport>(reportPath);
    run.report.OutputPath = run.report.OutputPath || reportPath;
  }

  return run;
}

function summarize(report: AuditDigest): void {
  const findings = report.Findings || [];
  const counts = new Map<string, number>();
  for (const severity of SEVERITIES) counts.set(severity, 0);
  if (report.FindingCounts) {
    for (const severity of SEVERITIES) counts.set(severity, report.FindingCounts[severity] || 0);
  } else {
    for (const finding of findings) {
      counts.set(finding.Severity || "Info", (counts.get(finding.Severity || "Info") || 0) + 1);
    }
  }

  console.log("StallSense Windows Health Audit");
  console.log(`Generated: ${report.GeneratedAt || "unknown"}`);
  if (report.Mode) console.log(`Mode: ${report.Mode}`);
  if (report.Elevation) console.log(`Elevation: ${report.Elevation}${report.IsAdmin === undefined ? "" : ` (admin=${report.IsAdmin})`}`);
  console.log(`Window: last ${report.Days ?? DEFAULT_DAYS} days`);
  if (report.OutputPath || report.FullReportPath) console.log(`Report: ${report.OutputPath || report.FullReportPath}`);
  if (report.SectionsRun?.length) {
    console.log(`Sections: ${report.SectionsRun.length} run, ${report.SectionsSkipped?.length || 0} skipped`);
  }

  console.log("\nFindings:");
  console.log(`- High: ${counts.get("High") || 0}`);
  console.log(`- Medium: ${counts.get("Medium") || 0}`);
  console.log(`- Low: ${counts.get("Low") || 0}`);
  console.log(`- Info: ${counts.get("Info") || 0}`);

  const top = findings
    .filter((finding) => finding.Severity === "High" || finding.Severity === "Medium")
    .sort((a, b) => (SEVERITY_RANK.get(a.Severity || "Info") ?? 99) - (SEVERITY_RANK.get(b.Severity || "Info") ?? 99))
    .slice(0, 12);

  if (top.length) {
    console.log("\nTop items:");
    for (const finding of top) {
      console.log(`- [${finding.Severity}] ${finding.Category || "General"}: ${finding.Message || ""}`);
      if (finding.Recommendation) console.log(`  Next: ${finding.Recommendation}`);
    }
  } else {
    console.log("\nTop items:");
    console.log("- No high or medium findings.");
  }

  if (report.Errors?.length) {
    console.log("\nCollection warnings:");
    for (const error of report.Errors.slice(0, 8)) {
      console.log(`- ${error.Area || "Unknown"}: ${error.Message || ""}`);
    }
    if (report.Errors.length > 8) console.log(`- ... ${report.Errors.length - 8} more in the JSON report`);
  } else if (report.ErrorCount) {
    console.log(`\nCollection warnings: ${report.ErrorCount} warning(s); see the full JSON report for details.`);
  }
}

function fixPcieOff(dryRun: boolean): void {
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
  console.log(runPowerShell(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]));
}

function runRepair(flags: Map<string, string | boolean>, positionals: string[]): string {
  const mode = positionals[0] || flag(flags, "mode", "status") || "status";
  const psArgs = [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    repairScriptPath(),
    mode,
  ];

  const stringArgs: Array<[string, string]> = [
    ["action", "-Action"],
    ["drive", "-Drive"],
    ["job-id", "-JobId"],
    ["job", "-JobId"],
  ];
  for (const [flagName, psName] of stringArgs) {
    const value = flag(flags, flagName);
    if (value && value !== "true") psArgs.push(psName, value);
  }
  appendNumberArg(psArgs, flags, "tail-lines", "-TailLines");
  appendNumberArg(psArgs, flags, "tail", "-TailLines");
  appendNumberArg(psArgs, flags, "timeout-seconds", "-TimeoutSeconds");
  appendNumberArg(psArgs, flags, "timeout", "-TimeoutSeconds");
  appendNumberArg(psArgs, flags, "poll-seconds", "-PollSeconds");
  appendNumberArg(psArgs, flags, "poll", "-PollSeconds");
  if (boolFlag(flags, "json") || boolFlag(flags, "as-json")) psArgs.push("-AsJson");

  return runPowerShell(psArgs);
}

function help(): void {
  console.log("Usage:");
  console.log("  stallsense audit [--days N] [--quick] [--sections A,B] [--exclude-sections A,B] [--json] [--out path] [--no-elevate]");
  console.log("  stallsense quick [--days N] [--json] [--out path]");
  console.log("  stallsense analyze [--days N] [--json] [--out path]");
  console.log("  stallsense fix --pcie-off [--dry-run]");
  console.log("  stallsense repair [start|status|wait|log|list] [--action name] [--job-id id] [--json]");
  console.log("");
  console.log("Audit options:");
  console.log("  --no-elevate, --progress, --probe-tools, --max-system-events N, --max-app-events N, --event-message-max-length N");
  console.log("");
  console.log("Repair actions:");
  console.log("  dism-checkhealth, dism-scanhealth, dism-restorehealth, dism-analyze-store,");
  console.log("  dism-component-cleanup, sfc-scannow, chkdsk-schedule, wu-reset, winsock-reset, dns-flush");
  console.log("");
  console.log("Examples:");
  console.log("  stallsense audit --days 14");
  console.log("  stallsense quick --days 14");
  console.log("  stallsense audit --sections EventLogs,GpuStability --days 30");
  console.log("  stallsense audit --json --out report.json");
  console.log("  stallsense repair start --action dism-checkhealth");
  console.log("  stallsense repair wait --timeout 50");
  console.log("  stallsense fix --pcie-off --dry-run");
}

function main(): void {
  const { cmd, flags, positionals } = parseArgs(process.argv.slice(2));

  if (cmd === "help" || cmd === "--help" || cmd === "-h") {
    help();
    return;
  }

  if (cmd === "fix") {
    if (!boolFlag(flags, "pcie-off")) {
      help();
      process.exitCode = 1;
      return;
    }
    fixPcieOff(boolFlag(flags, "dry-run"));
    return;
  }

  if (cmd === "repair") {
    const output = runRepair(flags, positionals);
    if (output) console.log(output);
    return;
  }

  if (cmd === "quick") {
    flags.set("quick", true);
  }

  if (cmd === "audit" || cmd === "analyze" || cmd === "quick") {
    const run = runAudit(flags, boolFlag(flags, "json"));
    if (boolFlag(flags, "json")) {
      console.log(JSON.stringify(run.report, null, 2));
    } else {
      summarize((run.summary || run.report) as AuditDigest);
      console.log(`\nOpen the full JSON report for raw evidence: ${basename(run.reportPath)}`);
    }
    return;
  }

  help();
  process.exitCode = 1;
}

main();
