import { spawnSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { basename, resolve } from "path";

type Finding = {
  Severity?: "High" | "Medium" | "Low" | "Info";
  Category?: string;
  Message?: string;
  Recommendation?: string;
};

type HealthReport = {
  GeneratedAt?: string;
  Days?: number;
  OutputPath?: string;
  Findings?: Finding[];
  Errors?: Array<{ Area?: string; Message?: string }>;
  Sections?: Record<string, unknown>;
};

type ParsedArgs = {
  cmd: string;
  flags: Map<string, string | boolean>;
};

const DEFAULT_DAYS = 14;
const SEVERITIES = ["High", "Medium", "Low", "Info"] as const;
const SEVERITY_RANK = new Map<string, number>(SEVERITIES.map((severity, index) => [severity, index]));

function parseArgs(argv: string[]): ParsedArgs {
  const args = [...argv];
  const cmd = args.length && !args[0].startsWith("-") ? String(args.shift()) : "audit";
  const flags = new Map<string, string | boolean>();

  while (args.length) {
    const arg = String(args.shift());
    if (!arg.startsWith("--")) continue;

    const eq = arg.indexOf("=");
    if (eq >= 0) {
      flags.set(arg.slice(2, eq), arg.slice(eq + 1));
      continue;
    }

    const key = arg.slice(2);
    const next = args[0];
    flags.set(key, next && !next.startsWith("--") ? String(args.shift()) : true);
  }

  return { cmd, flags };
}

function flag(flags: Map<string, string | boolean>, name: string, fallback?: string): string | undefined {
  const value = flags.get(name);
  if (value === undefined) return fallback;
  return value === true ? "true" : String(value);
}

function boolFlag(flags: Map<string, string | boolean>, name: string): boolean {
  return flags.get(name) === true || flags.get(name) === "true";
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

function runAudit(flags: Map<string, string | boolean>): HealthReport {
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

  if (boolFlag(flags, "progress")) psArgs.push("-DiagnosticProgress");
  if (boolFlag(flags, "probe-tools")) psArgs.push("-ProbeToolVersions");

  const scriptOut = runPowerShell(psArgs).split(/\r?\n/).filter(Boolean).pop();
  const reportPath = resolve(scriptOut || outPath);
  const report = JSON.parse(readFileSync(reportPath, "utf8")) as HealthReport;
  report.OutputPath = report.OutputPath || reportPath;
  return report;
}

function summarize(report: HealthReport): void {
  const findings = report.Findings || [];
  const counts = new Map<string, number>();
  for (const severity of SEVERITIES) counts.set(severity, 0);
  for (const finding of findings) {
    counts.set(finding.Severity || "Info", (counts.get(finding.Severity || "Info") || 0) + 1);
  }

  console.log("StallSense Windows Health Audit");
  console.log(`Generated: ${report.GeneratedAt || "unknown"}`);
  console.log(`Window: last ${report.Days ?? DEFAULT_DAYS} days`);
  if (report.OutputPath) console.log(`Report: ${report.OutputPath}`);

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

function help(): void {
  console.log("Usage:");
  console.log("  stallsense audit [--days N] [--json] [--out path] [--progress] [--probe-tools]");
  console.log("  stallsense analyze [--days N] [--json] [--out path]");
  console.log("  stallsense fix --pcie-off [--dry-run]");
  console.log("");
  console.log("Examples:");
  console.log("  stallsense audit --days 14");
  console.log("  stallsense audit --json --out report.json");
  console.log("  stallsense fix --pcie-off --dry-run");
}

function main(): void {
  const { cmd, flags } = parseArgs(process.argv.slice(2));

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

  if (cmd === "audit" || cmd === "analyze") {
    const report = runAudit(flags);
    if (boolFlag(flags, "json")) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      summarize(report);
      console.log(`\nOpen the full JSON report for raw evidence: ${basename(report.OutputPath || "")}`);
    }
    return;
  }

  help();
  process.exitCode = 1;
}

main();
