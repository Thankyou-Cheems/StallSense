<#
.SYNOPSIS
Asynchronous runner for long Windows repair operations (DISM, SFC, CHKDSK, Windows Update reset).

.DESCRIPTION
DISM /RestoreHealth and sfc /scannow routinely take 10-45 minutes. Running them inline from an
agent or automation shell almost always hits the shell timeout and leaves the operation in an
unknown state. This script decouples launch from completion:

  start   Launch the action as a detached background process and return immediately.
  status  Cheap poll: running/elapsed/progress/last log lines, or exit code + interpretation.
  wait    Poll until done or -TimeoutSeconds elapses, then return current state (never hangs).
  log     Print the last -TailLines of the job's output log.
  list    List known jobs and their states.

Typical agent loop:
  invoke-windows-repair.ps1 start -Action dism-restorehealth
  # ... do other work, or sleep ...
  invoke-windows-repair.ps1 wait -TimeoutSeconds 50      # repeat until State=Completed
  invoke-windows-repair.ps1 status -AsJson               # machine-readable final state

Jobs survive the launching shell. State lives under:
  %ProgramData%\pc-health-repair (elevated) or %LOCALAPPDATA%\pc-health-repair (not elevated).

.NOTES
All actions except dns-flush require an elevated shell at *launch* time.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('start','status','wait','log','list')]
    [string]$Mode = 'status',

    [ValidateSet(
        'dism-checkhealth',      # seconds: read pending-corruption flags only
        'dism-scanhealth',       # 5-20 min: deep store scan, no repair
        'dism-restorehealth',    # 10-45+ min: repair component store (may download from WU)
        'dism-analyze-store',    # 1-5 min: component store size / cleanup recommendation
        'dism-component-cleanup',# 10-60 min: WinSxS cleanup
        'sfc-verifyonly',        # 5-30 min: system file check only, no repair
        'sfc-scannow',           # 5-30 min: system file check + repair from store
        'chkdsk-scan',           # 1-10 min: online NTFS scan, no scheduled repair
        'chkdsk-schedule',       # seconds: schedules autochk for next boot on -Drive
        'wu-reset',              # 1-3 min: stop WU services, rename SoftwareDistribution/catroot2, restart
        'winsock-reset',         # seconds: netsh winsock reset (reboot required)
        'dns-flush'              # seconds: ipconfig /flushdns
    )]
    [string]$Action,

    [ValidatePattern('^[A-Za-z]$')]
    [string]$Drive = 'C',

    # Job to inspect for status/wait/log. Defaults to the most recently started job.
    [string]$JobId,

    [int]$TailLines = 25,
    # wait mode: maximum seconds to block before returning current state. Keep this BELOW the
    # calling shell's timeout; call wait repeatedly instead of raising it.
    [int]$TimeoutSeconds = 50,
    [int]$PollSeconds = 5,
    [switch]$AsJson,
    # Internal marker used when the runner relaunches itself through UAC.
    [switch]$ElevatedChild
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-StateRoot {
    $root = if (Test-Admin) { Join-Path $env:ProgramData 'pc-health-repair' } else { Join-Path $env:LOCALAPPDATA 'pc-health-repair' }
    if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    return $root
}

function Get-StateRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    $programDataRoot = Join-Path $env:ProgramData 'pc-health-repair'
    $localRoot = Join-Path $env:LOCALAPPDATA 'pc-health-repair'
    foreach ($root in @($programDataRoot, $localRoot)) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        if ($roots -contains $root) { continue }
        try {
            if (Test-Path -LiteralPath $root) { $roots.Add($root) | Out-Null }
        } catch { }
    }
    if ($roots.Count -eq 0) { $roots.Add((Get-StateRoot)) | Out-Null }
    return $roots.ToArray()
}

function ConvertTo-ProcessArgument {
    param([string]$Value)
    if ($null -eq $Value) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Get-CurrentPowerShellPath {
    try {
        $path = (Get-Process -Id $PID -ErrorAction Stop).Path
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    } catch { }
    return (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

function Get-ActionSpec {
    param([string]$ActionName, [string]$DriveLetter)
    switch ($ActionName) {
        'dism-checkhealth'       { @{ Exe = "$env:SystemRoot\System32\dism.exe"; Args = @('/Online','/Cleanup-Image','/CheckHealth');           Admin = $true;  Expected = 'seconds';   StripNulls = $false } }
        'dism-scanhealth'        { @{ Exe = "$env:SystemRoot\System32\dism.exe"; Args = @('/Online','/Cleanup-Image','/ScanHealth');            Admin = $true;  Expected = '5-20 min';  StripNulls = $false } }
        'dism-restorehealth'     { @{ Exe = "$env:SystemRoot\System32\dism.exe"; Args = @('/Online','/Cleanup-Image','/RestoreHealth');         Admin = $true;  Expected = '10-45 min'; StripNulls = $false } }
        'dism-analyze-store'     { @{ Exe = "$env:SystemRoot\System32\dism.exe"; Args = @('/Online','/Cleanup-Image','/AnalyzeComponentStore'); Admin = $true;  Expected = '1-5 min';   StripNulls = $false } }
        'dism-component-cleanup' { @{ Exe = "$env:SystemRoot\System32\dism.exe"; Args = @('/Online','/Cleanup-Image','/StartComponentCleanup'); Admin = $true;  Expected = '10-60 min'; StripNulls = $false } }
        'sfc-verifyonly'         { @{ Exe = "$env:SystemRoot\System32\sfc.exe";  Args = @('/verifyonly');                                       Admin = $true;  Expected = '5-30 min';  StripNulls = $true  } }
        'sfc-scannow'            { @{ Exe = "$env:SystemRoot\System32\sfc.exe";  Args = @('/scannow');                                          Admin = $true;  Expected = '5-30 min';  StripNulls = $true  } }
        'chkdsk-scan'            { @{ Exe = "$env:SystemRoot\System32\chkdsk.exe"; Args = @("${DriveLetter}:",'/scan');                         Admin = $true;  Expected = '1-10 min';  StripNulls = $false } }
        'chkdsk-schedule'        { @{ Exe = 'cmd.exe'; Args = @('/c', "echo y| chkdsk ${DriveLetter}: /f");                                     Admin = $true;  Expected = 'seconds';   StripNulls = $false } }
        'winsock-reset'          { @{ Exe = "$env:SystemRoot\System32\netsh.exe"; Args = @('winsock','reset');                                  Admin = $true;  Expected = 'seconds';   StripNulls = $false } }
        'dns-flush'              { @{ Exe = "$env:SystemRoot\System32\ipconfig.exe"; Args = @('/flushdns');                                     Admin = $false; Expected = 'seconds';   StripNulls = $false } }
        'wu-reset'               { @{ Exe = $null; Args = @(); Admin = $true; Expected = '1-3 min'; StripNulls = $false; Inline = $true } }
        default { throw "Unknown action: $ActionName" }
    }
}

function Get-JobDirs {
    $dirs = @()
    foreach ($root in Get-StateRoots) {
        $dirs += @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)
    }
    @($dirs | Sort-Object Name -Descending)
}

function Resolve-JobDir {
    param([string]$Id)
    $dirs = Get-JobDirs
    if ($dirs.Count -eq 0) { return $null }
    if ([string]::IsNullOrWhiteSpace($Id)) { return $dirs[0] }
    $match = $dirs | Where-Object { $_.Name -eq $Id -or $_.Name -like "*$Id*" } | Select-Object -First 1
    return $match
}

function Read-JobLogTail {
    param([string]$JobDir, [int]$Lines, [bool]$StripNulls)
    $raw = @()
    foreach ($name in @('output.log', 'output.log.cmd')) {
        $logPath = Join-Path $JobDir $name
        if (Test-Path -LiteralPath $logPath) {
            # output.log.cmd is the live stdout redirect while the job runs; it gets merged into
            # output.log when the wrapper finishes, after which it only duplicates content we
            # would already have, but tailing both is harmless and keeps mid-run status live.
            $raw += @(Get-Content -LiteralPath $logPath -Tail ([Math]::Max($Lines, 1)) -ErrorAction SilentlyContinue | ForEach-Object { [string]$_ })
        }
    }
    if ($StripNulls) { $raw = @($raw | ForEach-Object { ($_ -replace "`0", '') }) }
    return @($raw | Where-Object { $_ -match '\S' } | Select-Object -Last ([Math]::Max($Lines, 1)))
}

function Get-DismProgress {
    param([string[]]$LogTail)
    # DISM writes lines like "[==========                 18.0%                          ]"
    for ($i = $LogTail.Count - 1; $i -ge 0; $i--) {
        $match = [regex]::Match($LogTail[$i], '(\d{1,3}(?:\.\d)?)%')
        if ($match.Success) { return $match.Groups[1].Value + '%' }
    }
    return $null
}

function Get-ExitInterpretation {
    param([string]$ActionName, [int]$ExitCode, [string[]]$LogTail)
    $text = ($LogTail -join "`n")
    if ($ActionName -like 'dism-*') {
        switch ($ExitCode) {
            0     { if ($text -match 'repairable')      { return 'Corruption detected and repairable. Run dism-restorehealth next.' }
                    if ($text -match 'No component store corruption') { return 'Component store is healthy.' }
                    return 'Completed successfully.' }
            87    { return 'Invalid argument (exit 87). Check DISM syntax and Windows edition.' }
            1726  { return 'RPC failure (exit 1726). Retry after reboot; check Winmgmt/RpcSs services.' }
            3010  { return 'Success, reboot required to finish.' }
            default {
                if ($ExitCode -eq -2146498529 -or $text -match '0x800f081f') { return 'Source files not found (0x800f081f). Retry with internet access, or use /Source: pointing at matching install media (install.wim) plus /LimitAccess.' }
                if ($text -match '0x800f0906') { return 'Source could not be downloaded (0x800f0906). Check network/WSUS policy, or provide /Source.' }
                return "Failed with exit code $ExitCode. Check C:\Windows\Logs\DISM\dism.log around the end time."
            }
        }
    }
    if ($ActionName -like 'sfc-*') {
        if ($text -match 'did not find any integrity violations') { return 'No integrity violations found.' }
        if ($ActionName -eq 'sfc-verifyonly' -and $text -match 'found integrity violations') { return 'Integrity violations found. Run dism-restorehealth if component store health is suspect, then sfc-scannow when repair is approved.' }
        if ($text -match 'successfully repaired')   { return 'Corrupt files found and repaired. Verify [SR] lines in C:\Windows\Logs\CBS\CBS.log, then reboot.' }
        if ($text -match 'unable to fix')           { return 'Corrupt files found but NOT repaired. Run dism-restorehealth, then rerun sfc-scannow.' }
        if ($text -match 'could not perform')        { return 'SFC could not run (often pending reboot or servicing in progress). Reboot and retry.' }
        return "Completed with exit code $ExitCode. Parse the log text; SFC exit codes alone are unreliable."
    }
    if ($ActionName -eq 'chkdsk-schedule') {
        if ($text -match 'will be checked|scheduled') { return 'chkdsk scheduled for next boot. Reboot to run it; check Wininit event 1001 afterwards.' }
        return "Completed with exit code $ExitCode. Verify scheduling output in the log."
    }
    if ($ActionName -eq 'chkdsk-scan') {
        if ($ExitCode -eq 0) { return 'Online disk scan completed. Review the log tail for file-system problems or required offline repair.' }
        return "Online disk scan completed with exit code $ExitCode. Review the log tail; offline repair may be required."
    }
    if ($ActionName -eq 'winsock-reset') { return 'Winsock catalog reset. Reboot required to take effect.' }
    if ($ActionName -eq 'wu-reset') {
        if ($ExitCode -eq 0) { return 'Windows Update caches renamed and services restarted. Check for updates to verify; old folders kept as *.bak-<timestamp> for rollback.' }
        return "WU reset reported exit code $ExitCode. Review the log; services may need manual restart."
    }
    if ($ExitCode -eq 0) { return 'Completed successfully.' }
    return "Completed with exit code $ExitCode."
}

function New-WrapperScript {
    param([string]$JobDir, [hashtable]$Spec, [string]$ActionName, [string]$DriveLetter)
    $wrapperPath = Join-Path $JobDir 'wrapper.ps1'
    $outLog = Join-Path $JobDir 'output.log'
    $exitFile = Join-Path $JobDir 'exitcode.txt'

    if ($Spec.ContainsKey('Inline') -and $Spec.Inline) {
        # wu-reset is a multi-step PowerShell procedure, not a single exe.
        $body = @"
`$ErrorActionPreference = 'Continue'
function Log([string]`$m) { Add-Content -LiteralPath '$outLog' -Value ("{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), `$m) }
`$code = 0
try {
    `$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    `$services = @('wuauserv','bits','cryptsvc','msiserver')
    foreach (`$s in `$services) { Log "Stopping `$s"; Stop-Service -Name `$s -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 3
    foreach (`$pair in @(
        @{ Path = "`$env:SystemRoot\SoftwareDistribution"; New = "`$env:SystemRoot\SoftwareDistribution.bak-`$stamp" },
        @{ Path = "`$env:SystemRoot\System32\catroot2";    New = "`$env:SystemRoot\System32\catroot2.bak-`$stamp" }
    )) {
        if (Test-Path -LiteralPath `$pair.Path) {
            Log "Renaming `$(`$pair.Path) -> `$(`$pair.New)"
            try { Rename-Item -LiteralPath `$pair.Path -NewName (Split-Path -Leaf `$pair.New) -ErrorAction Stop }
            catch { Log "RENAME FAILED: `$(`$_.Exception.Message)"; `$code = 1 }
        } else { Log "Not present, skipping: `$(`$pair.Path)" }
    }
    foreach (`$s in `$services) { Log "Starting `$s"; Start-Service -Name `$s -ErrorAction SilentlyContinue }
    Log 'Windows Update reset finished.'
} catch {
    Log "FATAL: `$(`$_.Exception.Message)"
    `$code = 1
}
Set-Content -LiteralPath '$exitFile' -Value `$code
"@
        Set-Content -LiteralPath $wrapperPath -Value $body -Encoding UTF8
        return $wrapperPath
    }

    $argArrayLiteral = (@($Spec.Args | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', ')
    $exeEscaped = $Spec.Exe -replace "'", "''"
    $errLog = Join-Path $JobDir 'stderr.log'
    $body = @"
`$ErrorActionPreference = 'Continue'
Add-Content -LiteralPath '$outLog' -Value ("STARTED {0} :: $ActionName" -f (Get-Date -Format 'o'))
`$code = 1
try {
    `$argList = @($argArrayLiteral)
    & '$exeEscaped' @argList > '$outLog.cmd' 2> '$errLog'
    if (`$null -ne `$LASTEXITCODE) { `$code = `$LASTEXITCODE } else { `$code = 0 }
} catch {
    Add-Content -LiteralPath '$outLog' -Value ("WRAPPER ERROR: {0}" -f `$_.Exception.Message)
}
try {
    if (Test-Path -LiteralPath '$outLog.cmd') {
        Get-Content -LiteralPath '$outLog.cmd' -ErrorAction SilentlyContinue | ForEach-Object { Add-Content -LiteralPath '$outLog' -Value `$_ }
    }
    if ((Test-Path -LiteralPath '$errLog') -and (Get-Item -LiteralPath '$errLog').Length -gt 0) {
        Add-Content -LiteralPath '$outLog' -Value '--- stderr ---'
        Get-Content -LiteralPath '$errLog' -ErrorAction SilentlyContinue | ForEach-Object { Add-Content -LiteralPath '$outLog' -Value `$_ }
    }
} catch { }
Add-Content -LiteralPath '$outLog' -Value ("FINISHED {0} EXIT={1}" -f (Get-Date -Format 'o'), `$code)
Set-Content -LiteralPath '$exitFile' -Value `$code
"@
    Set-Content -LiteralPath $wrapperPath -Value $body -Encoding UTF8
    return $wrapperPath
}

function Invoke-ElevatedStart {
    param([string]$ActionName, [string]$DriveLetter)
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) { throw 'Cannot auto-elevate because PSCommandPath is empty.' }

    $startedAfter = (Get-Date).AddSeconds(-2)
    $childArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath,
        'start',
        '-Action', $ActionName,
        '-Drive', $DriveLetter,
        '-ElevatedChild'
    )
    if ($AsJson) { $childArgs += '-AsJson' }
    $argumentLine = (@($childArgs | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' ')
    $process = Start-Process -FilePath (Get-CurrentPowerShellPath) -ArgumentList $argumentLine -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "Elevated start exited with code $($process.ExitCode)." }

    Start-Sleep -Milliseconds 300
    $dir = Get-JobDirs |
        Where-Object { $_.Name -like "*-$ActionName" -and $_.LastWriteTime -ge $startedAfter } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($dir) {
        Write-Status (Get-JobStatus -JobDir $dir -Lines $TailLines)
        return
    }
    if ($AsJson) {
        [pscustomobject]@{ Action = $ActionName; State = 'StartedElevated'; Note = 'Job was started elevated, but its state directory was not visible to this user.' } | ConvertTo-Json
    } else {
        Write-Host "STARTED_ELEVATED ACTION=$ActionName"
        Write-Host 'Job was started elevated, but its state directory was not visible to this user.'
    }
}

function Get-JobStatus {
    param([System.IO.DirectoryInfo]$JobDir, [int]$Lines = 25)
    $metaPath = Join-Path $JobDir.FullName 'job.json'
    if (-not (Test-Path -LiteralPath $metaPath)) { return $null }
    $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
    $spec = Get-ActionSpec -ActionName $meta.Action -DriveLetter 'C'
    $exitFile = Join-Path $JobDir.FullName 'exitcode.txt'
    $tail = Read-JobLogTail -JobDir $JobDir.FullName -Lines $Lines -StripNulls ([bool]$spec.StripNulls)
    $elapsed = [Math]::Round(((Get-Date) - [datetime]$meta.StartedAt).TotalMinutes, 1)

    if (Test-Path -LiteralPath $exitFile) {
        $exitCode = 0
        try { $exitCode = [int]((Get-Content -LiteralPath $exitFile -Raw).Trim()) } catch { }
        return [pscustomobject]@{
            JobId = $JobDir.Name; Action = $meta.Action; State = 'Completed'
            ExitCode = $exitCode
            Interpretation = (Get-ExitInterpretation -ActionName $meta.Action -ExitCode $exitCode -LogTail $tail)
            ElapsedMinutes = $elapsed; Progress = $null; LogTail = $tail
        }
    }

    $alive = $false
    if ($meta.WrapperPid) {
        $proc = Get-Process -Id ([int]$meta.WrapperPid) -ErrorAction SilentlyContinue
        $alive = [bool]$proc
    }
    $state = if ($alive) { 'Running' } else { 'Unknown (wrapper not running, no exit code; it may have been killed)' }
    return [pscustomobject]@{
        JobId = $JobDir.Name; Action = $meta.Action; State = $state
        ExitCode = $null
        Interpretation = ("Expected duration: {0}. Poll again with: invoke-windows-repair.ps1 wait" -f $meta.ExpectedDuration)
        ElapsedMinutes = $elapsed
        Progress = (Get-DismProgress -LogTail $tail)
        LogTail = $tail
    }
}

function Write-Status {
    param($Status)
    if ($AsJson) { $Status | ConvertTo-Json -Depth 5; return }
    if ($null -eq $Status) { Write-Host 'No jobs found. Use: invoke-windows-repair.ps1 start -Action <action>'; return }
    Write-Host ("JOB={0} ACTION={1} STATE={2} ELAPSED={3}min PROGRESS={4} EXIT={5}" -f `
        $Status.JobId, $Status.Action, $Status.State, $Status.ElapsedMinutes, $Status.Progress, $Status.ExitCode)
    Write-Host ("INTERPRETATION: {0}" -f $Status.Interpretation)
    if ($Status.LogTail -and $Status.LogTail.Count -gt 0) {
        Write-Host '--- log tail ---'
        $Status.LogTail | ForEach-Object { Write-Host $_ }
    }
}

switch ($Mode) {
    'start' {
        if ([string]::IsNullOrWhiteSpace($Action)) { throw "start requires -Action. Valid: dism-checkhealth, dism-scanhealth, dism-restorehealth, dism-analyze-store, dism-component-cleanup, sfc-verifyonly, sfc-scannow, chkdsk-scan, chkdsk-schedule, wu-reset, winsock-reset, dns-flush" }
        $spec = Get-ActionSpec -ActionName $Action -DriveLetter $Drive
        if ($spec.Admin -and -not (Test-Admin) -and -not $ElevatedChild) {
            Invoke-ElevatedStart -ActionName $Action -DriveLetter $Drive
            break
        }
        if ($spec.Admin -and -not (Test-Admin)) { throw "Action '$Action' requires an elevated (Administrator) shell." }

        # Refuse overlapping servicing operations: DISM and SFC share the servicing stack.
        $servicingActions = @('dism-scanhealth','dism-restorehealth','dism-component-cleanup','sfc-verifyonly','sfc-scannow','dism-checkhealth','dism-analyze-store')
        if ($Action -in $servicingActions) {
            foreach ($dir in Get-JobDirs) {
                $existing = Get-JobStatus -JobDir $dir -Lines 3
                if ($existing -and $existing.State -eq 'Running' -and $existing.Action -in $servicingActions) {
                    throw "A servicing job is already running ($($existing.JobId) :: $($existing.Action)). Wait for it; concurrent DISM/SFC runs conflict."
                }
            }
        }

        $jobId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $Action
        $jobDir = Join-Path (Get-StateRoot) $jobId
        New-Item -ItemType Directory -Path $jobDir -Force | Out-Null
        $wrapper = New-WrapperScript -JobDir $jobDir -Spec $spec -ActionName $Action -DriveLetter $Drive

        $proc = Start-Process -FilePath 'powershell.exe' `
            -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$wrapper`"" `
            -WindowStyle Hidden -PassThru
        $meta = [ordered]@{
            JobId = $jobId; Action = $Action; Drive = $Drive
            StartedAt = (Get-Date).ToString('o')
            WrapperPid = $proc.Id
            ExpectedDuration = $spec.Expected
        }
        $meta | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $jobDir 'job.json') -Encoding UTF8

        $launched = [pscustomobject]@{
            JobId = $jobId; Action = $Action; State = 'Started'; WrapperPid = $proc.Id
            ExpectedDuration = $spec.Expected
            Next = "Poll with: invoke-windows-repair.ps1 wait -JobId $jobId -TimeoutSeconds 50"
        }
        if ($AsJson) { $launched | ConvertTo-Json } else {
            Write-Host ("STARTED JOB={0} PID={1} EXPECTED={2}" -f $jobId, $proc.Id, $spec.Expected)
            Write-Host $launched.Next
        }
    }
    'status' {
        $dir = Resolve-JobDir -Id $JobId
        $statusResult = if ($dir) { Get-JobStatus -JobDir $dir -Lines $TailLines } else { $null }
        Write-Status $statusResult
    }
    'wait' {
        $dir = Resolve-JobDir -Id $JobId
        if (-not $dir) { Write-Status $null; break }
        $deadline = (Get-Date).AddSeconds([Math]::Max($TimeoutSeconds, 1))
        $status = $null
        while ($true) {
            $status = Get-JobStatus -JobDir $dir -Lines $TailLines
            if ($status.State -ne 'Running') { break }
            if ((Get-Date) -ge $deadline) { break }
            Start-Sleep -Seconds ([Math]::Max($PollSeconds, 1))
        }
        Write-Status $status
    }
    'log' {
        $dir = Resolve-JobDir -Id $JobId
        if (-not $dir) { Write-Status $null; break }
        $metaPath = Join-Path $dir.FullName 'job.json'
        $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
        $spec = Get-ActionSpec -ActionName $meta.Action -DriveLetter 'C'
        $tail = Read-JobLogTail -JobDir $dir.FullName -Lines $TailLines -StripNulls ([bool]$spec.StripNulls)
        if ($AsJson) { @{ JobId = $dir.Name; LogTail = $tail } | ConvertTo-Json -Depth 4 } else { $tail | ForEach-Object { Write-Host $_ } }
    }
    'list' {
        $rows = @()
        foreach ($dir in Get-JobDirs) {
            $status = Get-JobStatus -JobDir $dir -Lines 1
            if ($status) { $rows += ($status | Select-Object JobId, Action, State, ExitCode, ElapsedMinutes) }
        }
        if ($AsJson) { $rows | ConvertTo-Json -Depth 4 } else { $rows | Format-Table -AutoSize | Out-String | Write-Host }
    }
}
