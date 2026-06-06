param(
    [int]$Days = 14,
    [switch]$ProbeToolVersions,
    [switch]$DiagnosticProgress,
    [string]$OutputPath
)

$ErrorActionPreference = 'Continue'

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-ErrorRecord {
    param([string]$Area, [string]$Message)
    $script:Errors.Add([pscustomobject]@{ Area = $Area; Message = $Message }) | Out-Null
}

function Add-Finding {
    param(
        [ValidateSet('High','Medium','Low','Info')][string]$Severity,
        [string]$Category,
        [string]$Message,
        [object]$Evidence = $null,
        [string]$Recommendation = ''
    )
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Category = $Category
        Message = $Message
        Evidence = $Evidence
        Recommendation = $Recommendation
    }) | Out-Null
}

function Expand-RegistryString {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    return [Environment]::ExpandEnvironmentVariables($Value)
}

function Get-CommandTarget {
    param([AllowNull()][string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $s = (Expand-RegistryString $Command).Trim()
    if ($s.StartsWith('"')) {
        $end = $s.IndexOf('"', 1)
        if ($end -gt 0) { return $s.Substring(1, $end - 1) }
    }
    if ($s.StartsWith("'")) {
        $end = $s.IndexOf("'", 1)
        if ($end -gt 0) { return $s.Substring(1, $end - 1) }
    }
    $match = [regex]::Match($s, '^(?<path>.+?\.(exe|com|cmd|bat|ps1|sys|dll|scr))(?:\s|$)', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($match.Success) { return $match.Groups['path'].Value.Trim() }
    return ($s -split '\s+', 2)[0]
}

function Normalize-LocalPath {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = (Expand-RegistryString $Path).Trim()
    if ($p.StartsWith('"') -and $p.EndsWith('"') -and $p.Length -gt 1) {
        $p = $p.Substring(1, $p.Length - 2)
    }
    $p = $p -replace '^\\\?\?\\', ''
    $p = $p -replace '^\\\\\?\\', ''
    if ($p -match '^\\SystemRoot\\(.+)$') {
        return (Join-Path $env:SystemRoot $Matches[1])
    }
    if ($p -match '^(?i:System32\\.+)$') {
        return (Join-Path $env:SystemRoot $p)
    }
    return $p
}

function Test-LocalFilesystemPath {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ($Path -match '^[A-Za-z]:\\' -or $Path -match '^\\\\')
}

function Get-FileCompany {
    param([AllowNull()][string]$Path)
    try {
        if (-not (Test-LocalFilesystemPath $Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }
        return (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.CompanyName
    } catch {
        return $null
    }
}

function Get-RegistryValueRows {
    param([string]$Path)
    $rows = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Path)) { return $rows.ToArray() }
    try {
        $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -like 'PS*') { continue }
            $rows.Add([pscustomobject]@{
                Path = $Path
                Name = $prop.Name
                Value = $prop.Value
            }) | Out-Null
        }
    } catch {
        Add-ErrorRecord 'RegistryValueRows' "$Path :: $($_.Exception.Message)"
    }
    return $rows.ToArray()
}

function Get-RegistrySubkeyDefaults {
    param([string]$Path)
    $rows = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Path)) { return $rows.ToArray() }
    try {
        foreach ($key in Get-ChildItem -LiteralPath $Path -ErrorAction Stop) {
            $rows.Add([pscustomobject]@{
                Path = $key.PSPath
                Name = $key.PSChildName
                DefaultValue = $key.GetValue('')
            }) | Out-Null
        }
    } catch {
        Add-ErrorRecord 'RegistrySubkeyDefaults' "$Path :: $($_.Exception.Message)"
    }
    return $rows.ToArray()
}

function Get-ServiceRegistryImage {
    param([string]$Name)
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path $path)) { return $null }
    return (Get-ItemProperty -Path $path -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
}

function Get-ShellClsidServer {
    param([AllowNull()][string]$Clsid)
    if ([string]::IsNullOrWhiteSpace($Clsid)) { return $null }
    $clean = $Clsid.Trim()
    foreach ($path in @(
        "Registry::HKEY_CLASSES_ROOT\CLSID\$clean\InprocServer32",
        "Registry::HKEY_CLASSES_ROOT\WOW6432Node\CLSID\$clean\InprocServer32"
    )) {
        try {
            if (Test-Path $path) {
                $value = (Get-Item -Path $path -ErrorAction Stop).GetValue('')
                if ($value) { return $value }
            }
        } catch {
            Add-ErrorRecord 'ShellClsidServer' "$path :: $($_.Exception.Message)"
        }
    }
    return $null
}

function Get-WhereResults {
    param([string]$CommandName)
    try {
        return @(& where.exe $CommandName 2>$null)
    } catch {
        return @()
    }
}

function Test-UnquotedPathWithSpaces {
    param([AllowNull()][string]$Command, [AllowNull()][string]$Target)
    if ([string]::IsNullOrWhiteSpace($Command) -or [string]::IsNullOrWhiteSpace($Target)) { return $false }
    $s = (Expand-RegistryString $Command).Trim()
    if ($s.StartsWith('"') -or $s.StartsWith("'")) { return $false }
    return ($Target -match '\s' -and $s.StartsWith($Target, [StringComparison]::OrdinalIgnoreCase))
}

function Get-DefaultValue {
    param([string]$Path)
    try {
        return (Get-Item -Path $Path -ErrorAction Stop).GetValue('')
    } catch {
        Add-ErrorRecord 'RegistryDefaultValue' "$Path :: $($_.Exception.Message)"
        return $null
    }
}

function Normalize-AppDisplayName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $n = $Name.Trim([char]0).Trim().ToLowerInvariant()
    $n = $n -replace '\s+', ''
    $n = $n -replace '[\(\)\[\]{}_\-:：\.，,、/\\]+', ''
    return $n
}

function Get-UninstallTarget {
    param([AllowNull()][string]$Command)
    $target = Normalize-LocalPath (Get-CommandTarget $Command)
    if ([string]::IsNullOrWhiteSpace($target)) { return $null }
    if ($target -match '^(?i)msiexec(\.exe)?$') { return 'msiexec.exe' }
    return $target
}

function Test-ProbablyNoiseDuplicateApp {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return ($Name -match 'Windows (Software Development Kit|SDK|Driver Kit|App SDK|Desktop Extension SDK|IoT Extension SDK|Mobile Extension SDK|Team Extension SDK)|Extension SDK Contracts|Windows Desktop Runtime|Microsoft[ \.]NET|Microsoft\.NET\.Workload|Microsoft Visual C\+\+|Visual Studio|Universal CRT|Universal General MIDI|Application Verifier|WinRT Intellisense|IntelliTrace|MSI Development Tools|WinAppDeploy|icecap_|NVIDIA|Python 3\.[0-9]+.*(Core|Executables|Standard Library|Documentation|Development Libraries|Tcl/Tk|pip Bootstrap|Test Suite|Add to Path)|PowerToys')
}

function Invoke-Safe {
    param([string]$Area, [scriptblock]$Block)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    if ($DiagnosticProgress) {
        Write-Host "SECTION_START $Area"
        if ($script:DiagnosticPath) { Add-Content -LiteralPath $script:DiagnosticPath -Value "SECTION_START $Area" }
    }
    try {
        $result = & $Block
        $sw.Stop()
        if ($DiagnosticProgress) {
            $line = "SECTION_DONE {0} {1:n3}s" -f $Area, $sw.Elapsed.TotalSeconds
            Write-Host $line
            if ($script:DiagnosticPath) { Add-Content -LiteralPath $script:DiagnosticPath -Value $line }
        }
        return $result
    } catch {
        $sw.Stop()
        Add-ErrorRecord $Area $_.Exception.Message
        if ($DiagnosticProgress) {
            $line = "SECTION_ERROR {0} {1:n3}s" -f $Area, $sw.Elapsed.TotalSeconds
            Write-Host $line
            if ($script:DiagnosticPath) { Add-Content -LiteralPath $script:DiagnosticPath -Value $line }
        }
        return $null
    }
}

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Errors = New-Object System.Collections.Generic.List[object]
$generatedAt = Get-Date
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $safeTime = $generatedAt.ToString('yyyyMMdd-HHmmss')
    $OutputPath = Join-Path (Get-Location) "windows-health-audit-$safeTime.json"
}
$script:DiagnosticPath = if ($DiagnosticProgress) { "$OutputPath.progress.log" } else { $null }
if ($script:DiagnosticPath) { "DIAGNOSTIC_START $($generatedAt.ToString('o'))" | Set-Content -LiteralPath $script:DiagnosticPath -Encoding UTF8 }

$sections = [ordered]@{}
$sections.System = Invoke-Safe 'System' {
    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    [ordered]@{
        ComputerName = $env:COMPUTERNAME
        User = "$env:USERDOMAIN\$env:USERNAME"
        IsAdmin = Test-Admin
        OS = $os | Select-Object Caption, Version, BuildNumber, LastBootUpTime
        ComputerSystem = $computer | Select-Object Manufacturer, Model, SystemType, TotalPhysicalMemory
        BIOS = $bios | Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate
    }
}

$sections.PendingReboot = Invoke-Safe 'PendingReboot' {
    $pendingRename = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    $result = [ordered]@{
        CBSRebootPending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        WindowsUpdateRebootRequired = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        PendingFileRenameOperations = @($pendingRename)
    }
    if ($result.CBSRebootPending -or $result.WindowsUpdateRebootRequired -or $pendingRename) {
        Add-Finding 'Medium' 'WindowsUpdate' 'Windows has pending reboot or rename operations.' $result 'Reboot before deeper repair; do not manually delete pending Windows files.'
    }
    $result
}

$sections.Autoruns = Invoke-Safe 'Autoruns' {
    $autorunKeys = @(
        @{ Hive = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' },
        @{ Hive = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ Hive = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' },
        @{ Hive = 'HKLM'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ Hive = 'HKLM32'; Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' },
        @{ Hive = 'HKLM32'; Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' }
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($key in $autorunKeys) {
        if (-not (Test-Path $key.Path)) { continue }
        $props = Get-ItemProperty -Path $key.Path
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -like 'PS*') { continue }
            $command = [string]$prop.Value
            $target = Normalize-LocalPath (Get-CommandTarget $command)
            $isLocal = Test-LocalFilesystemPath $target
            $exists = if ($isLocal) { Test-Path -LiteralPath $target } else { $null }
            $unquoted = Test-UnquotedPathWithSpaces $command $target
            $row = [pscustomobject]@{
                Hive = $key.Hive
                Key = $key.Path
                Name = $prop.Name
                Command = $command
                Target = $target
                TargetExists = $exists
                UnquotedPathWithSpaces = $unquoted
            }
            $rows.Add($row) | Out-Null
            if ($isLocal -and -not $exists) {
                Add-Finding 'Medium' 'Autoruns' "Startup entry target is missing: $($prop.Name)" $row 'Remove the autorun entry after exporting the key.'
            }
            if ($unquoted) {
                Add-Finding 'Medium' 'Autoruns' "Startup entry path with spaces is unquoted: $($prop.Name)" $row 'Quote the executable path, preserving arguments.'
            }
        }
    }
    $rows.ToArray()
}

$sections.StartupControl = Invoke-Safe 'StartupControl' {
    $startupApprovedKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    )
    $approved = New-Object System.Collections.Generic.List[object]
    foreach ($key in $startupApprovedKeys) {
        foreach ($row in Get-RegistryValueRows $key) {
            $bytes = @($row.Value)
            $state = 'Unknown'
            if ($bytes.Count -gt 0) {
                if ($bytes[0] -eq 2) { $state = 'Enabled' }
                elseif ($bytes[0] -eq 3) { $state = 'Disabled' }
                elseif ($bytes[0] -eq 6) { $state = 'EnabledByPolicyOrUser' }
            }
            $approved.Add([pscustomobject]@{
                Path = $row.Path
                Name = $row.Name
                State = $state
                Raw = $row.Value
            }) | Out-Null
        }
    }

    $startupFolders = New-Object System.Collections.Generic.List[object]
    $folderCandidates = @(
        [Environment]::GetFolderPath('Startup'),
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    foreach ($folder in $folderCandidates) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($item in Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue) {
            $startupFolders.Add([pscustomobject]@{
                Folder = $folder
                Name = $item.Name
                FullName = $item.FullName
                Length = $item.Length
                LastWriteTime = $item.LastWriteTime
            }) | Out-Null
        }
    }

    [ordered]@{
        StartupApproved = $approved.ToArray()
        StartupFolders = $startupFolders.ToArray()
    }
}

$sections.Services = Invoke-Safe 'Services' {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($svc in Get-CimInstance Win32_Service) {
        $target = Normalize-LocalPath (Get-CommandTarget $svc.PathName)
        $isLocal = Test-LocalFilesystemPath $target
        $exists = if ($isLocal) { Test-Path -LiteralPath $target } else { $null }
        $unquoted = Test-UnquotedPathWithSpaces $svc.PathName $target
        $row = [pscustomobject]@{
            Name = $svc.Name
            DisplayName = $svc.DisplayName
            State = $svc.State
            StartMode = $svc.StartMode
            StartName = $svc.StartName
            PathName = $svc.PathName
            Target = $target
            TargetExists = $exists
            UnquotedPathWithSpaces = $unquoted
        }
        if (($isLocal -and -not $exists) -or $unquoted) { $rows.Add($row) | Out-Null }
        if ($isLocal -and -not $exists -and $svc.StartMode -ne 'Disabled') {
            Add-Finding 'Medium' 'Services' "Service target is missing: $($svc.Name)" $row 'Confirm the software is removed, then delete or repair the service.'
        }
        if ($unquoted) {
            Add-Finding 'Medium' 'Services' "Service path with spaces is unquoted: $($svc.Name)" $row 'Quote the ImagePath or use sc.exe config carefully.'
        }
    }
    $rows.ToArray()
}

$sections.ScheduledTasks = Invoke-Safe 'ScheduledTasks' {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($task in Get-ScheduledTask) {
        foreach ($action in $task.Actions) {
            if (-not $action.Execute) { continue }
            $target = Normalize-LocalPath (Get-CommandTarget $action.Execute)
            $isLocal = Test-LocalFilesystemPath $target
            $exists = if ($isLocal) { Test-Path -LiteralPath $target } else { $null }
            $row = [pscustomobject]@{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State
                Execute = $action.Execute
                Arguments = $action.Arguments
                Target = $target
                TargetExists = $exists
            }
            if ($isLocal -and -not $exists) { $rows.Add($row) | Out-Null }
            if ($isLocal -and -not $exists -and $task.TaskPath -notlike '\Microsoft*') {
                Add-Finding 'Medium' 'ScheduledTasks' "Scheduled task target is missing: $($task.TaskPath)$($task.TaskName)" $row 'Export then unregister the stale task, or reinstall the owning app.'
            }
        }
    }
    $rows.ToArray()
}

$sections.Persistence = Invoke-Safe 'Persistence' {
    $result = [ordered]@{}
    $ifeoRows = New-Object System.Collections.Generic.List[object]
    foreach ($root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    )) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in Get-ChildItem -Path $root -ErrorAction SilentlyContinue) {
            $p = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($p.Debugger) {
                $row = [pscustomobject]@{ Root = $root; Image = $key.PSChildName; Debugger = $p.Debugger }
                $ifeoRows.Add($row) | Out-Null
                Add-Finding 'High' 'Persistence' "IFEO debugger is configured for $($key.PSChildName)." $row 'Verify this is intentional debugging; otherwise remove the Debugger value.'
            }
        }
    }
    $result.IFEO_Debuggers = $ifeoRows.ToArray()

    $appInitRows = New-Object System.Collections.Generic.List[object]
    foreach ($path in @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    )) {
        if (-not (Test-Path $path)) { continue }
        $p = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        $row = [pscustomobject]@{ Path = $path; LoadAppInit_DLLs = $p.LoadAppInit_DLLs; AppInit_DLLs = $p.AppInit_DLLs }
        $appInitRows.Add($row) | Out-Null
        if ($p.LoadAppInit_DLLs -eq 1 -or -not [string]::IsNullOrWhiteSpace($p.AppInit_DLLs)) {
            Add-Finding 'High' 'Persistence' 'AppInit DLL loading is configured.' $row 'Verify all DLLs are trusted; usually this should be disabled.'
        }
    }
    $result.AppInit = $appInitRows.ToArray()

    $appCertRows = New-Object System.Collections.Generic.List[object]
    $appCertPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    if (Test-Path $appCertPath) {
        $p = Get-ItemProperty -Path $appCertPath
        foreach ($prop in $p.PSObject.Properties) {
            if ($prop.Name -like 'PS*') { continue }
            $row = [pscustomobject]@{ Name = $prop.Name; Value = $prop.Value }
            $appCertRows.Add($row) | Out-Null
            Add-Finding 'High' 'Persistence' "AppCertDlls value exists: $($prop.Name)." $row 'Verify the DLL is trusted; AppCertDlls is a high-impact injection point.'
        }
    }
    $result.AppCertDlls = $appCertRows.ToArray()

    $wmi = [ordered]@{ Filters = @(); CommandConsumers = @(); ScriptConsumers = @(); Bindings = @() }
    try {
        $wmi.Filters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop | Select-Object Name, Query, EventNamespace)
        $wmi.CommandConsumers = @(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction Stop | Select-Object Name, CommandLineTemplate, ExecutablePath)
        $wmi.ScriptConsumers = @(Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction Stop | Select-Object Name, ScriptingEngine, ScriptFilename)
        $wmi.Bindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | Select-Object Filter, Consumer)
        foreach ($consumer in $wmi.CommandConsumers) {
            Add-Finding 'High' 'Persistence' "WMI command consumer exists: $($consumer.Name)." $consumer 'Verify this WMI subscription is expected; command consumers are commonly abused.'
        }
        foreach ($consumer in $wmi.ScriptConsumers) {
            Add-Finding 'High' 'Persistence' "WMI script consumer exists: $($consumer.Name)." $consumer 'Verify this WMI subscription is expected.'
        }
    } catch {
        Add-ErrorRecord 'WMI_Subscription' $_.Exception.Message
    }
    $result.WMI = $wmi
    $result
}

$sections.BrowserNativeMessaging = Invoke-Safe 'BrowserNativeMessaging' {
    $roots = @(
        'HKCU:\Software\Google\Chrome\NativeMessagingHosts',
        'HKLM:\Software\Google\Chrome\NativeMessagingHosts',
        'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts',
        'HKLM:\Software\Microsoft\Edge\NativeMessagingHosts',
        'HKCU:\Software\Chromium\NativeMessagingHosts',
        'HKLM:\Software\Chromium\NativeMessagingHosts',
        'HKCU:\Software\Mozilla\NativeMessagingHosts',
        'HKLM:\Software\Mozilla\NativeMessagingHosts'
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($root in $roots) {
        foreach ($nativeHost in Get-RegistrySubkeyDefaults $root) {
            $manifest = Normalize-LocalPath $nativeHost.DefaultValue
            $exists = if (Test-LocalFilesystemPath $manifest) { Test-Path -LiteralPath $manifest } else { $null }
            $row = [pscustomobject]@{
                RegistryRoot = $root
                HostName = $nativeHost.Name
                ManifestPath = $manifest
                ManifestExists = $exists
            }
            $rows.Add($row) | Out-Null
            if ((Test-LocalFilesystemPath $manifest) -and -not $exists) {
                Add-Finding 'Medium' 'BrowserNativeMessaging' "Native Messaging host manifest is missing: $($nativeHost.Name)" $row 'Remove the stale host key or reinstall the owning browser extension/app.'
            }
        }
    }
    $rows.ToArray()
}

$sections.ExplorerExtensions = Invoke-Safe 'ExplorerExtensions' {
    $handlerRoots = @(
        'Registry::HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers',
        'Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers',
        'Registry::HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers',
        'Registry::HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers',
        'Registry::HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers',
        'Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers',
        'Registry::HKEY_CLASSES_ROOT\*\shellex\PropertySheetHandlers',
        'Registry::HKEY_CLASSES_ROOT\Directory\shellex\CopyHookHandlers',
        'Registry::HKEY_CLASSES_ROOT\Directory\shellex\DragDropHandlers',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($root in $handlerRoots) {
        foreach ($handler in Get-RegistrySubkeyDefaults $root) {
            $clsid = [string]$handler.DefaultValue
            $server = Normalize-LocalPath (Get-ShellClsidServer $clsid)
            $exists = if (Test-LocalFilesystemPath $server) { Test-Path -LiteralPath $server } else { $null }
            $company = Get-FileCompany $server
            $row = [pscustomobject]@{
                Root = $root
                Name = $handler.Name
                Clsid = $clsid
                Server = $server
                ServerExists = $exists
                Company = $company
            }
            $rows.Add($row) | Out-Null
            if ((Test-LocalFilesystemPath $server) -and -not $exists) {
                Add-Finding 'Medium' 'ExplorerExtensions' "Explorer shell extension server is missing: $($handler.Name)" $row 'Disable or remove the stale shell extension after exporting the key.'
            }
        }
    }

    $approved = Get-RegistryValueRows 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'
    $blocked = Get-RegistryValueRows 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked'
    [ordered]@{
        Handlers = $rows.ToArray()
        Approved = $approved
        Blocked = $blocked
    }
}

$sections.WinlogonAndSecurity = Invoke-Safe 'WinlogonAndSecurity' {
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    $result = [ordered]@{
        UAC = $uac | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop
        Winlogon = $winlogon | Select-Object Shell, Userinit, AutoAdminLogon, DefaultUserName, DefaultDomainName
        DefaultPasswordPresent = [bool]($winlogon.PSObject.Properties.Name -contains 'DefaultPassword')
    }
    if ($uac.EnableLUA -ne 1) { Add-Finding 'High' 'SecurityPolicy' 'UAC EnableLUA is not enabled.' $result.UAC 'Restore UAC unless intentionally disabled for a controlled reason.' }
    if ($uac.ConsentPromptBehaviorAdmin -eq 0) { Add-Finding 'Medium' 'SecurityPolicy' 'Admin elevation prompt is suppressed.' $result.UAC 'Use a safer prompt behavior such as 5.' }
    if ($uac.PromptOnSecureDesktop -eq 0) { Add-Finding 'Medium' 'SecurityPolicy' 'UAC secure desktop is disabled.' $result.UAC 'Enable secure desktop unless it breaks a known workflow.' }
    if ($winlogon.AutoAdminLogon -eq '1') { Add-Finding 'Medium' 'SecurityPolicy' 'AutoAdminLogon is enabled.' $result.Winlogon 'Disable auto logon unless required.' }
    if ($result.DefaultPasswordPresent) { Add-Finding 'High' 'SecurityPolicy' 'Winlogon DefaultPassword value exists.' $result.Winlogon 'Remove stored auto-logon password and rotate the account password if exposed.' }
    if ($winlogon.Shell -ne 'explorer.exe') { Add-Finding 'High' 'Winlogon' 'Winlogon Shell is not explorer.exe.' $result.Winlogon 'Verify shell replacement is intentional.' }
    if ($winlogon.Userinit -notmatch 'userinit\.exe,?$') { Add-Finding 'High' 'Winlogon' 'Winlogon Userinit is unusual.' $result.Winlogon 'Verify no extra executables are chained from Userinit.' }
    $result
}

$sections.FileAssociations = Invoke-Safe 'FileAssociations' {
    $result = [ordered]@{
        DotExe = Get-DefaultValue 'Registry::HKEY_CLASSES_ROOT\.exe'
        ExeOpenCommand = Get-DefaultValue 'Registry::HKEY_CLASSES_ROOT\exefile\shell\open\command'
        DotLnk = Get-DefaultValue 'Registry::HKEY_CLASSES_ROOT\.lnk'
        DirectoryShell = Get-DefaultValue 'Registry::HKEY_CLASSES_ROOT\Directory\shell'
        DriveShell = Get-DefaultValue 'Registry::HKEY_CLASSES_ROOT\Drive\shell'
        FolderShell = Get-DefaultValue 'Registry::HKEY_CLASSES_ROOT\Folder\shell'
    }
    if ($result.DotExe -ne 'exefile') { Add-Finding 'High' 'FileAssociations' '.exe association is not exefile.' $result 'Repair .exe association before running downloaded executables.' }
    if ($result.ExeOpenCommand -ne '"%1" %*') { Add-Finding 'High' 'FileAssociations' 'exefile open command is unusual.' $result 'Repair .exe open command.' }
    if ($result.DotLnk -ne 'lnkfile') { Add-Finding 'Medium' 'FileAssociations' '.lnk association is unusual.' $result 'Repair shortcut association if shortcuts fail.' }
    $result
}

$sections.ExplorerDailyOps = Invoke-Safe 'ExplorerDailyOps' {
    $extensions = @('.txt','.pdf','.html','.htm','.jpg','.jpeg','.png','.mp4','.zip','.7z','.py','.js','.json')
    $assocRows = New-Object System.Collections.Generic.List[object]
    foreach ($ext in $extensions) {
        $hkcrDefault = Get-DefaultValue "Registry::HKEY_CLASSES_ROOT\$ext"
        $userChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice"
        $userChoice = if (Test-Path $userChoicePath) { Get-ItemProperty $userChoicePath -ErrorAction SilentlyContinue } else { $null }
        $assocRows.Add([pscustomobject]@{
            Extension = $ext
            HKCRDefault = $hkcrDefault
            UserChoiceProgId = $userChoice.ProgId
            UserChoiceHashPresent = [bool]$userChoice.Hash
        }) | Out-Null
    }

    $bhoRows = New-Object System.Collections.Generic.List[object]
    foreach ($root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
    )) {
        foreach ($bho in Get-RegistrySubkeyDefaults $root) {
            $server = Normalize-LocalPath (Get-ShellClsidServer $bho.Name)
            $bhoRows.Add([pscustomobject]@{
                Root = $root
                Clsid = $bho.Name
                Server = $server
                ServerExists = if (Test-LocalFilesystemPath $server) { Test-Path -LiteralPath $server } else { $null }
                Company = Get-FileCompany $server
            }) | Out-Null
        }
    }

    [ordered]@{
        CommonFileAssociations = $assocRows.ToArray()
        BrowserHelperObjects = $bhoRows.ToArray()
    }
}

$sections.InstalledApps = Invoke-Safe 'InstalledApps' {
    $uninstallRoots = @(
        @{ Scope = 'Machine64'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' },
        @{ Scope = 'Machine32'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' },
        @{ Scope = 'User'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
    )
    $apps = New-Object System.Collections.Generic.List[object]
    foreach ($root in $uninstallRoots) {
        if (-not (Test-Path -LiteralPath $root.Path)) { continue }
        foreach ($key in Get-ChildItem -LiteralPath $root.Path -ErrorAction SilentlyContinue) {
            $p = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if ([string]::IsNullOrWhiteSpace($p.DisplayName)) { continue }
            $name = ([string]$p.DisplayName).Trim([char]0).Trim()
            $version = ([string]$p.DisplayVersion).Trim([char]0).Trim()
            $installLocation = ([string]$p.InstallLocation).Trim([char]0).Trim().Trim('"')
            $displayIcon = ([string]$p.DisplayIcon).Trim([char]0).Trim()
            $uninstallString = ([string]$p.UninstallString).Trim([char]0).Trim()
            $quietUninstallString = ([string]$p.QuietUninstallString).Trim([char]0).Trim()
            $uninstallTarget = Get-UninstallTarget $uninstallString
            $iconTarget = Normalize-LocalPath (Get-CommandTarget $displayIcon)
            $apps.Add([pscustomobject]@{
                Scope = $root.Scope
                Key = $key.PSChildName
                RegistryPath = $key.PSPath
                DisplayName = $name
                NormalizedName = Normalize-AppDisplayName $name
                DisplayVersion = $version
                Publisher = ([string]$p.Publisher).Trim([char]0).Trim()
                InstallLocation = $installLocation
                InstallLocationExists = if (Test-LocalFilesystemPath $installLocation) { Test-Path -LiteralPath $installLocation } else { $null }
                DisplayIcon = $displayIcon
                DisplayIconTarget = $iconTarget
                DisplayIconTargetExists = if (Test-LocalFilesystemPath $iconTarget) { Test-Path -LiteralPath $iconTarget } else { $null }
                UninstallString = $uninstallString
                QuietUninstallString = $quietUninstallString
                UninstallTarget = $uninstallTarget
                UninstallTargetExists = if (Test-LocalFilesystemPath $uninstallTarget) { Test-Path -LiteralPath $uninstallTarget } elseif ($uninstallTarget -eq 'msiexec.exe') { $true } else { $null }
                InstallDate = ([string]$p.InstallDate).Trim([char]0).Trim()
                EstimatedSizeKB = $p.EstimatedSize
            }) | Out-Null
        }
    }

    $duplicateGroups = New-Object System.Collections.Generic.List[object]
    foreach ($group in ($apps | Where-Object { $_.NormalizedName } | Group-Object NormalizedName | Where-Object Count -gt 1)) {
        $items = @($group.Group)
        $sampleName = ($items | Select-Object -First 1).DisplayName
        $row = [pscustomobject]@{
            NormalizedName = $group.Name
            DisplayNames = @($items | Select-Object -ExpandProperty DisplayName -Unique)
            Count = $items.Count
            Scopes = @($items | Select-Object -ExpandProperty Scope -Unique)
            Versions = @($items | Select-Object -ExpandProperty DisplayVersion -Unique)
            InstallLocations = @($items | Select-Object -ExpandProperty InstallLocation -Unique)
            Items = $items
            LikelyNoise = Test-ProbablyNoiseDuplicateApp $sampleName
        }
        $duplicateGroups.Add($row) | Out-Null
        if (-not $row.LikelyNoise) {
            Add-Finding 'Medium' 'InstalledApps' "Duplicate installed-app records found: $sampleName" $row 'Correlate files, shortcuts, package-manager output, and event logs before deleting stale uninstall keys.'
        }
    }

    $sameLocationGroups = New-Object System.Collections.Generic.List[object]
    foreach ($group in ($apps | Where-Object { -not [string]::IsNullOrWhiteSpace($_.InstallLocation) } | Group-Object { $_.InstallLocation.ToLowerInvariant().TrimEnd('\') } | Where-Object Count -gt 1)) {
        $items = @($group.Group)
        $sampleName = (($items | Select-Object -ExpandProperty DisplayName -Unique) -join ', ')
        $row = [pscustomobject]@{
            InstallLocation = $group.Name
            Count = $items.Count
            DisplayNames = @($items | Select-Object -ExpandProperty DisplayName -Unique)
            Versions = @($items | Select-Object -ExpandProperty DisplayVersion -Unique)
            Scopes = @($items | Select-Object -ExpandProperty Scope -Unique)
            Items = $items
            LikelyNoise = ($items | Where-Object { Test-ProbablyNoiseDuplicateApp $_.DisplayName } | Measure-Object).Count -gt 0
        }
        $sameLocationGroups.Add($row) | Out-Null
        if (-not $row.LikelyNoise) {
            Add-Finding 'Medium' 'InstalledApps' "Multiple installed-app records share one install location: $sampleName" $row 'Usually remove only the stale metadata entry after exporting the key.'
        }
    }

    $brokenUninstallers = @($apps | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.UninstallTarget) -and
        (Test-LocalFilesystemPath $_.UninstallTarget) -and
        $_.UninstallTargetExists -eq $false
    })
    foreach ($app in $brokenUninstallers) {
        Add-Finding 'Medium' 'InstalledApps' "Uninstall entry points to a missing target: $($app.DisplayName)" $app 'If a valid surviving install exists, export and remove the stale uninstall key.'
    }

    $brokenIcons = @($apps | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.DisplayIconTarget) -and
        (Test-LocalFilesystemPath $_.DisplayIconTarget) -and
        $_.DisplayIconTargetExists -eq $false
    })

    $shortcutDirs = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    )
    $shortcuts = New-Object System.Collections.Generic.List[object]
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { Add-ErrorRecord 'InstalledAppsShortcuts' $_.Exception.Message }
    if ($shell) {
        foreach ($dir in $shortcutDirs) {
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            foreach ($lnkFile in Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.lnk' -ErrorAction SilentlyContinue) {
                try {
                    $lnk = $shell.CreateShortcut($lnkFile.FullName)
                    $target = Normalize-LocalPath $lnk.TargetPath
                    $exists = if (Test-LocalFilesystemPath $target) { Test-Path -LiteralPath $target } else { $null }
                    $isIconTarget = $target -match '\.(ico|png|jpg|jpeg|bmp)$'
                    $isKnownPackagedShortcut = (
                        $lnkFile.Name -in @('WSL.lnk','WSL Settings.lnk') -and
                        $target -match '\\Installer\\\{0C25A4AA-B7AC-4436-8BCC-017CEDB0E43A\}\\wsl\.ico$' -and
                        (Test-Path -LiteralPath "$env:SystemRoot\System32\wsl.exe")
                    )
                    $row = [pscustomobject]@{
                        Shortcut = $lnkFile.FullName
                        Target = $target
                        Arguments = $lnk.Arguments
                        WorkingDirectory = $lnk.WorkingDirectory
                        IconLocation = $lnk.IconLocation
                        TargetExists = $exists
                        TargetLooksLikeIcon = $isIconTarget
                    }
                    $shortcuts.Add($row) | Out-Null
                    if ((Test-LocalFilesystemPath $target) -and (-not $exists -or $isIconTarget) -and -not $isKnownPackagedShortcut) {
                        Add-Finding 'Low' 'InstalledApps' "Start Menu shortcut target is broken or not executable: $($lnkFile.Name)" $row 'Fix the shortcut to the real executable or remove the stale shortcut.'
                    }
                } catch {
                    Add-ErrorRecord 'InstalledAppsShortcuts' "$($lnkFile.FullName) :: $($_.Exception.Message)"
                }
            }
        }
    }

    $packageManagers = [ordered]@{
        Winget = (Get-Command winget -ErrorAction SilentlyContinue | Select-Object -First 1 Source)
        Scoop = (Get-Command scoop -ErrorAction SilentlyContinue | Select-Object -First 1 Source)
        Chocolatey = (Get-Command choco -ErrorAction SilentlyContinue | Select-Object -First 1 Source)
    }

    [ordered]@{
        AppCount = $apps.Count
        Apps = $apps.ToArray()
        DuplicateNameGroups = $duplicateGroups.ToArray()
        SameInstallLocationGroups = $sameLocationGroups.ToArray()
        BrokenUninstallers = $brokenUninstallers
        BrokenDisplayIcons = $brokenIcons
        StartMenuShortcuts = $shortcuts.ToArray()
        PackageManagers = $packageManagers
    }
}

$sections.PathEnvironment = Invoke-Safe 'PathEnvironment' {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($scope in @('User','Machine')) {
        $value = [Environment]::GetEnvironmentVariable('Path', $scope)
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        $entries = $value -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $groups = $entries | ForEach-Object { (Expand-RegistryString $_).Trim().TrimEnd('\').ToLowerInvariant() } | Group-Object | Where-Object Count -gt 1
        foreach ($group in $groups) {
            Add-Finding 'Low' 'Environment' "Duplicate PATH entry in $scope scope: $($group.Name)" $group 'Remove duplicates when convenient.'
        }
        foreach ($entry in $entries) {
            $expanded = Expand-RegistryString $entry
            $exists = Test-Path -LiteralPath $expanded
            $row = [pscustomobject]@{ Scope = $scope; Entry = $entry; Expanded = $expanded; Exists = $exists }
            if (-not $exists -and (Test-LocalFilesystemPath $expanded)) {
                $rows.Add($row) | Out-Null
                Add-Finding 'Low' 'Environment' "PATH entry does not exist in $scope scope." $row 'Remove stale PATH entries if the tool is no longer installed.'
            }
        }
    }
    $rows.ToArray()
}

$sections.DeveloperToolchain = Invoke-Safe 'DeveloperToolchain' {
    $commands = @('python','python3','py','node','npm','npx','git','docker','docker-compose','adb','dotnet','java','javac','go','rustc','cargo','uv')
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($cmd in $commands) {
        $where = @(Get-WhereResults $cmd)
        $commandInfo = Get-Command $cmd -ErrorAction SilentlyContinue | Select-Object -First 1
        $version = $null
        if ($ProbeToolVersions) {
            try {
                if ($cmd -in @('python','python3','node','npm','git','docker','dotnet','java','go','rustc','cargo','uv')) {
                    $version = (& $cmd --version 2>$null | Select-Object -First 1)
                } elseif ($cmd -eq 'py') {
                    $version = (& py --version 2>$null | Select-Object -First 1)
                } elseif ($cmd -eq 'adb') {
                    $version = (& adb version 2>$null | Select-Object -First 1)
                }
            } catch {
                $version = $null
            }
        }
        $row = [pscustomobject]@{
            Command = $cmd
            ResolvedPath = $commandInfo.Source
            AllWhereMatches = $where
            MatchCount = $where.Count
            Version = $version
            VersionProbed = [bool]$ProbeToolVersions
        }
        $rows.Add($row) | Out-Null
        if ($where.Count -gt 1) {
            Add-Finding 'Low' 'DeveloperToolchain' "Multiple PATH matches for command: $cmd" $row 'Confirm the first match is the intended version.'
        }
    }

    $userPath = ([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') | Where-Object { $_ }
    $machinePath = ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') | Where-Object { $_ }
    $userNormalized = $userPath | ForEach-Object { (Expand-RegistryString $_).Trim().TrimEnd('\').ToLowerInvariant() }
    $machineNormalized = $machinePath | ForEach-Object { (Expand-RegistryString $_).Trim().TrimEnd('\').ToLowerInvariant() }
    $crossScopeDuplicates = @($userNormalized | Where-Object { $machineNormalized -contains $_ } | Select-Object -Unique)
    foreach ($dup in $crossScopeDuplicates) {
        Add-Finding 'Low' 'Environment' "PATH entry appears in both User and Machine scope: $dup" $dup 'Remove one copy if ordering does not matter.'
    }

    [ordered]@{
        Commands = $rows.ToArray()
        CrossScopePathDuplicates = $crossScopeDuplicates
    }
}

$sections.Network = Invoke-Safe 'Network' {
    $internetSettings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $winHttpProxy = (& netsh winhttp show proxy) -join "`n"
    $udpEndpoints = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
    $udpByProcess = @($udpEndpoints | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 15 @{n='PID';e={$_.Name}}, Count, @{n='ProcessName';e={(Get-Process -Id ([int]$_.Name) -ErrorAction SilentlyContinue).ProcessName}})
    $result = [ordered]@{
        UserProxy = $internetSettings | Select-Object ProxyEnable, ProxyServer, AutoConfigURL
        WinHttpProxy = $winHttpProxy
        NetAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, LinkSpeed)
        DnsServers = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, AddressFamily, ServerAddresses)
        UdpEndpointCount = $udpEndpoints.Count
        UdpByProcess = $udpByProcess
    }
    if ($internetSettings.ProxyEnable -eq 1) {
        Add-Finding 'Medium' 'Network' 'User proxy is enabled.' $result.UserProxy 'Verify proxy is expected; compare with WinHTTP and VPN tools.'
    }
    if ($udpEndpoints.Count -gt 8000) {
        Add-Finding 'Medium' 'Network' 'UDP endpoint count is unusually high.' $udpByProcess 'Identify the owning process before changing dynamic port ranges.'
    }
    $result
}

$sections.NetworkDeep = Invoke-Safe 'NetworkDeep' {
    $winsockText = ''
    try { $winsockText = (& netsh winsock show catalog) -join "`n" } catch { Add-ErrorRecord 'WinsockCatalog' $_.Exception.Message }

    $namespaceRows = New-Object System.Collections.Generic.List[object]
    foreach ($root in @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries',
        'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries'
    )) {
        if (-not (Test-Path $root)) { continue }
        foreach ($entry in Get-ChildItem -Path $root -ErrorAction SilentlyContinue) {
            $p = Get-ItemProperty -Path $entry.PSPath -ErrorAction SilentlyContinue
            $namespaceRows.Add([pscustomobject]@{
                Root = $root
                Entry = $entry.PSChildName
                DisplayString = $p.DisplayString
                LibraryPath = $p.LibraryPath
                ProviderId = $p.ProviderId
            }) | Out-Null
        }
    }

    $firewallProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, AllowLocalIPsecRules)
    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled -ne $true) {
            Add-Finding 'Medium' 'Firewall' "Windows Firewall profile is disabled: $($profile.Name)" $profile 'Verify another firewall is active before leaving this disabled.'
        }
    }

    $vpnAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'vpn|tun|tap|wintun|warp|clash|docker|tailscale|wireguard|zerotier|mihomo|hyper-v|virtual' -or
        $_.InterfaceDescription -match 'vpn|tun|tap|wintun|warp|clash|docker|tailscale|wireguard|zerotier|mihomo|hyper-v|virtual'
    } | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress)

    $networkServices = @(Get-CimInstance Win32_Service | Where-Object {
        $_.Name -match 'clash|mihomo|warp|cloudflare|docker|vpn|tun|tap|tailscale|wireguard|zerotier|easytier|verge' -or
        $_.DisplayName -match 'clash|mihomo|warp|cloudflare|docker|vpn|tun|tap|tailscale|wireguard|zerotier|easytier|verge'
    } | Select-Object Name, DisplayName, State, StartMode, PathName)

    $networkProcesses = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -match 'clash|mihomo|warp|cloudflare|docker|vpn|tun|tap|tailscale|wireguard|zerotier|easytier|verge'
    } | Select-Object Id, ProcessName, Path)

    [ordered]@{
        WinsockCatalogText = $winsockText
        NameSpaceAndProtocolCatalog = $namespaceRows.ToArray()
        FirewallProfiles = $firewallProfiles
        VpnTunTapVirtualAdapters = $vpnAdapters
        NetworkRelatedServices = $networkServices
        NetworkRelatedProcesses = $networkProcesses
    }
}

$sections.Defender = Invoke-Safe 'Defender' {
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $policy = if (Test-Path $policyPath) { Get-ItemProperty $policyPath } else { $null }
    $status = $null
    try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { Add-ErrorRecord 'DefenderStatus' $_.Exception.Message }
    $result = [ordered]@{
        Policy = $policy | Select-Object DisableAntiSpyware, DisableRealtimeMonitoring
        Status = $status | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntispywareEnabled, NISEnabled
    }
    if ($policy.DisableAntiSpyware -eq 1 -or $policy.DisableRealtimeMonitoring -eq 1) {
        Add-Finding 'High' 'SecurityPolicy' 'Defender appears disabled by policy.' $result.Policy 'Confirm another trusted security product is present, otherwise remove the policy.'
    }
    if ($status -and $status.RealTimeProtectionEnabled -eq $false) {
        Add-Finding 'High' 'SecurityPolicy' 'Defender real-time protection is disabled.' $result.Status 'Re-enable protection unless a trusted EDR manages it.'
    }
    $result
}

$sections.SecurityDeep = Invoke-Safe 'SecurityDeep' {
    $smartScreenSystem = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue
    $smartScreenExplorerLM = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue
    $smartScreenExplorerCU = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue
    $terminalServer = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    $remoteRegistry = Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction SilentlyContinue
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $lanman = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue
    $mrxsmb10 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -ErrorAction SilentlyContinue
    $executionPolicy = @(Get-ExecutionPolicy -List | Select-Object Scope, ExecutionPolicy)
    $admins = @()
    try { $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object Name, ObjectClass, PrincipalSource) } catch { Add-ErrorRecord 'LocalAdministrators' $_.Exception.Message }

    $result = [ordered]@{
        SmartScreenPolicy = $smartScreenSystem | Select-Object EnableSmartScreen, ShellSmartScreenLevel
        SmartScreenExplorerLM = $smartScreenExplorerLM | Select-Object SmartScreenEnabled
        SmartScreenExplorerCU = $smartScreenExplorerCU | Select-Object SmartScreenEnabled
        PowerShellExecutionPolicy = $executionPolicy
        Rdp = $terminalServer | Select-Object fDenyTSConnections
        RemoteRegistry = $remoteRegistry | Select-Object Name, State, StartMode
        SMB = [ordered]@{
            LanmanServerSMB1 = $lanman.SMB1
            MrxSmb10Start = $mrxsmb10.Start
        }
        Lsa = $lsa | Select-Object LimitBlankPasswordUse, RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous, NoLmHash, LmCompatibilityLevel
        LocalAdministrators = $admins
    }

    if ($smartScreenSystem.EnableSmartScreen -eq 0 -or $smartScreenExplorerLM.SmartScreenEnabled -eq 'Off' -or $smartScreenExplorerCU.SmartScreenEnabled -eq 'Off') {
        Add-Finding 'Medium' 'SecurityPolicy' 'SmartScreen appears disabled.' $result 'Re-enable SmartScreen unless a managed security baseline intentionally disables it.'
    }
    foreach ($policy in $executionPolicy) {
        if ($policy.Scope -ne 'Process' -and $policy.ExecutionPolicy -in 'Bypass','Unrestricted') {
            Add-Finding 'Medium' 'SecurityPolicy' "PowerShell execution policy is permissive at $($policy.Scope)." $policy 'Verify this scope needs Bypass/Unrestricted.'
        }
    }
    if ($terminalServer.fDenyTSConnections -eq 0) {
        Add-Finding 'Medium' 'SecurityPolicy' 'Remote Desktop is enabled.' $result.Rdp 'Verify RDP exposure, firewall rules, and account password strength.'
    }
    if ($remoteRegistry -and $remoteRegistry.StartMode -ne 'Disabled') {
        Add-Finding 'Medium' 'SecurityPolicy' 'RemoteRegistry service is not disabled.' $result.RemoteRegistry 'Disable RemoteRegistry unless remote registry management is required.'
    }
    if ($lanman.SMB1 -eq 1 -or $mrxsmb10.Start -in 0,1,2) {
        Add-Finding 'High' 'SecurityPolicy' 'SMB1 appears enabled or loadable.' $result.SMB 'Disable SMB1 unless required for legacy devices.'
    }
    if ($lsa.EveryoneIncludesAnonymous -eq 1 -or $lsa.LimitBlankPasswordUse -eq 0) {
        Add-Finding 'Medium' 'SecurityPolicy' 'Anonymous access policy is permissive.' $result.Lsa 'Review local security policy before changing; avoid broad anonymous access.'
    }
    $result
}

$sections.WindowsUpdateAndStore = Invoke-Safe 'WindowsUpdateAndStore' {
    $wuPolicy = Get-RegistryValueRows 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auPolicy = Get-RegistryValueRows 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $servicingKeys = [ordered]@{
        RebootPending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        RebootInProgress = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress'
        SessionsPending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\SessionsPending'
        PackagesPending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'
    }
    $gamingPackages = @()
    $storePackages = @()
    $appxScope = if (Test-Admin) { 'AllUsers' } else { 'CurrentUser' }
    try {
        if ($appxScope -eq 'AllUsers') {
            $gamingPackages = @(Get-AppxPackage -Name 'Microsoft.GamingServices' -AllUsers -ErrorAction Stop | Select-Object Name, PackageFullName, Status, InstallLocation)
        } else {
            $gamingPackages = @(Get-AppxPackage -Name 'Microsoft.GamingServices' -ErrorAction Stop | Select-Object Name, PackageFullName, Status, InstallLocation)
        }
    } catch { Add-ErrorRecord 'GamingServicesPackage' $_.Exception.Message }
    try {
        if ($appxScope -eq 'AllUsers') {
            $storePackages = @(Get-AppxPackage -Name 'Microsoft.WindowsStore' -AllUsers -ErrorAction Stop | Select-Object Name, PackageFullName, Status, InstallLocation)
        } else {
            $storePackages = @(Get-AppxPackage -Name 'Microsoft.WindowsStore' -ErrorAction Stop | Select-Object Name, PackageFullName, Status, InstallLocation)
        }
    } catch { Add-ErrorRecord 'WindowsStorePackage' $_.Exception.Message }
    $gamingServices = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'GamingServices|Xbl|Xbox' -or $_.DisplayName -match 'Gaming|Xbox' } | Select-Object Name, DisplayName, State, StartMode, PathName)
    $cbsSrLines = @()
    $cbsPath = 'C:\Windows\Logs\CBS\CBS.log'
    try {
        if (Test-Path -LiteralPath $cbsPath) {
            $cbsSrLines = @(Select-String -LiteralPath $cbsPath -Pattern '\[SR\]|corrupt|repair' -CaseSensitive:$false -ErrorAction Stop | Select-Object -Last 120 LineNumber, Line)
        }
    } catch {
        Add-ErrorRecord 'CBSLog' $_.Exception.Message
    }

    if ($wuPolicy.Count -gt 0 -or $auPolicy.Count -gt 0) {
        Add-Finding 'Info' 'WindowsUpdate' 'Windows Update policy keys are configured.' @{ WindowsUpdate = $wuPolicy; AU = $auPolicy } 'Review policy values if updates behave unexpectedly.'
    }
    if ($servicingKeys.RebootPending -or $servicingKeys.RebootInProgress -or $servicingKeys.SessionsPending -or $servicingKeys.PackagesPending) {
        Add-Finding 'Medium' 'WindowsUpdate' 'CBS/Servicing has pending state.' $servicingKeys 'Reboot and rerun health checks before manual package repair.'
    }

    [ordered]@{
        WindowsUpdatePolicy = $wuPolicy
        AutoUpdatePolicy = $auPolicy
        CBSAndServicing = $servicingKeys
        AppxScope = $appxScope
        GamingServicesPackages = $gamingPackages
        WindowsStorePackages = $storePackages
        GamingAndXboxServices = $gamingServices
        RecentCBSRepairLines = $cbsSrLines
    }
}

$sections.Drivers = Invoke-Safe 'Drivers' {
    $rows = New-Object System.Collections.Generic.List[object]
    $thirdParty = New-Object System.Collections.Generic.List[object]
    foreach ($key in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue) {
        $p = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
        $type = if ($null -ne $p.Type) { [int]$p.Type } else { 0 }
        if (($type -band 1) -eq 0 -and ($type -band 2) -eq 0) { continue }
        $image = $p.ImagePath
        if ([string]::IsNullOrWhiteSpace($image)) { $image = "System32\Drivers\$($key.PSChildName).sys" }
        $target = Normalize-LocalPath (Get-CommandTarget $image)
        $isLocal = Test-LocalFilesystemPath $target
        $exists = if ($isLocal) { Test-Path -LiteralPath $target } else { $null }
        $company = Get-FileCompany $target
        $row = [pscustomobject]@{ Name = $key.PSChildName; Type = $type; Start = $p.Start; ImagePath = $image; Target = $target; TargetExists = $exists; Company = $company }
        if ($exists -and $company -and $company -notmatch 'Microsoft') {
            $thirdParty.Add($row) | Out-Null
        }
        if ($isLocal -and -not $exists -and $p.Start -in 0,1,2) {
            $rows.Add($row) | Out-Null
            Add-Finding 'High' 'Drivers' "Boot/system/auto driver target is missing: $($key.PSChildName)" $row 'Verify path normalization first; repair or disable only when the driver is truly stale.'
        }
    }
    [ordered]@{
        MissingOrUnusualDrivers = $rows.ToArray()
        ThirdPartyKernelDrivers = $thirdParty.ToArray()
    }
}

$sections.DeviceFilters = Invoke-Safe 'DeviceFilters' {
    $classMap = [ordered]@{
        '{4d36e967-e325-11ce-bfc1-08002be10318}' = 'DiskDrive'
        '{4d36e965-e325-11ce-bfc1-08002be10318}' = 'CDROM'
        '{4d36e96a-e325-11ce-bfc1-08002be10318}' = 'HDC'
        '{4d36e96b-e325-11ce-bfc1-08002be10318}' = 'Keyboard'
        '{4d36e96f-e325-11ce-bfc1-08002be10318}' = 'Mouse'
        '{36fc9e60-c465-11cf-8056-444553540000}' = 'USB'
        '{4d36e968-e325-11ce-bfc1-08002be10318}' = 'Display'
        '{4d36e972-e325-11ce-bfc1-08002be10318}' = 'Net'
        '{745a17a0-74d3-11d0-b6fe-00a0c90f57da}' = 'HIDClass'
        '{4d36e96c-e325-11ce-bfc1-08002be10318}' = 'Media'
        '{4d36e97d-e325-11ce-bfc1-08002be10318}' = 'System'
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($guid in $classMap.Keys) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$guid"
        if (-not (Test-Path $path)) { continue }
        $p = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        foreach ($kind in @('UpperFilters','LowerFilters')) {
            $filters = @($p.$kind) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($filter in $filters) {
                $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$filter"
                $image = Get-ServiceRegistryImage $filter
                $target = Normalize-LocalPath (Get-CommandTarget $image)
                $exists = if (Test-LocalFilesystemPath $target) { Test-Path -LiteralPath $target } else { $null }
                $row = [pscustomobject]@{
                    DeviceClass = $classMap[$guid]
                    ClassGuid = $guid
                    FilterType = $kind
                    FilterService = $filter
                    ServiceExists = Test-Path $svcPath
                    ImagePath = $image
                    Target = $target
                    TargetExists = $exists
                    Company = Get-FileCompany $target
                }
                $rows.Add($row) | Out-Null
                if (-not $row.ServiceExists) {
                    Add-Finding 'High' 'DeviceFilters' "Device filter service is missing: $filter" $row 'Do not delete filter values blindly; export the class key and verify device impact first.'
                } elseif ((Test-LocalFilesystemPath $target) -and -not $exists) {
                    Add-Finding 'High' 'DeviceFilters' "Device filter driver target is missing: $filter" $row 'Repair or remove stale filter only after confirming the owning software is gone.'
                }
            }
        }
    }
    $rows.ToArray()
}

$sections.HardwareAndPower = Invoke-Safe 'HardwareAndPower' {
    $graphicsDrivers = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -ErrorAction SilentlyContinue
    [ordered]@{
        GPUs = @(Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, DriverDate, Status)
        PhysicalDisks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName, HealthStatus, OperationalStatus, Size, MediaType)
        Volumes = @(Get-Volume -ErrorAction SilentlyContinue | Select-Object DriveLetter, FileSystemLabel, HealthStatus, OperationalStatus, SizeRemaining, Size)
        ActivePowerScheme = ((& powercfg /getactivescheme) -join ' ')
        SleepStates = ((& powercfg /a) -join "`n")
        GraphicsDriversRegistry = $graphicsDrivers | Select-Object HwSchMode, TdrDelay, TdrDdiDelay, TdrLevel
        Minidumps = @(Get-ChildItem 'C:\Windows\Minidump' -Filter '*.dmp' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10 FullName, Length, LastWriteTime)
    }
}

$sections.GpuStability = Invoke-Safe 'GpuStability' {
    $graphicsDrivers = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -ErrorAction SilentlyContinue
    $dwm = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\Dwm' -ErrorAction SilentlyContinue
    $videoControllers = @(Get-CimInstance Win32_VideoController | Select-Object Name, PNPDeviceID, DriverVersion, DriverDate, Status)
    $virtualDisplays = @($videoControllers | Where-Object { $_.Name -match 'virtual|indirect|dummy|parsec|gameviewer|spacedesk|idd|displaylink' -or $_.PNPDeviceID -match 'ROOT\\DISPLAY|VIRTUAL|DISPLAYLINK|SPACEDESK|GAMEVIEWER' })
    $nvidiaServices = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match '^Nv|NVIDIA|nvcontainer|nvtelemetry' -or $_.DisplayName -match 'NVIDIA|NvContainer|Telemetry' } | Select-Object Name, DisplayName, State, StartMode, PathName)
    $nvidiaProcesses = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'nvidia|nvcontainer|nvsphelper|nvdisplay|nvtelemetry' } | Select-Object Id, ProcessName, Path)
    $overlayProcesses = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -match 'discord|steamwebhelper|gamebar|obs|overwolf|rtss|msiafterburner|geforce|nvidia|teamspeak|gameviewer|parsec|sunshine|moonlight'
    } | Select-Object Id, ProcessName, Path)

    $tdr = [ordered]@{
        HwSchMode = $graphicsDrivers.HwSchMode
        TdrDelay = $graphicsDrivers.TdrDelay
        TdrDdiDelay = $graphicsDrivers.TdrDdiDelay
        TdrLevel = $graphicsDrivers.TdrLevel
        TdrLimitCount = $graphicsDrivers.TdrLimitCount
        TdrLimitTime = $graphicsDrivers.TdrLimitTime
    }
    $mpo = [ordered]@{
        OverlayTestMode = $dwm.OverlayTestMode
        ForceDisableModeChangeAnimation = $dwm.ForceDisableModeChangeAnimation
    }

    if ($virtualDisplays.Count -gt 0) {
        Add-Finding 'Info' 'GpuStability' 'Virtual display adapters are present.' $virtualDisplays 'Consider temporarily disabling virtual display drivers when debugging TDR/black-screen issues.'
    }
    if ($graphicsDrivers.TdrDelay -or $graphicsDrivers.TdrDdiDelay -or $graphicsDrivers.TdrLevel -or $graphicsDrivers.TdrLimitCount -or $graphicsDrivers.TdrLimitTime) {
        Add-Finding 'Medium' 'GpuStability' 'Custom TDR registry values are configured.' $tdr 'Verify these were intentionally set; custom TDR values can mask or change GPU failure behavior.'
    }

    [ordered]@{
        VideoControllers = $videoControllers
        VirtualDisplayAdapters = $virtualDisplays
        TdrAndHagsRegistry = $tdr
        DwmMpoRegistry = $mpo
        NvidiaServices = $nvidiaServices
        NvidiaProcesses = $nvidiaProcesses
        CommonOverlayProcesses = $overlayProcesses
    }
}

$sections.EventLogs = Invoke-Safe 'EventLogs' {
    $since = (Get-Date).AddDays(-[Math]::Abs($Days))
    $systemEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $since; Level = 1,2,3 } -MaxEvents 5000 -ErrorAction SilentlyContinue)
    $appEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $since; Level = 1,2,3 } -MaxEvents 2000 -ErrorAction SilentlyContinue)
    $systemSummary = @($systemEvents | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 30 Count, Name)
    $appSummary = @($appEvents | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 20 Count, Name)
    $notableSystem = @($systemEvents | Where-Object {
        $_.Id -in 41,6008,4101,14,17,18,19,20,45,46,47,7000,7009,7031,7034,1001 -or
        $_.ProviderName -match 'nvlddmkm|amdkmdag|WHEA|BugCheck|Kernel-Power'
    } | Sort-Object TimeCreated | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message)
    $notableApp = @($appEvents | Where-Object { $_.Id -in 1000,1001,1002,1026 } | Sort-Object TimeCreated | Select-Object -Last 100 TimeCreated, Id, ProviderName, LevelDisplayName, Message)
    $kp41 = @($notableSystem | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41 })
    $gpu = @($notableSystem | Where-Object { $_.ProviderName -match 'nvlddmkm|amdkmdag' -or $_.Id -eq 4101 })
    $whea = @($notableSystem | Where-Object { $_.ProviderName -match 'WHEA' })
    $bugChecks = @($systemEvents | Where-Object { $_.ProviderName -match 'BugCheck|WER-SystemErrorReporting' -or $_.Id -eq 1001 } | ForEach-Object {
        $code = $null
        $dump = $null
        $codeMatch = [regex]::Match($_.Message, '0x[0-9a-fA-F]{8,16}')
        if ($codeMatch.Success) { $code = $codeMatch.Value.ToLowerInvariant() }
        $dumpMatch = [regex]::Match($_.Message, '[A-Za-z]:\\Windows\\Minidump\\[^ \r\n]+\.dmp', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($dumpMatch.Success) { $dump = $dumpMatch.Value }
        [pscustomobject]@{
            TimeCreated = $_.TimeCreated
            Id = $_.Id
            ProviderName = $_.ProviderName
            BugCheckCode = $code
            DumpPath = $dump
            Message = $_.Message
        }
    })
    if ($kp41.Count -gt 0) { Add-Finding 'High' 'Stability' "Unexpected shutdown/reboot events found: $($kp41.Count)." ($kp41 | Select-Object -Last 10) 'Correlate with BugCheck, GPU, WHEA, and power events before changing registry settings.' }
    if ($gpu.Count -gt 0) { Add-Finding 'High' 'Stability' "Display/GPU driver errors found: $($gpu.Count)." ($gpu | Select-Object -Last 10) 'Check GPU driver version, overlays, HAGS/TDR, virtual display drivers, power, and minidumps.' }
    if ($whea.Count -gt 0) { Add-Finding 'High' 'Stability' "WHEA hardware errors found: $($whea.Count)." ($whea | Select-Object -Last 10) 'Treat as hardware/PCIe/CPU/RAM/storage stability evidence.' }
    foreach ($bugCheck in $bugChecks) {
        if ($bugCheck.BugCheckCode -eq '0x00000116') {
            Add-Finding 'High' 'Stability' 'BugCheck 0x116 VIDEO_TDR_FAILURE found.' $bugCheck 'Prioritize GPU driver/display path, overlays, virtual displays, power, and minidump analysis.'
        }
    }
    [ordered]@{
        Since = $since
        SystemSummary = $systemSummary
        ApplicationSummary = $appSummary
        NotableSystem = $notableSystem
        NotableApplication = $notableApp
        BugChecks = $bugChecks
    }
}

$report = [ordered]@{
    GeneratedAt = $generatedAt.ToString('o')
    Days = $Days
    OutputPath = $OutputPath
    Findings = $script:Findings.ToArray()
    Errors = $script:Errors.ToArray()
    Sections = $sections
}

$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output $OutputPath
