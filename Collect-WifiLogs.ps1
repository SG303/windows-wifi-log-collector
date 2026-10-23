#Requires -Version 5.1
<#
.SYNOPSIS
    Collects logs, traces and configuration data to troubleshoot Wi-Fi / 802.1X problems on a Windows host.

.DESCRIPTION
    Based on Microsoft's "Data collection for troubleshooting 802.1X authentication issues"
    (https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/data-collection-for-troubleshooting-802-1x-authentication-issues)
    and extended with Wi-Fi specific sources (WLAN report, driver/adapter settings, power settings,
    signal/roaming sampling, gateway ping, event timeline, automatic findings).

    Default flow (run in an elevated PowerShell):
      1. Start capture: RAS tracing, 'netsh trace' (WLAN or LAN scenario incl. packet capture),
         CAPI2 log, Problem Steps Recorder, signal/BSSID sampler, gateway ping, neighbour AP scan.
      2. Reproduce the problem (press ENTER when done, or use -DurationSeconds for unattended runs).
      3. Stop capture, collect configuration, certificate stores, event logs, GPO result, ...
      4. Build Summary.txt with automatic findings and zip everything.

    Use -SnapshotOnly if the problem cannot be reproduced on demand and you only want the current
    state plus the historical event logs.

    PRIVACY: the result contains internal information (computer/user names, SSIDs, EAP/RADIUS
    settings, certificate details, Security event log, PSR screenshots, packet capture).
    Wi-Fi pre-shared keys are NOT exported. Handle the archive accordingly.

.PARAMETER OutputPath
    Base folder for results. A sub folder <COMPUTERNAME>_<timestamp> is created. Default: C:\MSLOG

.PARAMETER Scenario
    'Wireless' (default) traces the WLAN scenario, 'Wired' traces the LAN scenario (802.1X on Ethernet).

.PARAMETER DurationSeconds
    Capture for a fixed time instead of waiting for ENTER. Useful for remote/unattended runs.

.PARAMETER SnapshotOnly
    Skip all live captures (traces, PSR, samplers). Only collect current state and event logs.

.PARAMETER EventLogDays
    Only export events of the last N days (default 7). 0 exports the complete logs.

.PARAMETER MaxTraceSizeMB
    Maximum size of the netsh trace file (circular). Default 1024.

.PARAMETER MaxScreenshots
    Maximum number of PSR screenshots. Default 100.

.PARAMETER PingTarget
    Additional ping targets (IP or name) next to the default gateway during the capture.

.PARAMETER NoPacketCapture
    Run 'netsh trace' with capture=no (ETW only, no packets).

.PARAMETER IncludePsr
    Also run the Problem Steps Recorder (screenshots). Opt-in: psr.exe was removed in Windows 11 24H2.

.PARAMETER IncludeMsinfo
    Also run msinfo32 /report (slow, takes ~5-6 minutes on many systems). systeminfo, drivers and
    hotfixes are collected anyway.

.PARAMETER NoCertificates
    Skip the certutil certificate store dumps.

.PARAMETER NoSecurityLog
    Do not export the Security event log.

.PARAMETER NoZip
    Do not create a zip archive.

.PARAMETER NoLlmReport
    Do not create 08_LLM\llm_report.md (single text file for LLM analysis) and its redacted copy.

.PARAMETER NoTraceConvert
    Do not decode the ETW trace with tracerpt for the LLM report.

.PARAMETER LlmReportMaxKB
    Size budget of the LLM report in KB (default 300, roughly 85k tokens). Least important sections are shortened first.

.PARAMETER Force
    Stop an already running 'netsh trace' session if it blocks the new trace.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Collect-WifiLogs.ps1

.EXAMPLE
    .\Collect-WifiLogs.ps1 -DurationSeconds 600 -PingTarget 10.0.0.1,8.8.8.8

.EXAMPLE
    .\Collect-WifiLogs.ps1 -SnapshotOnly -EventLogDays 30
#>
[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\MSLOG',
    [ValidateSet('Wireless', 'Wired')]
    [string]$Scenario = 'Wireless',
    [ValidateRange(0, 86400)]
    [int]$DurationSeconds = 0,
    [switch]$SnapshotOnly,
    [ValidateRange(0, 3650)]
    [int]$EventLogDays = 7,
    [ValidateRange(64, 16384)]
    [int]$MaxTraceSizeMB = 1024,
    [ValidateRange(1, 999)]
    [int]$MaxScreenshots = 100,
    [string[]]$PingTarget = @(),
    [switch]$NoPacketCapture,
    [switch]$IncludePsr,
    [switch]$IncludeMsinfo,
    [switch]$NoCertificates,
    [switch]$NoSecurityLog,
    [switch]$NoZip,
    [switch]$NoLlmReport,
    [switch]$NoTraceConvert,
    [ValidateRange(50, 4000)]
    [int]$LlmReportMaxKB = 300,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$script:Version = '1.5.3'

# ---------------------------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------------------------
if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    Write-Error 'This script only runs on Windows.'
    exit 1
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Administrator rights required. Start PowerShell with "Run as administrator" and run the script again.'
    exit 1
}

$script:StartTime = Get-Date
$script:RunName = '{0}_{1:yyyyMMdd_HHmmss}' -f $env:COMPUTERNAME, $script:StartTime
$script:RunDir = Join-Path $OutputPath $script:RunName
$script:Dir = [ordered]@{
    Summary      = Join-Path $script:RunDir '00_Summary'
    Traces       = Join-Path $script:RunDir '01_Traces'
    Events       = Join-Path $script:RunDir '02_EventLogs'
    Wireless     = Join-Path $script:RunDir '03_Wireless'
    Network      = Join-Path $script:RunDir '04_Network'
    System       = Join-Path $script:RunDir '05_System'
    Certificates = Join-Path $script:RunDir '06_Certificates'
    Monitor      = Join-Path $script:RunDir '07_Monitor'
    Llm          = Join-Path $script:RunDir '08_LLM'
}
foreach ($d in $script:Dir.Values) { New-Item -ItemType Directory -Path $d -Force | Out-Null }

$script:LogFile = Join-Path $script:RunDir 'collector.log'
$script:Manifest = New-Object System.Collections.Generic.List[object]
$script:StepWarn = $null
$script:StepSkip = $null
$script:LocationBlocked = $false
$script:State = @{
    NetshTrace = $false
    EtwSession = $false
    RasTrace   = $false
    Psr        = $false
    Capi2Prev  = $null
    Jobs       = @()
}

# Only export events newer than this (null = everything)
$script:Since = $null
if ($EventLogDays -gt 0) { $script:Since = $script:StartTime.AddDays(-$EventLogDays) }

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------
function Write-CollectorLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0:yyyy-MM-dd HH:mm:ss.fff} [{1}] {2}' -f (Get-Date), $Level, $Message
    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
}

function Write-Info {
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host $Message -ForegroundColor $Color
    Write-CollectorLog $Message
}

function Add-ManifestEntry {
    param([string]$Step, [string]$Status, [double]$Seconds, [string]$Detail)
    # one line, bounded length: full details are in collector.log
    $line = ($Detail -split "\r?\n")[0]
    if ($line.Length -gt 220) { $line = $line.Substring(0, 220) + '...' }
    $script:Manifest.Add([pscustomobject]@{ Step = $Step; Status = $Status; Seconds = [math]::Round($Seconds, 1); Detail = $line })
    $color = switch ($Status) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'SKIP' { 'DarkGray' } default { 'Red' } }
    $suffix = ''
    if ($line) { $suffix = " ($line)" }
    Write-Host ('  [{0,-4}] {1}{2}' -f $Status, $Step, $suffix) -ForegroundColor $color
    Write-CollectorLog ('{0} | {1}{2}' -f $Status, $Step, $suffix) $Status
    if ($Detail -and $Detail -ne $line) { Write-CollectorLog $Detail 'DETAIL' }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    $script:StepWarn = $null
    $script:StepSkip = $null
    $status = 'OK'
    $detail = ''
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Write-Progress -Id 1 -Activity 'Wi-Fi log collection' -Status $Name
    try { & $Action | Out-Null } catch { $status = 'FAIL'; $detail = $_.Exception.Message }
    $sw.Stop()
    Write-Progress -Id 1 -Activity 'Wi-Fi log collection' -Completed
    if ($status -eq 'OK' -and $script:StepSkip) { $status = 'SKIP'; $detail = $script:StepSkip }
    elseif ($status -eq 'OK' -and $script:StepWarn) { $status = 'WARN'; $detail = $script:StepWarn }
    Add-ManifestEntry -Step $Name -Status $status -Seconds $sw.Elapsed.TotalSeconds -Detail $detail
}

function Skip-Step {
    param([string]$Name, [string]$Reason)
    Add-ManifestEntry -Step $Name -Status 'SKIP' -Seconds 0 -Detail $Reason
}

# Some native tools (netsh on current Windows 11 builds) emit UTF-8 while PowerShell decodes with the OEM code page,
# which turns umlauts into box-drawing characters. Re-decode such lines.
function Repair-ConsoleText {
    param([string]$Text, [Text.Encoding]$Encoding = [Console]::OutputEncoding)
    if ($Text -notmatch '[\u2500-\u257F]|\u00D4\u00C7') { return $Text }
    try {
        $fixed = [Text.Encoding]::UTF8.GetString($Encoding.GetBytes($Text))
        if ($fixed.IndexOf([char]0xFFFD) -lt 0) { return $fixed }
    } catch { Write-Verbose "Repair-ConsoleText failed: $_" }
    return $Text
}

# A click into the console window starts text selection (QuickEdit) and freezes the script on its next console write until
# a key is pressed. Switch QuickEdit off while running and restore the previous mode afterwards.
function Set-ConsoleQuickEdit {
    param([bool]$Enable)
    try {
        if (-not ('WifiCollector.ConsoleMode' -as [type])) {
            Add-Type -Namespace WifiCollector -Name ConsoleMode -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)] public static extern System.IntPtr GetStdHandle(int nStdHandle);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetConsoleMode(System.IntPtr h, out uint mode);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleMode(System.IntPtr h, uint mode);
'@
        }
        $h = [WifiCollector.ConsoleMode]::GetStdHandle(-10)
        [uint32]$mode = 0
        if (-not [WifiCollector.ConsoleMode]::GetConsoleMode($h, [ref]$mode)) { return }   # no console (redirected)
        if ($null -eq $script:QuickEditOrig) { $script:QuickEditOrig = $mode }
        if ($Enable) { $new = $script:QuickEditOrig } else { $new = ($mode -band 0xFFFFFFBFL) -bor 0x80L }   # 0x40 QUICK_EDIT, 0x80 EXTENDED_FLAGS
        if ($new -ne $mode) { [void][WifiCollector.ConsoleMode]::SetConsoleMode($h, [uint32]$new) }
    } catch { $null = $_ }
}

# Runs a native command with a time limit. Output goes to temp files, not to a pipe: a pipe only ends when ALL processes
# holding the handle exit (e.g. helper processes spawned by 'netsh trace stop'), which can block PowerShell forever.
function Invoke-NativeTimed {
    param(
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [int]$TimeoutSec = 120,
        [string]$Activity = ''
    )
    $result = [pscustomobject]@{ ExitCode = -1; Output = @(); TimedOut = $false }
    $cmd = Get-Command $Exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd) { $result.Output = @("$Exe not found"); return $result }
    $outFile = [IO.Path]::GetTempFileName()
    $errFile = [IO.Path]::GetTempFileName()
    $inFile = [IO.Path]::GetTempFileName()   # empty stdin: a child must never wait for a key on the shared console
    try {
        $argText = (@($Arguments) | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
        $spArgs = @{ FilePath = $cmd.Source; NoNewWindow = $true; PassThru = $true; RedirectStandardOutput = $outFile; RedirectStandardError = $errFile; RedirectStandardInput = $inFile }
        if ($argText) { $spArgs.ArgumentList = $argText }
        $proc = Start-Process @spArgs
        $null = $proc.Handle   # keep the handle so ExitCode is available
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (-not $proc.WaitForExit(1000)) {
            if ($Activity) { Write-Progress -Id 2 -Activity $Activity -Status ('{0:N0} s elapsed (time limit {1} s)' -f $sw.Elapsed.TotalSeconds, $TimeoutSec) }
            if ($sw.Elapsed.TotalSeconds -ge $TimeoutSec) {
                $result.TimedOut = $true
                try { & taskkill.exe /T /F /PID $proc.Id 2>&1 | Out-Null } catch { $null = $_ }
                try { if (-not $proc.HasExited) { $proc.Kill() } } catch { $null = $_ }
                break
            }
        }
        if ($Activity) { Write-Progress -Id 2 -Activity $Activity -Completed }
        if (-not $result.TimedOut) { $result.ExitCode = $proc.ExitCode }
    } finally {
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($f in $outFile, $errFile) {
            $text = ''
            try {
                $fs = New-Object IO.FileStream($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                $sr = New-Object IO.StreamReader($fs, [Console]::OutputEncoding)
                $text = $sr.ReadToEnd()
                $sr.Dispose()
            } catch { $text = '' }
            foreach ($l in ($text -split "\r?\n")) { $lines.Add((Repair-ConsoleText $l)) }
            Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $inFile -Force -ErrorAction SilentlyContinue
        while ($lines.Count -gt 0 -and -not $lines[$lines.Count - 1].Trim()) { $lines.RemoveAt($lines.Count - 1) }
        $result.Output = @($lines)
    }
    return $result
}

# Runs a native command and writes stdout+stderr to a UTF-8 file. A non-zero exit code is a warning.
function Save-NativeOutput {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [int]$TimeoutSec = 180
    )
    if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) {
        $script:StepWarn = "$Exe not found"
        return
    }
    $timedOut = $false
    try {
        $r = Invoke-NativeTimed -Exe $Exe -Arguments $Arguments -TimeoutSec $TimeoutSec
        $out = @($r.Output)
        $code = $r.ExitCode
        $timedOut = $r.TimedOut
    } catch {
        Write-CollectorLog "Invoke-NativeTimed failed for $Exe ($($_.Exception.Message)), using plain invocation" 'WARN'
        $out = @(& $Exe @Arguments 2>&1 | ForEach-Object { Repair-ConsoleText "$_" })
        $code = $LASTEXITCODE
    }
    $out | Out-File -FilePath $Path -Encoding utf8
    if ($timedOut) { $script:StepWarn = "timed out after $TimeoutSec s, output may be partial" }
    elseif (($out -join "`n") -match 'privacy-location') {
        $script:LocationBlocked = $true
        $script:StepWarn = 'blocked by Windows: location access required for WLAN info (see Summary)'
    } elseif ($code -ne 0) { $script:StepWarn = "exit code $code" }
}

# Runs a script block and writes its (formatted) output to a UTF-8 file.
function Save-CmdletOutput {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][scriptblock]$Script)
    & $Script 2>&1 | Out-String -Width 4096 | Out-File -FilePath $Path -Encoding utf8
}

function ConvertTo-WevtutilTime {
    param([datetime]$Time)
    $Time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.000'Z'")
}

function Export-EventLogFile {
    param([string]$LogName, [string]$Directory, [Nullable[datetime]]$Since)
    $file = Join-Path $Directory (($LogName -replace '[\\/ ]', '_') + '.evtx')
    $wevtArgs = @('epl', $LogName, $file, '/ow:true')
    if ($Since) { $wevtArgs += ('/q:*[System[TimeCreated[@SystemTime>=''{0}'']]]' -f (ConvertTo-WevtutilTime $Since)) }
    $out = & wevtutil.exe @wevtArgs 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { throw ("wevtutil exit code {0}: {1}" -f $LASTEXITCODE, ($out -join ' ')) }
}

function Test-WifiScenario { return ($Scenario -eq 'Wireless') }

# ---------------------------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------------------------
# Scenario names differ between Windows builds (e.g. Windows 11 24H2 has no WLAN scenario at all): ask netsh.
function Get-NetshTraceScenario {
    $r = Invoke-NativeTimed -Exe 'netsh.exe' -Arguments @('trace', 'show', 'scenarios') -TimeoutSec 60
    $r.Output | Out-File -FilePath (Join-Path $script:Dir.Traces 'netsh_trace_show_scenarios.txt') -Encoding utf8
    $names = @()
    foreach ($l in $r.Output) { if ($l -match '^\s*([A-Za-z0-9_\-]+)\s*:\s') { $names += $Matches[1] } }
    return $names
}

# Wi-Fi/EAP/DHCP ETW providers from 'netsh trace show providers' (name + GUID).
function Get-NetshTraceProvider {
    param([string[]]$Priority, [string]$Pattern)
    $r = Invoke-NativeTimed -Exe 'netsh.exe' -Arguments @('trace', 'show', 'providers') -TimeoutSec 60
    $r.Output | Out-File -FilePath (Join-Path $script:Dir.Traces 'netsh_trace_show_providers.txt') -Encoding utf8
    $found = @{}
    foreach ($l in $r.Output) {
        if ($l -match '(\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})') {
            $guid = $Matches[1]
            $name = ($l -replace [regex]::Escape($guid), '').Trim(" `t-:()[]")
            if ($name -match $Pattern -and $name -notmatch 'Virtual|Hyper-V|Bluetooth|Heap') {
                $score = 100
                for ($i = 0; $i -lt $Priority.Count; $i++) { if ($name -match $Priority[$i]) { $score = $i; break } }
                $found[$guid] = [pscustomobject]@{ Guid = $guid; Name = $name; Score = $score }
            }
        }
    }
    return @($found.Values | Sort-Object Score, Name | Select-Object -First 40)
}

# Own ETW session via logman: a denied/unknown provider only skips that provider instead of failing the whole trace.
function Start-WifiEtwSession {
    $sessionName = 'WifiLogCollector'
    if (Test-WifiScenario) {
        $priority = @('WLAN-AutoConfig', 'NWiFi|Native-?Wifi', 'WiFiNetworkManager', 'WLAN', 'WDI', 'OneX', 'EapHost', 'Eap(Methods|Peer)|RasChap|RasTls', 'Dhcp', 'NCSI', 'NlaSvc', 'Wcm')
        $pattern = 'WLAN|WiFi|Wi-Fi|NWiFi|Native-?Wifi|80211|WDI|OneX|EapHost|Eap(Methods|Peer)|RasChap|RasTls|Dhcp|NCSI|NlaSvc|\bWcm'
    } else {
        $priority = @('Wired-AutoConfig|Dot3', 'OneX', 'EapHost', 'Eap(Methods|Peer)|RasChap|RasTls', 'Dhcp', 'NCSI', 'NlaSvc', 'Wcm')
        $pattern = 'Wired|Dot3|OneX|EapHost|Eap(Methods|Peer)|RasChap|RasTls|Dhcp|NCSI|NlaSvc|\bWcm'
    }
    $providers = @(Get-NetshTraceProvider -Priority $priority -Pattern $pattern)
    if ($providers.Count -eq 0) { throw 'no matching ETW providers found (see 01_Traces\netsh_trace_show_providers.txt)' }
    Write-CollectorLog ('ETW providers selected: ' + (($providers | ForEach-Object { '{0} {1}' -f $_.Name, $_.Guid }) -join '; '))

    $etl = Join-Path $script:Dir.Traces ($env:COMPUTERNAME + '_wifi_etw.etl')
    [void](Invoke-NativeTimed -Exe 'logman.exe' -Arguments @('stop', $sessionName, '-ets') -TimeoutSec 30)   # stale session of an aborted run
    $enabled = 0
    $denied = New-Object System.Collections.Generic.List[string]
    foreach ($p in $providers) {
        if ($enabled -eq 0) {
            $logmanArgs = @('create', 'trace', $sessionName, '-ow', '-o', $etl, '-f', 'bincirc', '-max', '512', '-p', $p.Guid, '0xFFFFFFFFFFFFFFFF', '5', '-ets')
        } else {
            $logmanArgs = @('update', 'trace', $sessionName, '-p', $p.Guid, '0xFFFFFFFFFFFFFFFF', '5', '-ets')
        }
        $r = Invoke-NativeTimed -Exe 'logman.exe' -Arguments $logmanArgs -TimeoutSec 30
        Write-CollectorLog ('logman {0} [{1}] -> exit {2}: {3}' -f ($logmanArgs[0..1] -join ' '), $p.Name, $r.ExitCode, (($r.Output | Where-Object { $_.Trim() }) -join ' | '))
        if ($r.ExitCode -eq 0 -and -not $r.TimedOut) { $enabled++ } else { $denied.Add($p.Name) }
    }
    if ($enabled -eq 0) { throw "no ETW provider could be enabled (all $($providers.Count) failed, see collector.log)" }
    $script:State.EtwSession = $true
    $script:EtwSessionName = $sessionName
    $script:EtwInfo = '{0} of {1} Wi-Fi/EAP/DHCP ETW providers enabled' -f $enabled, $providers.Count
    if ($denied.Count -gt 0) { $script:StepWarn = ('{0}; not enabled: {1}' -f $script:EtwInfo, (($denied | Select-Object -First 6) -join ', ')) }
}

function Stop-WifiEtwSession {
    $r = Invoke-NativeTimed -Exe 'logman.exe' -Arguments @('stop', $script:EtwSessionName, '-ets') -TimeoutSec 120
    Write-CollectorLog ('logman stop -> exit {0}: {1}' -f $r.ExitCode, (($r.Output | Where-Object { $_.Trim() }) -join ' | '))
    $script:State.EtwSession = $false
    if ($r.ExitCode -ne 0) { $script:StepWarn = "logman stop exit code $($r.ExitCode)" }
}

# Is a netsh trace session running right now? (the status output contains the .etl path only while one is running)
function Test-NetshTraceRunning {
    $r = Invoke-NativeTimed -Exe 'netsh.exe' -Arguments @('trace', 'show', 'status') -TimeoutSec 30
    return (($r.Output -join "`n") -match '\.etl')
}

# netsh trace: scenario if the build offers one, otherwise a plain NDIS packet capture (no ETW providers needed).
function Start-NetshTrace {
    if ($NoPacketCapture) { $script:StepSkip = '-NoPacketCapture given'; return }
    if (Test-WifiScenario) {
        $etl = Join-Path $script:Dir.Traces ($env:COMPUTERNAME + '_wireless_cli.etl')
        $scenarioPattern = 'wlan|wi-?fi|wireless'
    } else {
        $etl = Join-Path $script:Dir.Traces ($env:COMPUTERNAME + '_wired_cli.etl')
        $scenarioPattern = '^lan$|wired|dot3|ethernet'
    }
    $common = @('capture=yes', "maxsize=$MaxTraceSizeMB", "tracefile=$etl")

    if (Test-NetshTraceRunning) {
        if ($Force) {
            Write-CollectorLog 'A netsh trace session is already running, -Force given: stopping it.' 'WARN'
            [void](Invoke-NativeTimed -Exe 'netsh.exe' -Arguments @('trace', 'stop') -TimeoutSec 600 -Activity 'stopping the existing netsh trace session')
        } else {
            throw "a netsh trace session is already running (check 'netsh trace show status'). Use -Force to stop it, or run 'netsh trace stop' first."
        }
    }

    $available = @(Get-NetshTraceScenario)
    $found = @($available | Where-Object { $_ -match $scenarioPattern -and $_ -notmatch 'display|direct|hosted|p2p|wwan|mbn' })
    Write-CollectorLog ("Available trace scenarios: {0}; selected: {1}" -f ($available -join ', '), ($found -join ', '))

    $attempts = New-Object System.Collections.Generic.List[object]
    if ($found.Count -gt 0) { $attempts.Add(@{ Label = "scenario $($found -join ',')"; Args = @("scenario=$($found -join ',')", 'globallevel=0xff') + $common }) }
    $attempts.Add(@{ Label = 'NDIS packet capture'; Args = @('globallevel=0xff') + $common })

    $lastError = ''
    foreach ($at in $attempts) {
        $traceArgs = @('trace', 'start') + $at.Args
        $r = Invoke-NativeTimed -Exe 'netsh.exe' -Arguments $traceArgs -TimeoutSec 90
        Write-CollectorLog ("netsh {0} -> exit {1}{2}`r`n{3}" -f ($traceArgs -join ' '), $r.ExitCode, $(if ($r.TimedOut) { ' (TIMED OUT)' } else { '' }), ($r.Output -join "`r`n"))
        if ($r.ExitCode -eq 0 -and -not $r.TimedOut) {
            $script:State.NetshTrace = $true
            $script:TraceMode = $at.Label
            return
        }
        $lastError = (($r.Output | Where-Object { $_.Trim() }) -join ' ')
        # no session existed before (checked above), so a failed start can only leave our own half-started session behind
        [void](Invoke-NativeTimed -Exe 'netsh.exe' -Arguments @('trace', 'stop') -TimeoutSec 300)
    }
    throw "netsh trace could not be started: $lastError"
}

function Enable-Capi2Log {
    $logName = 'Microsoft-Windows-CAPI2/Operational'
    $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
    $script:State.Capi2Prev = @{ Enabled = $log.IsEnabled; MaxSize = $log.MaximumSizeInBytes }
    & wevtutil.exe sl $logName /e:true | Out-Null
    if ($log.MaximumSizeInBytes -lt 104857600) { & wevtutil.exe sl $logName /ms:104857600 | Out-Null }
}

function Stop-Capi2Log {
    $logName = 'Microsoft-Windows-CAPI2/Operational'
    $prev = $script:State.Capi2Prev
    if (-not $prev) { return }
    # Export only what happened during this run; the existing log is never cleared.
    Export-EventLogFile -LogName $logName -Directory $script:Dir.Traces -Since $script:StartTime
    if (-not $prev.Enabled) { & wevtutil.exe sl $logName /e:false | Out-Null }
    if ($prev.MaxSize -lt 104857600) { & wevtutil.exe sl $logName "/ms:$($prev.MaxSize)" | Out-Null }
    $script:State.Capi2Prev = $null
}

function Start-Psr {
    $zip = Join-Path $script:Dir.Traces ($env:COMPUTERNAME + '_psr.zip')
    $script:PsrZip = $zip
    $script:PsrViaShell = $false
    $started = $false
    try {
        & psr.exe /start /output $zip /maxsc $MaxScreenshots /gui 0 2>&1 | Out-Null
        $started = ($LASTEXITCODE -eq 0)
    } catch { Write-CollectorLog "psr.exe direct start failed: $($_.Exception.Message)" 'WARN' }
    if (-not $started) {
        # e.g. error 740 'requires elevation': let the shell launch it (may show a UAC prompt)
        try {
            Start-Process -FilePath 'psr.exe' -ArgumentList ('/start /output "{0}" /maxsc {1} /gui 0' -f $zip, $MaxScreenshots) -WindowStyle Hidden -ErrorAction Stop
            $started = $true
            $script:PsrViaShell = $true
        } catch { throw "psr.exe could not be started: $($_.Exception.Message) (psr.exe was removed in Windows 11 24H2; do not use -IncludePsr there)" }
    }
    $script:State.Psr = $true
}

function Stop-Psr {
    if ($script:PsrViaShell) { Start-Process -FilePath 'psr.exe' -ArgumentList '/stop' -WindowStyle Hidden -ErrorAction SilentlyContinue }
    else { & psr.exe /stop 2>&1 | Out-Null }
    $script:State.Psr = $false
    # PSR writes the zip asynchronously
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-Path -LiteralPath $script:PsrZip) { break }
        Start-Sleep -Seconds 1
    }
    if (-not (Test-Path -LiteralPath $script:PsrZip)) { $script:StepWarn = 'PSR output file not found' }
}

# Background samplers: self-contained script blocks because jobs run in a separate process.
# Generic timestamped netsh sampler (used for 'wlan show interfaces' and 'wlan show networks mode=bssid').
$script:NetshSamplerBlock = {
    param($Path, $IntervalSec, $NetshArgs)
    function Repair-ConsoleText {
        param([string]$Text)
        if ($Text -notmatch '[\u2500-\u257F]|\u00D4\u00C7') { return $Text }
        try {
            $fixed = [Text.Encoding]::UTF8.GetString([Console]::OutputEncoding.GetBytes($Text))
            if ($fixed.IndexOf([char]0xFFFD) -lt 0) { return $fixed }
        } catch { $null = $_ }
        return $Text
    }
    $netshArgList = @($NetshArgs -split ' ')
    while ($true) {
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $text = (& netsh.exe @netshArgList 2>&1 | ForEach-Object { Repair-ConsoleText "$_" }) -join "`r`n"
        Add-Content -Path $Path -Value ("===== $ts =====`r`n$text`r`n") -Encoding UTF8
        Start-Sleep -Seconds $IntervalSec
    }
}

# Link state/speed of physical adapters; works without the location permission that 'netsh wlan show interfaces' needs.
$script:AdapterSamplerBlock = {
    param($Path, $IntervalSec)
    Add-Content -Path $Path -Value 'Time,Name,Status,LinkSpeed,Description,RssiDbm' -Encoding UTF8
    while ($true) {
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $rssi = @{}
        try {
            foreach ($w in @(Get-CimInstance -Namespace 'root\wmi' -ClassName MSNdis_80211_ReceivedSignalStrength -ErrorAction Stop)) {
                $rssi[[string]$w.InstanceName] = $w.Ndis80211ReceivedSignalStrength
            }
        } catch { $null = $_ }
        foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)) {
            $dbm = ''
            if ($a.Status -eq 'Up' -and $rssi.ContainsKey([string]$a.InterfaceDescription)) { $dbm = $rssi[[string]$a.InterfaceDescription] }
            Add-Content -Path $Path -Value ('{0},"{1}",{2},"{3}","{4}",{5}' -f $ts, $a.Name, $a.Status, $a.LinkSpeed, $a.InterfaceDescription, $dbm) -Encoding UTF8
        }
        Start-Sleep -Seconds $IntervalSec
    }
}

$script:PingBlock = {
    param($Path, $ExtraTargets)
    Add-Content -Path $Path -Value 'Time,Target,Status,RttMs' -Encoding UTF8
    $ping = New-Object System.Net.NetworkInformation.Ping
    $targets = @()
    $i = 0
    while ($true) {
        if ($i % 10 -eq 0) {
            $gw = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                    Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
                    Select-Object -ExpandProperty NextHop -Unique)
            $extra = @($ExtraTargets -split ',' | Where-Object { $_ })
            if ($gw.Count -eq 0) {   # e.g. full-tunnel VPN without a gateway on the default route: use the gateways of the physical adapters
                $gw = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' -ErrorAction SilentlyContinue |
                        Where-Object { $_.DefaultIPGateway -and $_.Description -notmatch 'Virtual|VPN|PPP|Hyper-V|VMware' } |
                        ForEach-Object { $_.DefaultIPGateway } | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -Unique)
            }
            $targets = @(($gw + $extra) | Select-Object -Unique)
        }
        foreach ($t in $targets) {
            $status = 'Error'
            $rtt = ''
            try {
                $reply = $ping.Send($t, 1000)
                $status = [string]$reply.Status
                if ($reply.Status -eq 'Success') { $rtt = $reply.RoundtripTime }
            } catch { $status = 'Error' }
            Add-Content -Path $Path -Value ('{0:yyyy-MM-dd HH:mm:ss.fff},{1},{2},{3}' -f (Get-Date), $t, $status, $rtt) -Encoding UTF8
        }
        $i++
        Start-Sleep -Seconds 1
    }
}

function Start-Monitors {
    $jobs = @()
    if (Test-WifiScenario) {
        $jobs += Start-Job -Name 'wlan-sampler' -ScriptBlock $script:NetshSamplerBlock -ArgumentList (Join-Path $script:Dir.Monitor 'wlan_interface_samples.log'), 2, 'wlan show interfaces'
        $jobs += Start-Job -Name 'wlan-neighbours' -ScriptBlock $script:NetshSamplerBlock -ArgumentList (Join-Path $script:Dir.Monitor 'wlan_neighbour_aps.log'), 15, 'wlan show networks mode=bssid'
    }
    $jobs += Start-Job -Name 'adapter-sampler' -ScriptBlock $script:AdapterSamplerBlock -ArgumentList (Join-Path $script:Dir.Monitor 'adapter_link_samples.csv'), 2
    $jobs += Start-Job -Name 'ping' -ScriptBlock $script:PingBlock -ArgumentList (Join-Path $script:Dir.Monitor 'ping.csv'), ($PingTarget -join ',')
    $script:State.Jobs = $jobs
}

function Stop-Monitors {
    foreach ($j in $script:State.Jobs) {
        Stop-Job -Job $j -ErrorAction SilentlyContinue
        Remove-Job -Job $j -Force -ErrorAction SilentlyContinue
    }
    $script:State.Jobs = @()
}

function Stop-NetshTrace {
    $limit = 1200
    $r = Invoke-NativeTimed -Exe 'netsh.exe' -Arguments @('trace', 'stop') -TimeoutSec $limit -Activity 'netsh trace stop (merging the trace file, can take several minutes)'
    $r.Output | Out-File -FilePath (Join-Path $script:Dir.Traces 'netsh_trace_stop.txt') -Encoding utf8
    if ($r.TimedOut) { $script:StepWarn = "netsh trace stop did not finish within $limit s and was aborted; the .etl may be incomplete" }
    elseif ($r.ExitCode -ne 0) { $script:StepWarn = "exit code $($r.ExitCode)" }
    $script:State.NetshTrace = $false
}

function Stop-RasTrace {
    [void](Invoke-NativeTimed -Exe 'netsh.exe' -Arguments @('ras', 'set', 'tracing', '*', 'disabled') -TimeoutSec 60)
    $script:State.RasTrace = $false
}

function Copy-RasTraceFiles {
    $src = Join-Path $env:SystemRoot 'Tracing'
    if (-not (Test-Path -LiteralPath $src)) { $script:StepWarn = "$src not found"; return }
    $dst = Join-Path $script:Dir.Traces 'Tracing'
    New-Item -ItemType Directory -Path $dst -Force | Out-Null
    $cutoff = $script:StartTime.AddMinutes(-1)
    $count = 0
    Get-ChildItem -LiteralPath $src -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $cutoff } |
        ForEach-Object {
            $rel = $_.FullName.Substring($src.Length).TrimStart('\')
            $target = Join-Path $dst $rel
            New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $target -ErrorAction SilentlyContinue
            $count++
        }
    if ($count -eq 0) { $script:StepWarn = 'no RAS trace files written during this run' }
}

function Wait-ForReproduction {
    if ($DurationSeconds -gt 0) {
        Write-Info ("Capturing for {0} s. Reproduce the problem now." -f $DurationSeconds) 'Cyan'
        $end = (Get-Date).AddSeconds($DurationSeconds)
        while ((Get-Date) -lt $end) {
            $left = [int][math]::Ceiling(($end - (Get-Date)).TotalSeconds)
            $pct = [int][math]::Min(100, [math]::Max(0, 100 * (1 - $left / $DurationSeconds)))
            Write-Progress -Activity 'Capturing - reproduce the issue now' -Status "$left s remaining" -PercentComplete $pct
            Start-Sleep -Seconds 1
        }
        Write-Progress -Activity 'Capturing' -Completed
    } else {
        Write-Host ''
        Write-Host '=============================================================================' -ForegroundColor Cyan
        Write-Host ' Capture is running. Now REPRODUCE THE PROBLEM:' -ForegroundColor Cyan
        Write-Host '   - Best: toggle Wi-Fi off/on (or reconnect to the SSID) so the complete' -ForegroundColor Cyan
        Write-Host '     association + authentication handshake is captured.' -ForegroundColor Cyan
        Write-Host '   - For roaming/drop issues: walk around / wait until it happens.' -ForegroundColor Cyan
        Write-Host ' Press ENTER when the problem occurred to stop the capture.' -ForegroundColor Cyan
        Write-Host '=============================================================================' -ForegroundColor Cyan
        [void](Read-Host 'ENTER to stop')
    }
}

# ---------------------------------------------------------------------------------------------
# Static collection
# ---------------------------------------------------------------------------------------------
function Get-WifiAdapters {
    @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object { $_.PhysicalMediaType -match '802\.11' -or $_.InterfaceDescription -match 'Wi-?Fi|Wireless|802\.11|WLAN' } |
            Where-Object { $_.InterfaceDescription -notmatch 'Virtual|Direct|Hosted' })
}

function Invoke-WirelessCollection {
    $d = $script:Dir.Wireless
    $days = $EventLogDays
    if ($days -le 0) { $days = 30 }
    if ($days -gt 365) { $days = 365 }

    $cmds = @(
        @{ File = 'wlan_show_all.txt'; Args = @('wlan', 'show', 'all') },
        @{ File = 'wlan_show_interfaces.txt'; Args = @('wlan', 'show', 'interfaces') },
        @{ File = 'wlan_show_drivers.txt'; Args = @('wlan', 'show', 'drivers') },
        @{ File = 'wlan_show_settings.txt'; Args = @('wlan', 'show', 'settings') },
        @{ File = 'wlan_show_filters.txt'; Args = @('wlan', 'show', 'filters') },
        @{ File = 'wlan_show_profiles_detail.txt'; Args = @('wlan', 'show', 'profiles', 'name=*') },
        @{ File = 'wlan_show_networks_bssid.txt'; Args = @('wlan', 'show', 'networks', 'mode=bssid') },
        @{ File = 'lan_show_interfaces.txt'; Args = @('lan', 'show', 'interfaces') },
        @{ File = 'lan_show_profiles.txt'; Args = @('lan', 'show', 'profiles') },
        @{ File = 'lan_show_settings.txt'; Args = @('lan', 'show', 'settings') }
    )
    $dot3 = Get-Service -Name dot3svc -ErrorAction SilentlyContinue
    $dot3Running = ($dot3 -and $dot3.Status -eq 'Running')
    foreach ($c in $cmds) {
        $stepName = 'netsh ' + ($c.Args -join ' ')
        if ($c.Args[0] -eq 'lan' -and -not $dot3Running) { Skip-Step $stepName 'Wired AutoConfig (dot3svc) is not running'; continue }
        Invoke-Step $stepName { Save-NativeOutput -Path (Join-Path $d $c.File) -Exe 'netsh.exe' -Arguments $c.Args }
    }

    # Profiles are exported without keys (key=clear is intentionally not used).
    Invoke-Step 'netsh wlan export profile' {
        $p = Join-Path $d 'WlanProfiles'
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        Save-NativeOutput -Path (Join-Path $d 'wlan_export_profile.txt') -Exe 'netsh.exe' -Arguments @('wlan', 'export', 'profile', "folder=$p")
    }
    if ($dot3Running) {
        Invoke-Step 'netsh lan export profile' {
            $p = Join-Path $d 'LanProfiles'
            New-Item -ItemType Directory -Path $p -Force | Out-Null
            Save-NativeOutput -Path (Join-Path $d 'lan_export_profile.txt') -Exe 'netsh.exe' -Arguments @('lan', 'export', 'profile', "folder=$p")
        }
    } else { Skip-Step 'netsh lan export profile' 'Wired AutoConfig (dot3svc) is not running' }

    Invoke-Step 'netsh wlan show wlanreport (HTML report)' {
        Save-NativeOutput -Path (Join-Path $d 'wlan_show_wlanreport.txt') -Exe 'netsh.exe' -Arguments @('wlan', 'show', 'wlanreport', "duration=$days")
        $reportDir = Join-Path $env:ProgramData 'Microsoft\Windows\WlanReport'
        $files = @(Get-ChildItem -LiteralPath $reportDir -Filter 'wlan-report-latest.*' -ErrorAction SilentlyContinue)
        if ($files.Count -eq 0) { $script:StepWarn = 'no wlan-report-latest.* found'; return }
        $files | Copy-Item -Destination $d -ErrorAction Stop
    }

    Invoke-Step 'WLAN profile XMLs from ProgramData' {
        $src = Join-Path $env:ProgramData 'Microsoft\Wlansvc\Profiles'
        if (Test-Path -LiteralPath $src) {
            Copy-Item -LiteralPath $src -Destination (Join-Path $d 'ProgramData_Wlansvc_Profiles') -Recurse -ErrorAction Stop
        } else { $script:StepWarn = 'folder not found' }
    }
}

function Invoke-NetworkCollection {
    $d = $script:Dir.Network
    $native = @(
        @{ File = 'ipconfig_all.txt'; Exe = 'ipconfig.exe'; Args = @('/all') },
        @{ File = 'route_print.txt'; Exe = 'route.exe'; Args = @('print') },
        @{ File = 'arp_a.txt'; Exe = 'arp.exe'; Args = @('-a') },
        @{ File = 'netsh_winhttp_proxy.txt'; Exe = 'netsh.exe'; Args = @('winhttp', 'show', 'proxy') },
        @{ File = 'netsh_advfirewall_profiles.txt'; Exe = 'netsh.exe'; Args = @('advfirewall', 'show', 'allprofiles') },
        @{ File = 'netcfg_network_components.txt'; Exe = 'netcfg.exe'; Args = @('-s', 'n') }
    )
    foreach ($c in $native) {
        Invoke-Step ("{0} {1}" -f $c.Exe, ($c.Args -join ' ')) { Save-NativeOutput -Path (Join-Path $d $c.File) -Exe $c.Exe -Arguments $c.Args }
    }

    $cmdlets = @(
        @{ File = 'Get-NetAdapter.txt'; Script = { Get-NetAdapter -IncludeHidden | Format-List * } },
        @{ File = 'Get-NetAdapterAdvancedProperty.txt'; Script = { Get-NetAdapterAdvancedProperty | Format-Table -AutoSize Name, DisplayName, DisplayValue, RegistryKeyword, RegistryValue } },
        @{ File = 'Get-NetAdapterPowerManagement.txt'; Script = { Get-NetAdapterPowerManagement | Format-List * } },
        @{ File = 'Get-NetAdapterBinding.txt'; Script = { Get-NetAdapterBinding | Format-Table -AutoSize } },
        @{ File = 'Get-NetAdapterStatistics.txt'; Script = { Get-NetAdapterStatistics | Format-List * } },
        @{ File = 'Get-NetIPConfiguration.txt'; Script = { Get-NetIPConfiguration -Detailed } },
        @{ File = 'Get-NetIPInterface.txt'; Script = { Get-NetIPInterface | Format-Table -AutoSize } },
        @{ File = 'Get-NetConnectionProfile.txt'; Script = { Get-NetConnectionProfile | Format-List * } },
        @{ File = 'Get-DnsClientServerAddress.txt'; Script = { Get-DnsClientServerAddress | Format-Table -AutoSize } },
        @{ File = 'Get-DnsClient.txt'; Script = { Get-DnsClient | Format-List * } },
        @{ File = 'Get-NetRoute.txt'; Script = { Get-NetRoute | Sort-Object DestinationPrefix | Format-Table -AutoSize } }
    )
    foreach ($c in $cmdlets) {
        Invoke-Step ($c.File -replace '\.txt$', '') { Save-CmdletOutput -Path (Join-Path $d $c.File) -Script $c.Script }
    }
}

function Invoke-SystemCollection {
    $d = $script:Dir.System
    $comp = $env:COMPUTERNAME

    $native = @(
        @{ File = 'systeminfo.txt'; Exe = 'systeminfo.exe'; Args = @() },
        @{ File = 'gpresult_R.txt'; Exe = 'gpresult.exe'; Args = @('/R') },
        @{ File = 'dsregcmd_status.txt'; Exe = 'dsregcmd.exe'; Args = @('/status') },
        @{ File = 'w32tm_status.txt'; Exe = 'w32tm.exe'; Args = @('/query', '/status') },
        @{ File = 'powercfg_active_scheme.txt'; Exe = 'powercfg.exe'; Args = @('/getactivescheme') },
        @{ File = 'powercfg_wireless_adapter_settings.txt'; Exe = 'powercfg.exe'; Args = @('/q', 'SCHEME_CURRENT', '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1') },
        @{ File = 'powercfg_available_sleep_states.txt'; Exe = 'powercfg.exe'; Args = @('/a') },
        @{ File = 'pnputil_net_devices.txt'; Exe = 'pnputil.exe'; Args = @('/enum-devices', '/class', 'Net') }
    )
    foreach ($c in $native) {
        Invoke-Step ("{0} {1}" -f $c.Exe, ($c.Args -join ' ')) { Save-NativeOutput -Path (Join-Path $d $c.File) -Exe $c.Exe -Arguments $c.Args }
    }

    Invoke-Step 'gpresult /H (Group Policy report)' {
        Save-NativeOutput -Path (Join-Path $d 'gpresult_cmd_output.txt') -Exe 'gpresult.exe' -Arguments @('/H', (Join-Path $d "${comp}_gpresult.htm"), '/F')
    }

    if ($IncludeMsinfo) {
        Invoke-Step 'msinfo32 /report (can take several minutes)' {
            $f = Join-Path $d "${comp}_msinfo32.txt"
            Start-Process -FilePath 'msinfo32.exe' -ArgumentList '/report', ('"{0}"' -f $f) -Wait -WindowStyle Hidden
            # msinfo32 may hand over to a child process: wait until the report stops growing
            $last = -1
            for ($i = 0; $i -lt 80; $i++) {
                $size = -1
                if (Test-Path -LiteralPath $f) { $size = (Get-Item -LiteralPath $f).Length }
                if ($size -gt 0 -and $size -eq $last) { return }
                $last = $size
                Start-Sleep -Seconds 3
            }
            $script:StepWarn = 'report may be incomplete'
        }
    }

    $cmdlets = @(
        @{ File = 'Get-Service_network_related.txt'; Script = {
                Get-Service -Name Wlansvc, dot3svc, EapHost, Dhcp, Dnscache, NlaSvc, netprofm, NcaSvc, WcmSvc, RasMan, CryptSvc, BFE, MpsSvc, W32Time, Netman, nsi, Netlogon -ErrorAction SilentlyContinue |
                    Format-Table -AutoSize Name, DisplayName, Status, StartType } },
        @{ File = 'OS_BIOS_ComputerSystem.txt'; Script = {
                Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime
                Get-CimInstance Win32_ComputerSystem | Format-List Manufacturer, Model, SystemType, Domain, PartOfDomain, DomainRole
                Get-CimInstance Win32_BIOS | Format-List Manufacturer, SMBIOSBIOSVersion, ReleaseDate } },
        @{ File = 'NetworkDrivers.txt'; Script = {
                Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -eq 'NET' } |
                    Sort-Object DeviceName | Format-List DeviceName, Manufacturer, DriverVersion, DriverDate, DriverProviderName, InfName, HardWareID } },
        @{ File = 'HotFixes.txt'; Script = { Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table -AutoSize } },
        @{ File = 'InstalledSoftware.txt'; Script = {
                $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
                    Sort-Object DisplayName | Format-Table -AutoSize DisplayName, DisplayVersion, Publisher } }
    )
    foreach ($c in $cmdlets) {
        Invoke-Step ($c.File -replace '\.txt$', '') { Save-CmdletOutput -Path (Join-Path $d $c.File) -Script $c.Script }
    }

    # Registry: supplicant services, policies, NIC driver settings, network profiles
    $regKeys = @(
        'HKLM\SOFTWARE\Microsoft\Wlansvc',
        'HKLM\SYSTEM\CurrentControlSet\Services\Wlansvc',
        'HKLM\SYSTEM\CurrentControlSet\Services\dot3svc',
        'HKLM\SYSTEM\CurrentControlSet\Services\EapHost',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\Wireless',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\WiredL2',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc',
        'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList',
        'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    )
    Invoke-Step 'Registry exports (Wlansvc, EapHost, policies, NIC class)' {
        $rd = Join-Path $d 'Registry'
        New-Item -ItemType Directory -Path $rd -Force | Out-Null
        $missing = 0
        foreach ($k in $regKeys) {
            $file = Join-Path $rd (($k -replace '[\\:{} ]', '_') + '.reg')
            & reg.exe export $k $file /y 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { $missing++ }
        }
        if ($missing -gt 0) { $script:StepWarn = "$missing key(s) not present" }
    }
}

function Invoke-CertificateCollection {
    $d = $script:Dir.Certificates

    # Same store list as the Microsoft article (certutil dumps, public data only).
    $machine = [ordered]@{
        MY            = @('reg')
        ROOT          = @('reg', 'gp', 'ent')
        TRUST         = @('reg', 'gp', 'ent')
        CA            = @('reg', 'gp', 'ent')
        AuthRoot      = @('reg', 'gp', 'ent')
        SmartCardRoot = @('reg', 'gp', 'ent')
        NTAUTH        = @('ent')
    }
    $user = [ordered]@{
        MY            = @('reg')
        ROOT          = @('reg', 'ent')
        TRUST         = @('reg', 'gp')
        CA            = @('reg', 'gp')
        Disallowed    = @('reg', 'gp')
        AuthRoot      = @('reg', 'gp')
        SmartCardRoot = @('reg', 'gp')
        UserDS        = @('reg')
    }
    $flag = @{ reg = $null; gp = '-grouppolicy'; ent = '-enterprise' }

    Invoke-Step 'certutil store dumps (machine + user)' {
        $failed = 0
        $total = 0
        foreach ($scope in 'Machine', 'User') {
            $set = $machine
            if ($scope -eq 'User') { $set = $user }
            foreach ($store in $set.Keys) {
                foreach ($variant in $set[$store]) {
                    $certArgs = @('-v', '-silent')
                    if ($scope -eq 'User') { $certArgs += '-user' }
                    $certArgs += '-store'
                    if ($flag[$variant]) { $certArgs += $flag[$variant] }
                    $certArgs += $store
                    $file = Join-Path $d ('{0}_{1}_{2}.txt' -f $scope, $store, $variant)
                    $total++
                    $out = & certutil.exe @certArgs 2>&1 | ForEach-Object { "$_" }
                    if ($LASTEXITCODE -ne 0) { $failed++ }
                    $out | Out-File -FilePath $file -Encoding utf8
                }
            }
        }
        if ($failed -gt 0) { $script:StepWarn = "$failed of $total dumps returned an error (empty/missing store is normal)" }
    }

    Invoke-Step 'Certificate summary (Personal stores, expiry / Client Authentication EKU)' {
        $rows = foreach ($store in 'Cert:\LocalMachine\My', 'Cert:\CurrentUser\My') {
            foreach ($cert in @(Get-ChildItem -Path $store -ErrorAction SilentlyContinue)) {
                $oids = @()
                foreach ($ext in @($cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] })) {
                    foreach ($o in $ext.EnhancedKeyUsages) { $oids += $o.Value }
                }
                $days = [int][math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
                [pscustomobject]@{
                    Store          = $store
                    Subject        = $cert.Subject
                    Issuer         = $cert.Issuer
                    NotBefore      = $cert.NotBefore.ToString('yyyy-MM-dd')
                    NotAfter       = $cert.NotAfter.ToString('yyyy-MM-dd')
                    DaysLeft       = $days
                    HasPrivateKey  = $cert.HasPrivateKey
                    ClientAuth     = ($oids -contains '1.3.6.1.5.5.7.3.2')
                    Thumbprint     = $cert.Thumbprint
                }
            }
        }
        $script:CertRows = @($rows | Where-Object { $_ })
        $script:CertRows | Export-Csv -Path (Join-Path $d 'PersonalCertificates_summary.csv') -NoTypeInformation -Encoding UTF8
    }
}

function Invoke-EventLogCollection {
    $d = $script:Dir.Events
    $logs = @('Application', 'System')
    if (-not $NoSecurityLog) { $logs += 'Security' }
    $logs += @(
        'Microsoft-Windows-WLAN-AutoConfig/Operational',
        'Microsoft-Windows-Wired-AutoConfig/Operational',
        'Microsoft-Windows-EapHost/Operational',
        'Microsoft-Windows-EapMethods-RasChap/Operational',
        'Microsoft-Windows-EapMethods-RasTls/Operational',
        'Microsoft-Windows-EapMethods-Sim/Operational',
        'Microsoft-Windows-EapMethods-Ttls/Operational',
        'Microsoft-Windows-WiFiNetworkManager/Operational',
        'Microsoft-Windows-NCSI/Operational',
        'Microsoft-Windows-NetworkProfile/Operational',
        'Microsoft-Windows-NlaSvc/Operational',
        'Microsoft-Windows-WCM/Operational',
        'Microsoft-Windows-Dhcp-Client/Admin',
        'Microsoft-Windows-DHCPv6-Client/Admin',
        'Microsoft-Windows-DNS-Client/Operational',
        'Microsoft-Windows-Diagnostics-Networking/Operational',
        'Microsoft-Windows-NDIS/Operational',
        'Microsoft-Windows-GroupPolicy/Operational',
        'Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational',
        'Microsoft-Windows-CertPoleEng/Operational',
        'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational',
        'Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational',
        'Microsoft-Windows-CertificateServices-Deployment/Operational',
        'Microsoft-Windows-AAD/Operational',
        'Microsoft-Windows-User Device Registration/Admin',
        'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    )

    $existing = @{}
    foreach ($l in @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue)) { $existing[$l.LogName.ToLowerInvariant()] = $true }

    foreach ($log in $logs) {
        if (-not $existing.ContainsKey($log.ToLowerInvariant())) {
            Skip-Step "Event log $log" 'log does not exist on this system'
            continue
        }
        Invoke-Step "Event log $log" { Export-EventLogFile -LogName $log -Directory $d -Since $script:Since }
    }
}

function Invoke-TimelineCollection {
    # Readable, merged timeline of the most relevant logs (CSV) - saves opening many .evtx files.
    Invoke-Step 'Event timeline (merged CSV of Wi-Fi/network relevant events)' {
        $days = $EventLogDays
        if ($days -le 0) { $days = 14 }
        $since = $script:StartTime.AddDays(-$days)
        $existing = @{}
        foreach ($l in @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue)) { $existing[$l.LogName.ToLowerInvariant()] = $true }

        $channels = @(
            'Microsoft-Windows-WLAN-AutoConfig/Operational', 'Microsoft-Windows-Wired-AutoConfig/Operational',
            'Microsoft-Windows-EapHost/Operational', 'Microsoft-Windows-EapMethods-RasChap/Operational',
            'Microsoft-Windows-EapMethods-RasTls/Operational', 'Microsoft-Windows-EapMethods-Ttls/Operational',
            'Microsoft-Windows-NCSI/Operational', 'Microsoft-Windows-NetworkProfile/Operational',
            'Microsoft-Windows-NlaSvc/Operational', 'Microsoft-Windows-WCM/Operational',
            'Microsoft-Windows-Dhcp-Client/Admin', 'Microsoft-Windows-Diagnostics-Networking/Operational'
        ) | Where-Object { $existing.ContainsKey($_.ToLowerInvariant()) }

        $events = New-Object System.Collections.Generic.List[object]
        foreach ($ch in $channels) {
            Get-WinEvent -FilterHashtable @{ LogName = $ch; StartTime = $since } -MaxEvents 20000 -ErrorAction SilentlyContinue |
                ForEach-Object { $events.Add($_) }
        }
        # System log: warnings/errors (capped per provider/ID, chatty drivers can log tens of thousands) plus sleep/resume events
        $script:TimelineCapped = @()
        $script:SystemIssueCount = 0
        $sysEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2, 3; StartTime = $since } -MaxEvents 50000 -ErrorAction SilentlyContinue)
        $script:SystemIssueCount = $sysEvents.Count
        foreach ($g in ($sysEvents | Group-Object { '{0}|{1}' -f $_.ProviderName, $_.Id })) {
            $keep = @($g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 20)
            foreach ($e in $keep) { $events.Add($e) }
            if ($g.Count -gt 20) { $script:TimelineCapped += ('{0} (events: {1}, kept newest 20)' -f $g.Name, $g.Count) }
        }
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 42, 107, 506, 507; StartTime = $since } -MaxEvents 5000 -ErrorAction SilentlyContinue |
            ForEach-Object { $events.Add($_) }
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Power-Troubleshooter'; Id = 1; StartTime = $since } -MaxEvents 5000 -ErrorAction SilentlyContinue |
            ForEach-Object { $events.Add($_) }

        $script:Timeline = @($events | Sort-Object TimeCreated | ForEach-Object {
                $msg = ''
                if ($_.Message) { $msg = ($_.Message -replace '\s+', ' ').Trim() }
                [pscustomobject]@{
                    Time     = $_.TimeCreated
                    Log      = ($_.LogName -replace '^Microsoft-Windows-', '')
                    Id       = $_.Id
                    LevelId  = $_.Level
                    Level    = $_.LevelDisplayName
                    Provider = $_.ProviderName
                    Message  = $msg
                }
            })
        $script:Timeline | Select-Object @{ n = 'Time'; e = { $_.Time.ToString('yyyy-MM-dd HH:mm:ss.fff') } }, Log, Id, Level, Provider, Message |
            Export-Csv -Path (Join-Path $script:Dir.Summary 'event_timeline.csv') -NoTypeInformation -Encoding UTF8
    }
}

# ---------------------------------------------------------------------------------------------
# Analysis / summary
# ---------------------------------------------------------------------------------------------
function ConvertFrom-WlanSampleLog {
    param([string]$Path, [string[]]$OwnMacs)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if (-not $raw) { return @() }
    $rows = @()
    foreach ($block in [regex]::Split($raw, '(?m)^===== ')) {
        if (-not $block.Trim()) { continue }
        $ts = ($block -split ' =====', 2)[0]
        # Locale independent: Signal is the only value ending with '%', BSSID is a MAC that is not the adapter's own MAC.
        $sig = [regex]::Match($block, '(?m):\s*(\d{1,3})%\s*$')
        $bssid = ''
        foreach ($m in [regex]::Matches($block, '(?im):\s*((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s*$')) {
            $mac = $m.Groups[1].Value.ToLowerInvariant()
            if ($OwnMacs -notcontains $mac) { $bssid = $mac; break }
        }
        $signal = $null
        if ($sig.Success) { $signal = [int]$sig.Groups[1].Value }
        $rows += [pscustomobject]@{ Time = $ts; SignalPercent = $signal; Bssid = $bssid }
    }
    return $rows
}

function New-Summary {
    $hdr = New-Object System.Collections.Generic.List[string]
    $s = New-Object System.Collections.Generic.List[string]
    $findings = New-Object System.Collections.Generic.List[string]

    $hdr.Add('Wi-Fi / 802.1X log collection summary')
    $hdr.Add(('=' * 72))
    $hdr.Add("Host            : $env:COMPUTERNAME")
    $hdr.Add("User            : $env:USERDOMAIN\$env:USERNAME")
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) { $hdr.Add("OS              : $($os.Caption) $($os.Version) (build $($os.BuildNumber))") }
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs) { $hdr.Add("Model           : $($cs.Manufacturer) $($cs.Model)") }
    $mode = ''
    if ($SnapshotOnly) { $mode = ', snapshot only' }
    $hdr.Add(('Collected       : {0:yyyy-MM-dd HH:mm:ss} (script v{1}, scenario {2}{3})' -f $script:StartTime, $script:Version, $Scenario, $mode))
    if ($script:TraceMode) { $hdr.Add("Trace mode      : $($script:TraceMode)") }

    # --- adapters ---
    $s.Add('Wireless adapters')
    $s.Add(('-' * 72))
    $wifi = Get-WifiAdapters
    $wifiVisible = @($wifi | Where-Object { -not $_.Hidden })
    if ($wifiVisible.Count -eq 0) {
        $s.Add('  none found')
        if (Test-WifiScenario) { $findings.Add('No wireless adapter found (disabled, missing driver, or hardware switch).') }
    }
    $ownMacs = @()
    foreach ($a in $wifiVisible) {
        $mac = ($a.MacAddress -replace '-', ':').ToLowerInvariant()
        $ownMacs += $mac
        $s.Add(("  {0} | {1} | Status {2} | MAC {3} | Link {4}" -f $a.Name, $a.InterfaceDescription, $a.Status, $mac, $a.LinkSpeed))
        # DriverDate is a DateTime on some builds and a string on others
        $drvDate = $null
        if ($a.DriverDate -is [datetime]) { $drvDate = $a.DriverDate }
        elseif ($a.DriverDate -match '^\d{14}\.') {
            try { $drvDate = [Management.ManagementDateTimeConverter]::ToDateTime([string]$a.DriverDate) } catch { $drvDate = $null }
        }
        elseif ($a.DriverDate) {
            try { $drvDate = [datetime]::Parse([string]$a.DriverDate, [Globalization.CultureInfo]::CurrentCulture) } catch { $drvDate = $null }
            if (-not $drvDate) { try { $drvDate = [datetime]::Parse([string]$a.DriverDate, [Globalization.CultureInfo]::InvariantCulture) } catch { $drvDate = $null } }
        }
        $drvText = [string]$a.DriverDate
        if ($drvDate) { $drvText = $drvDate.ToString('yyyy-MM-dd') }
        $s.Add(("    Driver {0} ({1}) by {2}" -f $a.DriverVersionString, $drvText, $a.DriverProvider))
        if ($a.Status -ne 'Up' -and (Test-WifiScenario)) { $findings.Add("Adapter '$($a.Name)' is not Up (Status: $($a.Status)).") }
        if ($drvDate -and ((Get-Date) - $drvDate).TotalDays -gt 730) {
            $findings.Add(("Adapter '{0}': driver is older than 2 years ({1}, {2})." -f $a.Name, $drvText, $a.DriverVersionString))
        }
        $pm = Get-NetAdapterPowerManagement -Name $a.Name -ErrorAction SilentlyContinue
        if ($pm -and "$($pm.AllowComputerToTurnOffDevice)" -eq 'Enabled') {
            $findings.Add("Adapter '$($a.Name)': 'Allow the computer to turn off this device to save power' is enabled (can cause drops after sleep/idle).")
        }
    }
    $s.Add('')

    # --- services ---
    if (Test-WifiScenario) {
        $svc = Get-Service -Name Wlansvc -ErrorAction SilentlyContinue
        if (-not $svc) { $findings.Add('WLAN AutoConfig service (Wlansvc) does not exist (WLAN feature missing, e.g. on Windows Server).') }
        elseif ($svc.Status -ne 'Running') { $findings.Add("WLAN AutoConfig service (Wlansvc) is $($svc.Status).") }
    } else {
        $svc = Get-Service -Name dot3svc -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') { $findings.Add("Wired AutoConfig service (dot3svc) is $($svc.Status).") }
    }

    # --- certificates ---
    if ($script:CertRows) {
        $ca = @($script:CertRows | Where-Object { $_.ClientAuth })
        $s.Add("Personal certificates with Client Authentication EKU: $($ca.Count)")
        foreach ($c in $ca) {
            $s.Add(("  {0} | {1} | issuer {2} | expires {3} ({4} days) | private key: {5} | {6}" -f $c.Store, $c.Subject, $c.Issuer, $c.NotAfter, $c.DaysLeft, $c.HasPrivateKey, $c.Thumbprint))
            if ($c.DaysLeft -lt 0) {
                $valid = @($ca | Where-Object { $_.Store -eq $c.Store -and $_.Issuer -eq $c.Issuer -and $_.DaysLeft -ge 0 })
                if ($valid.Count -gt 0) { $s.Add('      ^ expired, but a valid certificate from the same issuer exists (probably superseded)') }
                else { $findings.Add("Client-auth certificate EXPIRED and not superseded: $($c.Subject), issuer $($c.Issuer) ($($c.Store), $($c.NotAfter)).") }
            }
            elseif ($c.DaysLeft -lt 30) { $findings.Add("Client-auth certificate expires in $($c.DaysLeft) days: $($c.Subject) ($($c.Store)).") }
            if (-not $c.HasPrivateKey) { $findings.Add("Client-auth certificate without private key: $($c.Subject) ($($c.Store)).") }
        }
        $s.Add('')
    }

    # --- event statistics ---
    $s.Add('Key WLAN-AutoConfig events (last collected window)')
    $s.Add(('-' * 72))
    if ($script:Timeline) {
        $wl = @($script:Timeline | Where-Object { $_.Log -like 'WLAN-AutoConfig*' })
        $idLabels = [ordered]@{
            '8000'  = 'Connection attempt started'
            '8001'  = 'Connected successfully'
            '8002'  = 'Connection FAILED'
            '8003'  = 'Disconnected'
            '11002' = 'Association FAILED'
            '11006' = 'Security/authentication FAILED'
            '12011' = '802.1X authentication started'
            '12012' = '802.1X authentication succeeded'
            '12013' = '802.1X authentication FAILED'
            '12014' = '802.1X authentication restarted'
        }
        foreach ($id in $idLabels.Keys) {
            $n = @($wl | Where-Object { $_.Id -eq [int]$id }).Count
            $s.Add(('  {0,6}  {1,-34} {2,6}' -f $id, $idLabels[[string]$id], $n))
        }
        $fail = @($wl | Where-Object { $_.Id -in 8002, 11002, 11006, 12013 } | Sort-Object Time -Descending)
        if ($fail.Count -gt 0) {
            $findings.Add("$($fail.Count) WLAN connection/association/authentication failure events (8002/11002/11006/12013) - see below and event_timeline.csv.")
            $s.Add('')
            $s.Add('  Most recent failures:')
            foreach ($e in ($fail | Select-Object -First 5)) {
                $m = $e.Message
                if ($m.Length -gt 600) { $m = $m.Substring(0, 120) + ' ... ' + $m.Substring($m.Length - 420) }
                $s.Add(('    {0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f $e.Time, $e.Id, $m))
            }
        }
        # Connection attempts: 8000 (start) -> 8001 (connected) / 8002 (failed), with 802.1X duration (12011 -> 12012)
        $attempts = @()
        $cur = $null
        foreach ($e in @($wl | Sort-Object Time)) {
            switch ($e.Id) {
                8000 { $cur = @{ Start = $e.Time; AuthStart = $null; AuthSecs = $null; End = $null; Result = ''; Detail = '' } }
                12011 { if ($cur -and -not $cur.AuthStart) { $cur.AuthStart = $e.Time } }
                12012 { if ($cur -and $cur.AuthStart) { $cur.AuthSecs = ($e.Time - $cur.AuthStart).TotalSeconds } }
                8001 { if ($cur) { $cur.End = $e.Time; $cur.Result = 'connected'; $attempts += [pscustomobject]$cur; $cur = $null } }
                8002 {
                    if ($cur) {
                        $cur.End = $e.Time; $cur.Result = 'FAILED'
                        $cur.Detail = [string]$e.Message
                        $attempts += [pscustomobject]$cur; $cur = $null
                    }
                }
            }
        }
        if ($attempts.Count -gt 0) {
            $s.Add('')
            $s.Add('  Recent connection attempts (8000 -> 8001/8002):')
            foreach ($at in ($attempts | Select-Object -Last 8)) {
                $dur = [math]::Round(($at.End - $at.Start).TotalSeconds, 1)
                $auth = ''
                if ($null -ne $at.AuthSecs) { $auth = ', 802.1X auth {0:N1} s' -f $at.AuthSecs }
                $reason = ''
                if ($at.Result -eq 'FAILED') {
                    $m = $at.Detail
                    if ($m.Length -gt 200) { $m = '...' + $m.Substring($m.Length - 200) }
                    $reason = ' | ' + $m
                }
                $s.Add(('    {0:yyyy-MM-dd HH:mm:ss}  {1,-9} {2,5} s{3}{4}' -f $at.Start, $at.Result, $dur, $auth, $reason))
                if ($at.Result -eq 'connected' -and $dur -gt 10) { $findings.Add(('Slow connection setup: {0:yyyy-MM-dd HH:mm:ss} took {1} s{2}.' -f $at.Start, $dur, $auth)) }
            }
        }
        $sleep = @($script:Timeline | Where-Object { $_.Provider -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -in 42, 506 }).Count
        $resume = @($script:Timeline | Where-Object {
                ($_.Provider -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -in 107, 507) -or
                ($_.Provider -eq 'Microsoft-Windows-Power-Troubleshooter' -and $_.Id -eq 1) }).Count
        $s.Add('')
        $s.Add("  Sleep/standby entries: $sleep, resume events: $resume (correlate with disconnects in event_timeline.csv)")
        if ($script:TimelineCapped -and $script:TimelineCapped.Count -gt 0) {
            $s.Add('  Chatty System sources (capped in timeline, full data in System.evtx):')
            foreach ($c in ($script:TimelineCapped | Select-Object -First 8)) { $s.Add("    $c") }
        }
        $s.Add("  System critical/error/warning events in window (before capping): $($script:SystemIssueCount)")
    } else {
        $s.Add('  timeline not available')
    }
    $s.Add('')

    if ($script:LocationBlocked) {
        $findings.Add('Windows blocks "netsh wlan show interfaces/networks" (location access required). Signal, BSSID and neighbour AP data is missing: enable Settings > Privacy & security > Location > "Location services" and "Let desktop apps access your location", then run again.')
    }

    # --- adapter link samples (no location permission needed) ---
    $linkFile = Join-Path $script:Dir.Monitor 'adapter_link_samples.csv'
    if (Test-Path -LiteralPath $linkFile) {
        $links = @(Import-Csv -LiteralPath $linkFile -ErrorAction SilentlyContinue)
        if ($links.Count -gt 0) {
            $s.Add('Adapter link state during capture (Get-NetAdapter every 2 s)')
            $s.Add(('-' * 72))
            $hidden = 0
            foreach ($g in ($links | Group-Object Name)) {
                $everUp = @($g.Group | Where-Object { $_.Status -eq 'Up' }).Count -gt 0
                $isWifi = $g.Group[0].Description -match 'Wi-?Fi|Wireless|802\.11|WLAN'
                if (-not $everUp -and -not $isWifi) { $hidden++; continue }
                $statuses = @($g.Group | ForEach-Object { $_.Status })
                $changes = 0
                for ($i = 1; $i -lt $statuses.Count; $i++) { if ($statuses[$i] -ne $statuses[$i - 1]) { $changes++ } }
                $notUp = @($statuses | Where-Object { $_ -ne 'Up' }).Count
                $speeds = @($g.Group | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.LinkSpeed } | Select-Object -Unique)
                $s.Add(("  {0,-24} samples {1,4}, not Up {2,4}, state changes {3}, link speeds: {4}" -f $g.Name, $g.Count, $notUp, $changes, ($speeds -join ' / ')))
                $dbmVals = @($g.Group | Where-Object { $_.RssiDbm -match '^-?\d+$' } | ForEach-Object { [int]$_.RssiDbm })
                if ($dbmVals.Count -gt 0) {
                    $dm = $dbmVals | Measure-Object -Minimum -Maximum -Average
                    $s.Add(('  {0,-24} RSSI (WMI) dBm: min {1}, avg {2:N0}, max {3}' -f '', $dm.Minimum, $dm.Average, $dm.Maximum))
                    if ($dm.Minimum -lt -75) { $findings.Add("Weak RSSI observed on '$($g.Name)' (min $($dm.Minimum) dBm).") }
                }
                if ($changes -gt 0 -and $isWifi) { $findings.Add("Adapter '$($g.Name)' changed link state $changes time(s) during the capture.") }
            }
            if ($hidden -gt 0) { $s.Add("  ($hidden other physical adapters were never Up and are not listed, e.g. cellular/unused Ethernet)") }
            $s.Add('')
        }
    }

    # --- signal / roaming samples ---
    $sampleFile = Join-Path $script:Dir.Monitor 'wlan_interface_samples.log'
    $samples = @(ConvertFrom-WlanSampleLog -Path $sampleFile -OwnMacs $ownMacs)
    if ($samples.Count -gt 0 -and $script:LocationBlocked) {
        $s.Add('Signal / roaming during capture')
        $s.Add(('-' * 72))
        $s.Add('  no data: Windows blocked "netsh wlan show interfaces" (location access required, see findings).')
        $s.Add('')
    } elseif ($samples.Count -gt 0) {
        $s.Add('Signal / roaming during capture (netsh wlan show interfaces every 2 s)')
        $s.Add(('-' * 72))
        $samples | Export-Csv -Path (Join-Path $script:Dir.Monitor 'wlan_interface_samples.csv') -NoTypeInformation -Encoding UTF8
        $conn = @($samples | Where-Object { $null -ne $_.SignalPercent })
        $disc = $samples.Count - $conn.Count
        $s.Add("  Samples: $($samples.Count), without Wi-Fi connection: $disc")
        if ($conn.Count -gt 0) {
            $m = $conn | Measure-Object -Property SignalPercent -Minimum -Maximum -Average
            $s.Add(('  Signal %: min {0}, avg {1:N0}, max {2}' -f $m.Minimum, $m.Average, $m.Maximum))
            if ($m.Minimum -lt 40) { $findings.Add("Weak signal observed during capture (min $($m.Minimum) %).") }
            $bssids = @($conn | Where-Object { $_.Bssid } | Select-Object -ExpandProperty Bssid -Unique)
            $roams = 0
            $prev = $null
            foreach ($c in $conn) {
                if ($c.Bssid -and $prev -and $c.Bssid -ne $prev) { $roams++ }
                if ($c.Bssid) { $prev = $c.Bssid }
            }
            $s.Add("  Distinct BSSIDs: $($bssids.Count) ($($bssids -join ', ')), BSSID changes (roams): $roams")
            if ($roams -gt 3) { $findings.Add("$roams BSSID changes in the capture window (possible roaming/sticky-client problem).") }
        }
        if ($disc -gt 0) { $findings.Add("Wi-Fi was disconnected in $disc of $($samples.Count) samples during the capture.") }
        $s.Add('')
    }

    # --- ping ---
    $pingFile = Join-Path $script:Dir.Monitor 'ping.csv'
    if (Test-Path -LiteralPath $pingFile) {
        $pings = @(Import-Csv -LiteralPath $pingFile -ErrorAction SilentlyContinue)
        if ($pings.Count -gt 0) {
            $s.Add('Ping during capture (default gateway + -PingTarget)')
            $s.Add(('-' * 72))
            foreach ($g in ($pings | Group-Object Target)) {
                $ok = @($g.Group | Where-Object { $_.Status -eq 'Success' })
                $lost = $g.Count - $ok.Count
                $avg = 0
                $max = 0
                if ($ok.Count -gt 0) {
                    $mm = $ok | ForEach-Object { [double]$_.RttMs } | Measure-Object -Average -Maximum
                    $avg = $mm.Average
                    $max = $mm.Maximum
                }
                $s.Add(('  {0,-18} sent {1,5}  lost {2,4} ({3:N1} %)  avg {4:N1} ms  max {5:N0} ms' -f $g.Name, $g.Count, $lost, (100 * $lost / $g.Count), $avg, $max))
                if ($lost -gt 0) { $findings.Add(("Ping to {0}: {1} of {2} lost ({3:N1} %), max RTT {4:N0} ms." -f $g.Name, $lost, $g.Count, (100 * $lost / $g.Count), $max)) }
            }
            $s.Add('')
        }
    }

    # --- step failures ---
    $bad = @($script:Manifest | Where-Object { $_.Status -eq 'FAIL' })
    if ($bad.Count -gt 0) {
        $findings.Add("$($bad.Count) collection step(s) failed (see manifest.csv) - data may be incomplete.")
    }

    $head = New-Object System.Collections.Generic.List[string]
    $head.Add('')
    $head.Add('AUTOMATIC FINDINGS (hints, not a diagnosis)')
    $head.Add(('-' * 72))
    if ($findings.Count -eq 0) { $head.Add('  nothing suspicious detected by the built-in checks - analyse the traces/logs.') }
    foreach ($f in $findings) { $head.Add("  * $f") }
    $head.Add('')

    $out = New-Object System.Collections.Generic.List[string]
    $out.AddRange($hdr)
    $out.AddRange($head)
    $out.AddRange($s)
    $out.Add('Files')
    $out.Add(('-' * 72))
    $out.Add('  01_Traces        netsh trace .etl/.cab (packets: convert .etl with etl2pcapng for Wireshark), CAPI2, PSR, RAS tracing')
    $out.Add('  02_EventLogs     exported .evtx files')
    $out.Add('  03_Wireless      netsh wlan/lan output, WLAN report (HTML), exported profiles')
    $out.Add('  04_Network       IP config, routes, adapter settings (power saving, roaming aggressiveness, ...)')
    $out.Add('  05_System        systeminfo, GPO result, drivers, services, registry, power, time, Entra join')
    $out.Add('  06_Certificates  certutil store dumps + summary of personal certificates')
    $out.Add('  07_Monitor       signal/BSSID samples, ping, neighbour APs during the capture')
    $out.Add('  00_Summary       this file, event_timeline.csv, manifest.csv')
    $out | Out-File -FilePath (Join-Path $script:Dir.Summary 'Summary.txt') -Encoding utf8
    return $out
}

# ---------------------------------------------------------------------------------------------
# LLM report: one compact Markdown file with the text-based essentials (binary formats like
# .evtx/.etl/.cab are not readable by an LLM), plus a pseudonymised copy.
# ---------------------------------------------------------------------------------------------
function Limit-Text {
    param([string]$Text, [int]$MaxChars)
    if ($null -eq $Text) { return '' }
    if ($Text.Length -le $MaxChars) { return $Text }
    $head = [int]($MaxChars * 0.7)
    $tail = $MaxChars - $head
    return $Text.Substring(0, $head) + "`n[... " + ($Text.Length - $MaxChars) + " characters omitted ...]`n" + $Text.Substring($Text.Length - $tail)
}

function Read-FileText {
    param([string]$Path, [int]$MaxChars = 6000)
    if (-not (Test-Path -LiteralPath $Path)) { return '(file not available)' }
    $text = (@(Get-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction SilentlyContinue) -join "`n")
    $text = [regex]::Replace($text, '(\r?\n[ \t]*){3,}', "`n`n")
    return (Limit-Text -Text $text.Trim() -MaxChars $MaxChars)
}

function Get-XmlText {
    param($Xml, [string]$XPath)
    $nodes = @($Xml.SelectNodes($XPath))
    if ($nodes.Count -eq 0) { return '' }
    return ((@($nodes | ForEach-Object { $_.InnerText }) | Select-Object -Unique) -join ',')
}

function Get-WlanProfileSummary {
    $eapNames = @{ '13' = 'EAP-TLS'; '25' = 'PEAP'; '21' = 'EAP-TTLS'; '18' = 'EAP-SIM'; '23' = 'EAP-AKA'; '43' = 'EAP-FAST'; '26' = 'MSCHAPv2'; '6' = 'GTC' }
    $dir = Join-Path $script:Dir.Wireless 'WlanProfiles'
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.xml' -ErrorAction SilentlyContinue)) {
        try { $x = [xml](Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8) } catch { $lines.Add("$($f.Name): not parseable"); continue }
        # EAP chain, outer to inner (e.g. 25 = PEAP, 26 = MSCHAPv2)
        $chain = @()
        foreach ($n in @($x.SelectNodes("//*[local-name()='Eap']/*[local-name()='Type']"))) {
            $v = $n.InnerText.Trim()
            if ($eapNames.ContainsKey($v)) { $chain += "$v ($($eapNames[$v]))" } else { $chain += $v }
        }
        if ($chain.Count -eq 0) {
            $v = Get-XmlText $x "//*[local-name()='EapMethod']/*[local-name()='Type']"
            if ($v) { $chain += $v }
        }
        $eapText = $chain -join ' > '
        $lines.Add(('Profile "{0}"' -f (Get-XmlText $x "/*[local-name()='WLANProfile']/*[local-name()='name']")))
        $lines.Add(('  SSID: {0} | connectionType: {1} | connectionMode: {2}' -f (Get-XmlText $x "//*[local-name()='SSID']/*[local-name()='name']"), (Get-XmlText $x "//*[local-name()='connectionType']"), (Get-XmlText $x "//*[local-name()='connectionMode']")))
        $lines.Add(('  authentication: {0} | encryption: {1} | useOneX: {2} | MAC randomization: {3}' -f (Get-XmlText $x "//*[local-name()='authentication']"), (Get-XmlText $x "//*[local-name()='encryption']"), (Get-XmlText $x "//*[local-name()='useOneX']"), (Get-XmlText $x "//*[local-name()='enableRandomization']")))
        if ((Get-XmlText $x "//*[local-name()='useOneX']") -ne 'true') { $lines.Add(''); continue }
        $lines.Add(('  EAP method chain: {0}' -f $eapText))
        $lines.Add(('  server validation: DisableUserPromptForServerValidation={0} | ServerNames="{1}" | TrustedRootCA="{2}"' -f (Get-XmlText $x "//*[local-name()='DisableUserPromptForServerValidation']"), (Get-XmlText $x "//*[local-name()='ServerNames']"), (Get-XmlText $x "//*[local-name()='TrustedRootCA']")))
        $lines.Add(('  fast reconnect / cryptobinding / identity privacy: {0} / {1} / {2}' -f (Get-XmlText $x "//*[local-name()='FastReconnect']"), (Get-XmlText $x "//*[local-name()='EnableQuarantineChecks' or local-name()='CryptoBinding']"), (Get-XmlText $x "//*[local-name()='IdentityPrivacy']")))
        $lines.Add('')
    }
    if ($lines.Count -eq 0) { return '(no exported WLAN profiles)' }
    return ($lines -join "`n")
}

function Get-LlmEventExcerpt {
    param([int]$MaxLines = 450)
    if (-not $script:Timeline) { return '(no timeline available)' }
    $tl = @($script:Timeline)
    $net = '^(WLAN-AutoConfig|Wired-AutoConfig|EapHost|EapMethods|NCSI|NetworkProfile|NlaSvc|Dhcp|Diagnostics-Networking|WCM)'
    $picked = @{}
    $add = {
        param($e)
        $k = '{0}|{1}|{2}|{3}' -f $e.Time.Ticks, $e.Log, $e.Id, $e.Message.GetHashCode()
        if (-not $picked.ContainsKey($k)) { $picked[$k] = $e }
    }
    # 1) +-3 minutes around every failure (newest 10)
    $failures = @($tl | Where-Object { $_.Log -like 'WLAN-AutoConfig*' -and $_.Id -in 8002, 11002, 11006, 12013 } | Sort-Object Time -Descending | Select-Object -First 10)
    foreach ($f in $failures) {
        $from = $f.Time.AddMinutes(-3)
        $to = $f.Time.AddMinutes(3)
        $win = @($tl | Where-Object { $_.Time -ge $from -and $_.Time -le $to -and ($_.Log -match $net -or $_.LevelId -in 1, 2, 3 -or $_.Provider -match 'Power') } | Select-Object -First 80)
        foreach ($e in $win) { & $add $e }
    }
    # 2) everything network related during the capture
    $cap = $script:StartTime.AddMinutes(-1)
    foreach ($e in @($tl | Where-Object { $_.Time -ge $cap -and $_.Log -match $net } | Select-Object -First 250)) { & $add $e }
    # 3) the latest WLAN/EAP events for context
    foreach ($e in @($tl | Where-Object { $_.Log -match '^(WLAN-AutoConfig|Wired-AutoConfig|EapHost|EapMethods)' } | Sort-Object Time -Descending | Select-Object -First 120)) { & $add $e }

    $sorted = @($picked.Values | Sort-Object Time)
    if ($sorted.Count -gt $MaxLines) { $sorted = @($sorted | Select-Object -Last $MaxLines) }
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('time | log | id | level | message (long messages shortened, the reason is usually at the end)')
    foreach ($e in $sorted) {
        $m = [string]$e.Message
        if ($m.Length -gt 420) { $m = $m.Substring(0, 160) + ' ... ' + $m.Substring($m.Length - 250) }
        $out.Add(('{0:yyyy-MM-dd HH:mm:ss} | {1} | {2} | {3} | {4}' -f $e.Time, $e.Log, $e.Id, $e.Level, $m))
    }
    return ($out -join "`n")
}

function Get-LlmCaptureData {
    $out = New-Object System.Collections.Generic.List[string]
    $samples = Join-Path $script:Dir.Monitor 'wlan_interface_samples.csv'
    if ($script:LocationBlocked) {
        $out.Add('Signal/BSSID samples: NOT AVAILABLE (Windows blocked netsh wlan show interfaces: location access disabled).')
    } elseif (Test-Path -LiteralPath $samples) {
        $rows = @(Import-Csv -LiteralPath $samples)
        $out.Add('Signal/BSSID samples (time | signal % | bssid), every 5th sample plus every BSSID change:')
        $prev = $null
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if ($i % 5 -eq 0 -or ($prev -and $r.Bssid -ne $prev)) { $out.Add(('{0} | {1} | {2}' -f $r.Time, $r.SignalPercent, $r.Bssid)) }
            $prev = $r.Bssid
        }
    }
    $nb = Join-Path $script:Dir.Monitor 'wlan_neighbour_aps.log'
    if (-not $script:LocationBlocked -and (Test-Path -LiteralPath $nb)) {
        $raw = Get-Content -LiteralPath $nb -Raw -Encoding UTF8
        $blocks = @([regex]::Split($raw, '(?m)^===== ') | Where-Object { $_.Trim() })
        if ($blocks.Count -gt 0) {
            $out.Add('')
            $out.Add('Last neighbour AP scan (netsh wlan show networks mode=bssid):')
            $out.Add((Limit-Text -Text ('===== ' + $blocks[$blocks.Count - 1]) -MaxChars 9000))
        }
    }
    $link = Join-Path $script:Dir.Monitor 'adapter_link_samples.csv'
    if (Test-Path -LiteralPath $link) {
        $out.Add('')
        $out.Add('Adapter link changes (time | adapter | status | link speed), only changes of adapters that were Up at least once:')
        $rows = @(Import-Csv -LiteralPath $link)
        foreach ($g in ($rows | Group-Object Name)) {
            if (@($g.Group | Where-Object { $_.Status -eq 'Up' }).Count -eq 0) { continue }
            $prevKey = $null
            foreach ($r in $g.Group) {
                $key = '{0}|{1}' -f $r.Status, $r.LinkSpeed
                if ($key -ne $prevKey) { $out.Add(('{0} | {1} | {2} | {3}' -f $r.Time, $r.Name, $r.Status, $r.LinkSpeed)) }
                $prevKey = $key
            }
        }
    }
    $ping = Join-Path $script:Dir.Monitor 'ping.csv'
    if (Test-Path -LiteralPath $ping) {
        $rows = @(Import-Csv -LiteralPath $ping)
        $lost = @($rows | Where-Object { $_.Status -ne 'Success' })
        $out.Add('')
        $out.Add(('Ping: {0} samples, {1} lost. Lost/slow samples (time | target | status | rtt ms), max 40:' -f $rows.Count, $lost.Count))
        if ($rows.Count -eq 0) { $out.Add('(no ping target: no default gateway found, e.g. full-tunnel VPN; use -PingTarget <ip> to set one)') }
        $bad = @($rows | Where-Object { $_.Status -ne 'Success' -or ($_.RttMs -and [double]$_.RttMs -gt 100) } | Select-Object -First 40)
        foreach ($r in $bad) { $out.Add(('{0} | {1} | {2} | {3}' -f $r.Time, $r.Target, $r.Status, $r.RttMs)) }
    }
    return ($out -join "`n")
}

# Best effort: decode the ETW trace with tracerpt (built into Windows) and keep only Wi-Fi/EAP related events.
function Convert-TraceForLlm {
    $etl = @(Get-ChildItem -LiteralPath $script:Dir.Traces -Filter '*_wifi_etw.etl' -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($etl.Count -eq 0) { $script:StepSkip = 'no Wi-Fi ETW trace (ETW session was not started)'; return }
    $full = Join-Path $script:Dir.Llm 'trace_all_events.csv'
    $summary = Join-Path $script:Dir.Llm 'trace_summary.txt'
    $r = Invoke-NativeTimed -Exe 'tracerpt.exe' -Arguments @($etl[0].FullName, '-o', $full, '-of', 'CSV', '-summary', $summary, '-y') -TimeoutSec 600 -Activity 'tracerpt: decoding the ETW trace'
    if ($r.TimedOut) { $script:StepWarn = 'tracerpt timed out after 600 s'; }
    if (-not (Test-Path -LiteralPath $full)) { $script:StepWarn = 'tracerpt produced no output'; return }
    # keep only relevant lines; the full CSV (packet payload events) can be huge
    $keep = '(?i)wlan|wifi|wi-fi|nwifi|wdi|802|eap|onex|dhcp|ncsi|roam|assoc|auth|disconnect'
    $outFile = Join-Path $script:Dir.Llm 'trace_wifi_events.csv'
    $reader = New-Object IO.StreamReader($full)
    $writer = New-Object IO.StreamWriter($outFile, $false, (New-Object Text.UTF8Encoding($true)))
    $n = 0
    $kept = 0
    $perKey = @{}
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $n++
            if ($n -eq 1) { $writer.WriteLine($line); $kept++; continue }
            if ($line -notmatch $keep -or $line -match '^\s*(EventTrace|Unknown),') { continue }
            # high-volume events (e.g. WLAN-Driver Transmit, ~20000 per minute) would crowd out the rare, interesting ones
            $f = $line.Split(',')
            $key = if ($f.Count -ge 3) { ($f[0].Trim() + '|' + $f[1].Trim() + '|' + $f[2].Trim()) } else { $line }
            $c = 1 + [int]$perKey[$key]
            $perKey[$key] = $c
            if ($c -gt 20) { continue }
            if ($line.Length -gt 600) { $line = $line.Substring(0, 600) }
            $writer.WriteLine($line)
            $kept++
            if ($kept -ge 5000) { break }
            if ($n -ge 5000000) { break }
        }
    } finally { $reader.Dispose(); $writer.Dispose() }
    Remove-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if ($kept -gt 1) { $script:TraceCsv = $outFile } else { $script:StepWarn = 'trace decoded but contains no Wi-Fi events' }
}

function New-LlmReport {
    $sections = New-Object System.Collections.Generic.List[object]
    $addSection = {
        param([string]$Title, [scriptblock]$Body, [int]$MaxChars, [int]$Priority, [bool]$Code = $true)
        try { $text = [string](& $Body) } catch { $text = "(section failed: $($_.Exception.Message))" }
        $text = Limit-Text -Text $text -MaxChars $MaxChars
        $sections.Add([pscustomobject]@{ Title = $Title; Text = $text; Priority = $Priority; Code = $Code })
    }
    $d = $script:Dir
    $wifi = @(Get-WifiAdapters | Where-Object { -not $_.Hidden })

    & $addSection 'Automatic findings and statistics (Summary.txt)' { ($script:SummaryText -join "`n") } 20000 1
    & $addSection 'Wi-Fi profiles (exported XML, keys are never exported)' { Get-WlanProfileSummary } 8000 2
    & $addSection 'Event excerpt: failures +-3 min, capture window, latest Wi-Fi/EAP events' { Get-LlmEventExcerpt } 90000 1
    & $addSection 'Capture data: signal, BSSID, neighbour APs, link state, ping' { Get-LlmCaptureData } 20000 2
    if ($script:TraceCsv) {
        & $addSection 'Decoded ETW trace (Wi-Fi/EAP lines of tracerpt, max 20 per event type; payload is usually not decodable)' { Read-FileText -Path $script:TraceCsv -MaxChars 6000 } 6000 6
        & $addSection 'Trace summary (event counts per provider)' { Read-FileText -Path (Join-Path $script:Dir.Llm 'trace_summary.txt') -MaxChars 5000 } 5000 4
    }
    & $addSection 'Wireless driver capabilities (netsh wlan show drivers)' { Read-FileText -Path (Join-Path $d.Wireless 'wlan_show_drivers.txt') -MaxChars 6000 } 6000 2
    & $addSection 'WLAN settings and filters' {
        (Read-FileText -Path (Join-Path $d.Wireless 'wlan_show_settings.txt') -MaxChars 2500) + "`n`n" + (Read-FileText -Path (Join-Path $d.Wireless 'wlan_show_filters.txt') -MaxChars 2000)
    } 4500 4
    & $addSection 'Wi-Fi adapter advanced properties (roaming aggressiveness, band, power saving, ...)' {
        if ($wifi.Count -eq 0) { return '(no wireless adapter)' }
        (Get-NetAdapterAdvancedProperty -Name ($wifi | ForEach-Object { $_.Name }) -ErrorAction SilentlyContinue | Format-Table -AutoSize Name, DisplayName, DisplayValue | Out-String -Width 220)
    } 8000 2
    & $addSection 'Wi-Fi adapter power management' {
        if ($wifi.Count -eq 0) { return '(no wireless adapter)' }
        (Get-NetAdapterPowerManagement -Name ($wifi | ForEach-Object { $_.Name }) -ErrorAction SilentlyContinue | Format-List * | Out-String -Width 220)
    } 3000 4
    & $addSection 'Wi-Fi power plan settings (powercfg)' { Read-FileText -Path (Join-Path $d.System 'powercfg_wireless_adapter_settings.txt') -MaxChars 3500 } 3500 4
    & $addSection 'Network drivers' { Read-FileText -Path (Join-Path $d.System 'NetworkDrivers.txt') -MaxChars 5000 } 5000 3
    & $addSection 'Bound network components / filter drivers (netcfg -s n)' { Read-FileText -Path (Join-Path $d.Network 'netcfg_network_components.txt') -MaxChars 3500 } 3500 3
    & $addSection 'IP configuration (ipconfig /all)' { Read-FileText -Path (Join-Path $d.Network 'ipconfig_all.txt') -MaxChars 9000 } 9000 2
    & $addSection 'IPv4 routing table' {
        $t = Read-FileText -Path (Join-Path $d.Network 'route_print.txt') -MaxChars 12000
        $i = $t.IndexOf('IPv6')
        if ($i -gt 0) { $t = $t.Substring(0, $i) }
        $t
    } 4000 4
    & $addSection 'Proxy (netsh winhttp show proxy)' { Read-FileText -Path (Join-Path $d.Network 'netsh_winhttp_proxy.txt') -MaxChars 1500 } 1500 5
    & $addSection 'Time synchronisation (w32tm)' { Read-FileText -Path (Join-Path $d.System 'w32tm_status.txt') -MaxChars 2000 } 2000 4
    & $addSection 'Join state (dsregcmd, selected lines)' {
        $f = Join-Path $d.System 'dsregcmd_status.txt'
        if (-not (Test-Path -LiteralPath $f)) { return '(not available)' }
        (@(Get-Content -LiteralPath $f -Encoding UTF8) | Where-Object { $_ -match 'AzureAdJoined|DomainJoined|EnterpriseJoined|TenantName|MdmUrl|DeviceAuthStatus|WamDefaultSet|NgcSet' } | ForEach-Object { $_.Trim() }) -join "`n"
    } 3000 5
    & $addSection 'Group Policy (gpresult /R, first lines)' { Read-FileText -Path (Join-Path $d.System 'gpresult_R.txt') -MaxChars 7000 } 7000 4
    & $addSection 'Services' { Read-FileText -Path (Join-Path $d.System 'Get-Service_network_related.txt') -MaxChars 3000 } 3000 5
    & $addSection 'Collection problems (steps that are not OK)' {
        $bad = @($script:Manifest | Where-Object { $_.Status -ne 'OK' })
        if ($bad.Count -eq 0) { return 'all steps OK' }
        ($bad | ForEach-Object { '{0} | {1} | {2}' -f $_.Status, $_.Step, $_.Detail }) -join "`n"
    } 6000 1

    # budget: shrink the least important sections first until everything fits
    $budget = $LlmReportMaxKB * 1024
    $guard = 0
    while ($true) {
        $total = 0
        foreach ($sec in $sections) { $total += $sec.Text.Length }
        if ($total -le $budget -or $guard -ge 200) { break }
        $guard++
        $victim = $sections | Where-Object { $_.Text.Length -gt 1500 } | Sort-Object @{ Expression = { $_.Priority }; Descending = $true }, @{ Expression = { $_.Text.Length }; Descending = $true } | Select-Object -First 1
        if (-not $victim) { break }
        $victim.Text = Limit-Text -Text $victim.Text -MaxChars ([int]($victim.Text.Length * 0.6))
    }

    $md = New-Object System.Collections.Generic.List[string]
    $md.Add("# Wi-Fi / 802.1X troubleshooting report: $env:COMPUTERNAME")
    $md.Add('')
    $md.Add('This file was generated by Collect-WifiLogs.ps1 for analysis by a person or an LLM. It condenses the text based data of a')
    $md.Add('Windows client Wi-Fi/802.1X collection. Binary sources (.evtx, .etl, .cab, PSR) are NOT included, only their decoded excerpts.')
    $md.Add('')
    $md.Add("- Collected: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) (host local time), scenario: $Scenario, snapshot only: $SnapshotOnly, event window: $EventLogDays day(s)")
    $md.Add("- ETW trace: $($script:EtwInfo); packet capture: $($script:TraceMode)")
    $md.Add("- Location access blocked for netsh wlan: $($script:LocationBlocked) (if true, signal/BSSID/neighbour data is missing)")
    $md.Add('- Event messages are in the OS display language. WLAN-AutoConfig IDs: 8000 connect start, 8001 connected, 8002 connect failed, 8003 disconnected, 11000-11006 association/security, 12011-12014 802.1X (12012 success, 12013 failure).')
    $md.Add('')
    $md.Add('Suggested task for the analysis: identify the most likely root cause of the reported Wi-Fi problem, list the evidence with timestamps, and name the next data to collect if the evidence is insufficient.')
    $md.Add('')
    foreach ($s in $sections) {
        $md.Add("## $($s.Title)")
        $md.Add('')
        if ($s.Code) { $md.Add('```text'); $md.Add($s.Text.TrimEnd()); $md.Add('```') } else { $md.Add($s.Text) }
        $md.Add('')
    }
    $path = Join-Path $d.Llm 'llm_report.md'
    $md -join "`r`n" | Out-File -FilePath $path -Encoding utf8
    $script:LlmReportPath = $path
    $len = (Get-Item -LiteralPath $path).Length
    $script:LlmReportInfo = ('{0:N0} KB, roughly {1:N0}k tokens' -f ($len / 1KB), ($len / 3.5 / 1000))
}

# Pseudonymises the report (best effort, regex based): hostnames, users, domains, SSIDs, MACs, GUIDs, known IPs,
# thumbprints, e-mail addresses and certificate subjects. The mapping is written OUTSIDE the archive.
function New-RedactedReport {
    $text = Get-Content -LiteralPath $script:LlmReportPath -Raw -Encoding UTF8
    $map = New-Object System.Collections.Generic.List[object]
    $counters = @{}
    $known = @{}
    $token = {
        param([string]$Type, [string]$Original)
        $key = $Type + '|' + $Original.ToLowerInvariant()
        if (-not $known.ContainsKey($key)) {
            if (-not $counters.ContainsKey($Type)) { $counters[$Type] = 0 }
            $counters[$Type]++
            $known[$key] = '{0}-{1}' -f $Type, $counters[$Type]
            $map.Add([pscustomobject]@{ Type = $Type; Original = $Original; Token = $known[$key] })
        }
        return $known[$key]
    }
    $literal = {
        param([string]$Type, [string]$Value)
        if (-not $Value -or $Value.Length -lt 3) { return }
        $tok = & $token $Type $Value
        $script:__t = [regex]::Replace($script:__t, [regex]::Escape($Value), $tok, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $script:__t = $text

    # certificate subjects / DNs first (they contain names), then literals, then patterns
    $script:__t = [regex]::Replace($script:__t, '(?i)\b(?:CN|OU|DC|O|L|S|C)=[^,|\r\n]+(?:,\s*(?:CN|OU|DC|O|L|S|C)=[^,|\r\n]+)*', { param($m) & $token 'DN' $m.Value.Trim() })

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $domains = New-Object System.Collections.Generic.List[string]
    if ($cs -and $cs.PartOfDomain -and $cs.Domain) { $domains.Add([string]$cs.Domain) }
    if ($env:USERDNSDOMAIN) { $domains.Add([string]$env:USERDNSDOMAIN) }
    foreach ($dm in @($domains)) {
        # also the parent domains down to two labels (corp.example.com -> example.com)
        $labels = $dm.Split('.')
        for ($i = 1; $i -le $labels.Count - 2; $i++) { $domains.Add(($labels[$i..($labels.Count - 1)] -join '.')) }
    }
    $domains = @($domains | Select-Object -Unique | Sort-Object { $_.Length } -Descending)
    # hostnames inside these domains first (whole FQDN), then the bare domain
    foreach ($dm in $domains) {
        $script:__t = [regex]::Replace($script:__t, ('(?i)\b[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9_-]+)*\.' + [regex]::Escape($dm) + '\b'), { param($m) & $token 'FQDN' $m.Value })
    }
    foreach ($dm in $domains) { & $literal 'DOMAIN' $dm }
    & $literal 'HOST' $env:COMPUTERNAME
    & $literal 'USER' $env:USERNAME
    if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { & $literal 'NTDOMAIN' $env:USERDOMAIN }
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $script:Dir.Wireless 'WlanProfiles') -Filter '*.xml' -ErrorAction SilentlyContinue)) {
        try {
            $x = [xml](Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8)
            foreach ($n in @($x.SelectNodes("//*[local-name()='SSID']/*[local-name()='name']"))) { & $literal 'SSID' $n.InnerText }
            foreach ($n in @($x.SelectNodes("/*[local-name()='WLANProfile']/*[local-name()='name']"))) { & $literal 'PROFILE' $n.InnerText }
        } catch { Write-CollectorLog "Redaction: profile $($f.Name) not parsed" 'WARN' }
    }

    # IPv4: addresses seen in the network dumps, plus RFC1918 192.168/172.16-31 anywhere (version numbers stay untouched)
    $ipSet = @{}
    foreach ($f in @((Join-Path $script:Dir.Network 'ipconfig_all.txt'), (Join-Path $script:Dir.Network 'route_print.txt'), (Join-Path $script:Dir.Network 'arp_a.txt'), (Join-Path $script:Dir.Monitor 'ping.csv'))) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        foreach ($m in [regex]::Matches((Get-Content -LiteralPath $f -Raw -Encoding UTF8), '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d])')) {
            if ($m.Value -notmatch '^(255\.|0\.|127\.|169\.254\.)') { $ipSet[$m.Value] = $true }
        }
    }
    foreach ($ip in ($ipSet.Keys | Sort-Object { $_.Length } -Descending)) {
        $tok = & $token 'IP' $ip
        $script:__t = [regex]::Replace($script:__t, ('(?<![\d.])' + [regex]::Escape($ip) + '(?![\d])'), $tok)
    }
    $script:__t = [regex]::Replace($script:__t, '(?<![\d.])(?:192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d])', { param($m) & $token 'IP' $m.Value })

    $script:__t = [regex]::Replace($script:__t, '(?i)\b[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}\b', { param($m) & $token 'MAC' (($m.Value.ToLowerInvariant()) -replace '-', ':') })
    $script:__t = [regex]::Replace($script:__t, '(?i)\{?\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b\}?', { param($m) & $token 'GUID' ($m.Value.Trim('{', '}')) })
    $script:__t = [regex]::Replace($script:__t, '(?i)\b[0-9a-f]{40}\b', { param($m) & $token 'THUMB' $m.Value })
    $script:__t = [regex]::Replace($script:__t, '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', { param($m) & $token 'EMAIL' $m.Value })

    $redacted = Join-Path $script:Dir.Llm 'llm_report.redacted.md'
    $script:__t | Out-File -FilePath $redacted -Encoding utf8
    $script:__t = $null
    $script:RedactedPath = $redacted
    # the mapping must not end up in the archive (it would undo the redaction)
    $script:RedactionMapPath = Join-Path $OutputPath ($script:RunName + '_redaction_map.csv')
    $map | Export-Csv -Path $script:RedactionMapPath -NoTypeInformation -Encoding UTF8
}

# Zip that tolerates files still open in another process (e.g. an .etl a trace session is writing to).
# Returns the list of files that could not be added.
function New-ZipFromFolder {
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
    Add-Type -AssemblyName System.IO.Compression
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Force }
    $skipped = New-Object System.Collections.Generic.List[string]
    $root = $Source.TrimEnd('\')
    $rootName = Split-Path -Path $root -Leaf
    $zipStream = [IO.File]::Open($Destination, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite)
    $zip = $null
    try {
        $zip = New-Object IO.Compression.ZipArchive($zipStream, [IO.Compression.ZipArchiveMode]::Create)
        foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)) {
            $entryName = $rootName + '/' + $f.FullName.Substring($root.Length + 1).Replace('\', '/')
            try {
                $in = New-Object IO.FileStream($f.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                try {
                    $entry = $zip.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
                    $out = $entry.Open()
                    try { $in.CopyTo($out) } finally { $out.Dispose() }
                } finally { $in.Dispose() }
            } catch { $skipped.Add(('{0}: {1}' -f $f.FullName, $_.Exception.Message)) }
        }
    } finally {
        if ($zip) { $zip.Dispose() }
        $zipStream.Dispose()
    }
    return $skipped
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host "Wi-Fi log collector v$($script:Version) - $env:COMPUTERNAME" -ForegroundColor White
Write-Host "Output: $($script:RunDir)" -ForegroundColor White
Write-Host 'Note: the archive contains internal data (Security log, certificates, SSIDs, screenshots, packets). Wi-Fi keys are not exported.' -ForegroundColor DarkGray
Write-Host ''
Set-ConsoleQuickEdit -Enable $false
Write-CollectorLog "Started. Scenario=$Scenario SnapshotOnly=$SnapshotOnly EventLogDays=$EventLogDays PS=$($PSVersionTable.PSVersion)"

# Windows 11 24H2+ refuses 'netsh wlan show interfaces/networks' without location access (error 5)
if (Test-WifiScenario) {
    $probe = (& netsh.exe wlan show interfaces 2>&1 | ForEach-Object { "$_" }) -join "`n"
    if ($probe -match 'privacy-location') {
        $script:LocationBlocked = $true
        Write-Host '!! Windows blocks WLAN queries: "netsh wlan show interfaces" needs location access.' -ForegroundColor Yellow
        Write-Host '   Signal/BSSID sampling and the neighbour AP scan will be EMPTY until you enable:' -ForegroundColor Yellow
        Write-Host '   Settings > Privacy & security > Location > "Location services" = On' -ForegroundColor Yellow
        Write-Host '                                            > "Let desktop apps access your location" = On' -ForegroundColor Yellow
        Write-Host ''
        Write-CollectorLog 'Location access blocked for netsh wlan' 'WARN'
        if ($DurationSeconds -eq 0 -and -not $SnapshotOnly) {
            [void](Read-Host 'Press ENTER to continue anyway, or Ctrl+C to abort, enable location and start again')
        }
    }
}

try {
    if (-not $SnapshotOnly) {
        Write-Info '== Phase 1: start capture ==' 'White'
        Invoke-Step 'RAS tracing on (netsh ras set tracing * enabled)' {
            $r = Invoke-NativeTimed -Exe 'netsh.exe' -Arguments @('ras', 'set', 'tracing', '*', 'enabled') -TimeoutSec 60
            Write-CollectorLog ("netsh ras set tracing * enabled -> exit {0}, timed out {1}: {2}" -f $r.ExitCode, $r.TimedOut, ($r.Output -join ' | '))
            if ($r.TimedOut -or $r.ExitCode -ne 0) { throw ("exit code {0}, timed out: {1}: {2}" -f $r.ExitCode, $r.TimedOut, (($r.Output | Where-Object { $_.Trim() }) -join ' ')) }
            # tracing must be switched off again even if this step looks odd
            $script:State.RasTrace = $true
        }
        Invoke-Step "ETW session for Wi-Fi/EAP/DHCP providers (logman)" { Start-WifiEtwSession }
        Invoke-Step "netsh trace start (packet capture)" { Start-NetshTrace }
        Invoke-Step 'CAPI2 log on (100 MB)' { Enable-Capi2Log }
        if ($IncludePsr) { Invoke-Step 'Problem Steps Recorder start' { Start-Psr } }
        Invoke-Step 'Background samplers (signal/BSSID, ping, neighbour APs)' { Start-Monitors }

        Write-Info '' 'White'
        Write-Info '== Phase 2: reproduce ==' 'White'
        Wait-ForReproduction

        Write-Info '' 'White'
        Write-Info '== Phase 3: stop capture (netsh trace stop can take a few minutes) ==' 'White'
        if ($script:State.Psr) { Invoke-Step 'Problem Steps Recorder stop' { Stop-Psr } }
        Invoke-Step 'Stop background samplers' { Stop-Monitors }
        Invoke-Step 'CAPI2 export + restore previous log settings' { Stop-Capi2Log }
        Invoke-Step 'RAS tracing off' { Stop-RasTrace }
        if ($script:State.EtwSession) { Invoke-Step 'ETW session stop (logman)' { Stop-WifiEtwSession } }
        if ($script:State.NetshTrace) {
            Write-Host '  ... stopping netsh trace (merging the trace file, up to 20 minutes, please wait)' -ForegroundColor DarkGray
            Invoke-Step 'netsh trace stop' { Stop-NetshTrace }
        }
        Invoke-Step 'Copy RAS trace files (%SystemRoot%\Tracing)' { Copy-RasTraceFiles }
    }

    Write-Info '' 'White'
    Write-Info '== Phase 4: collect configuration and logs ==' 'White'
    Invoke-WirelessCollection
    Invoke-NetworkCollection
    Invoke-SystemCollection
    if (-not $NoCertificates) { Invoke-CertificateCollection }
    Invoke-EventLogCollection
    Invoke-TimelineCollection

    Write-Info '' 'White'
    Write-Info '== Phase 5: analysis ==' 'White'
    Invoke-Step 'Summary.txt' { $script:SummaryText = New-Summary }
    if (-not $NoLlmReport) {
        if (-not $SnapshotOnly -and -not $NoTraceConvert) { Invoke-Step 'Decode ETW trace for the LLM report (tracerpt, can take minutes)' { Convert-TraceForLlm } }
        Invoke-Step '08_LLM\llm_report.md (single file for LLM analysis)' { New-LlmReport }
        Invoke-Step '08_LLM\llm_report.redacted.md (pseudonymised copy)' { New-RedactedReport }
    }
    $script:Manifest | Export-Csv -Path (Join-Path $script:Dir.Summary 'manifest.csv') -NoTypeInformation -Encoding UTF8
}
finally {
    # Make sure nothing keeps running if the script was interrupted (Ctrl+C) or failed midway.
    if ($script:State.Jobs.Count -gt 0) { Stop-Monitors }
    if ($script:State.Psr) { & psr.exe /stop 2>&1 | Out-Null }
    if ($script:State.Capi2Prev) { try { Stop-Capi2Log } catch { Write-CollectorLog "CAPI2 cleanup failed: $_" 'WARN' } }
    if ($script:State.RasTrace) { Stop-RasTrace }
    if ($script:State.EtwSession) { try { Stop-WifiEtwSession } catch { Write-CollectorLog "ETW session cleanup failed: $_" 'WARN' } }
    if ($script:State.NetshTrace) {
        Write-Host 'Stopping netsh trace (merging trace file, please wait) ...' -ForegroundColor Yellow
        Stop-NetshTrace
    }
    Set-ConsoleQuickEdit -Enable $true
}

if ($script:SummaryText) {
    Write-Host ''
    $script:SummaryText | ForEach-Object { Write-Host $_ }
}

$zipPath = $null
if (-not $NoZip) {
    Write-Host ''
    Write-Info 'Creating archive ...' 'White'
    try {
        $zipPath = Join-Path $OutputPath ($script:RunName + '.zip')
        $skipped = @(New-ZipFromFolder -Source $script:RunDir -Destination $zipPath)
        foreach ($sk in $skipped) { Write-CollectorLog "Not added to zip: $sk" 'WARN' }
        if ($skipped.Count -gt 0) {
            Write-Info ("Archive created, but {0} file(s) could not be added (still locked, see collector.log). They remain in the folder." -f $skipped.Count) 'Yellow'
        }
    } catch {
        Write-Info "Zip creation failed: $($_.Exception.Message). The folder is complete, archive it manually." 'Red'
        $zipPath = $null
    }
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host "  Folder : $($script:RunDir)" -ForegroundColor Green
if ($zipPath) { Write-Host "  Archive: $zipPath" -ForegroundColor Green }
Write-Host "  Start with: $(Join-Path $script:Dir.Summary 'Summary.txt')" -ForegroundColor Green
if ($script:LlmReportPath) {
    Write-Host ''
    Write-Host "  LLM report         : $($script:LlmReportPath) ($($script:LlmReportInfo))" -ForegroundColor Cyan
    if ($script:RedactedPath) {
        Write-Host "  LLM report redacted: $($script:RedactedPath)" -ForegroundColor Cyan
        Write-Host "  Redaction map (keep local, NOT in the archive): $($script:RedactionMapPath)" -ForegroundColor Cyan
        Write-Host '  Redaction is best effort: review the redacted file before uploading it anywhere.' -ForegroundColor Yellow
    }
}
