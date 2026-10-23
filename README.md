<img src="assets/icon.svg" width="64" height="64" alt="">

# Windows Wifi Log Collector

Single PowerShell script that gathers everything needed to troubleshoot Wi-Fi (and wired 802.1X) problems on a
Windows host. It follows Microsoft's
[Data collection for troubleshooting 802.1X authentication issues](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/data-collection-for-troubleshooting-802-1x-authentication-issues)
and adds Wi-Fi specific sources and an automatic first-pass analysis.

Created in [T3 Code](https://t3.codes).

## Requirements

- Windows 10/11 or Windows Server with Windows PowerShell 5.1 (PowerShell 7 should work), run **as administrator**.
- No external modules or downloads; only tools shipped with Windows (`netsh`, `logman`, `tracerpt`, `wevtutil`, `certutil`, ...).
- Developed and verified on Windows 11 Enterprise (build 26200, German UI, Intel AX201). Other Windows versions and
  UI languages, and the wired (`-Scenario Wired`) path, are best effort and not yet verified on real hardware. Issues
  and pull requests with findings from other environments are welcome.

## Usage

Run in an **elevated** Windows PowerShell 5.1 (or PowerShell 7) on the affected host:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Collect-WifiLogs.ps1
```

1. The script starts the traces, then asks you to reproduce the problem (toggle Wi-Fi, reconnect, walk around).
2. Press **ENTER** to stop. Stopping `netsh trace` can take a few minutes.
3. Static data and event logs are collected, `Summary.txt` is generated and everything is zipped to
   `C:\MSLOG\<COMPUTERNAME>_<timestamp>.zip`.

| Parameter | Purpose |
| --- | --- |
| `-DurationSeconds 600` | Capture for a fixed time instead of waiting for ENTER (unattended / remote) |
| `-SnapshotOnly` | No live capture, only current state + historical event logs (problem not reproducible on demand) |
| `-Scenario Wired` | Trace the `lan` scenario (Ethernet 802.1X) instead of `wlan` |
| `-PingTarget 10.0.0.1,8.8.8.8` | Extra ping targets next to the default gateway |
| `-EventLogDays 7` | Limit exported events to the last N days (`0` = complete logs) |
| `-OutputPath`, `-MaxTraceSizeMB`, `-MaxScreenshots` | Output folder (default `C:\MSLOG`), trace size, PSR screenshots |
| `-IncludeMsinfo` | Also run `msinfo32 /report` (opt-in, takes ~6 minutes) |
| `-IncludePsr` | Also run the Problem Steps Recorder (opt-in: `psr.exe` was removed in Windows 11 24H2) |
| `-NoPacketCapture`, `-NoCertificates`, `-NoSecurityLog`, `-NoZip`, `-NoLlmReport`, `-NoTraceConvert` | Skip parts |
| `-Force` | Stop an already running `netsh trace` session that blocks the new one |

## What is collected

From Microsoft's article: RAS tracing (`netsh ras set tracing`), `netsh trace` WLAN/LAN scenario with packet
capture, CAPI2 log (enabled for the run, exported, previous settings restored, log is never cleared), Problem Steps
Recorder, `gpresult`, `msinfo32`, `ipconfig`, `route print`, Application/System/Security/GroupPolicy/WLAN-/Wired-AutoConfig/
certificate-related event logs, all `certutil` certificate store dumps, `netsh wlan|lan show/export`, `%SystemRoot%\Tracing`.

Additions: WLAN report (HTML), EapHost/EAP-method, NCSI, NLA, WCM, DHCP, DNS, NDIS, Entra/MDM logs, adapter and
advanced driver properties (power saving, roaming aggressiveness, ...), driver versions, bound network components /
filter drivers, power settings, services, hotfixes, installed software, time sync, Entra join state, registry
exports, signal/BSSID sampling every 2 s, gateway ping, neighbouring AP scan every 15 s, a merged event timeline
(`event_timeline.csv`) and `Summary.txt` with automatic findings (failed associations/authentications, expired
client-auth certificates, weak signal, roaming count, packet loss, stale drivers, adapter power saving, stopped services).

## LLM analysis

Binary formats (`.evtx`, `.etl`, `.cab`, PSR) cannot be read by an LLM. The script therefore writes
`08_LLM\llm_report.md`: one Markdown file with the findings, Wi-Fi profile summary (EAP chain, server validation),
event excerpts around every failure, signal/BSSID/link/ping data, driver and adapter settings, IP config, join state,
GPO and the Wi-Fi related lines of the decoded ETW trace (`tracerpt`). Size budget: `-LlmReportMaxKB` (default 300 KB,
~85k tokens), least important sections are shortened first.

`08_LLM\llm_report.redacted.md` is a pseudonymised copy (host, user, domains, SSIDs, MACs, GUIDs, known IPs, thumbprints,
e-mail addresses, certificate subjects). The mapping `<run>_redaction_map.csv` is written **next to** the archive, never
into it. Redaction is regex based and best effort: review the file before uploading it to any external service and
check your company policy first. Skip with `-NoLlmReport`, skip trace decoding with `-NoTraceConvert`.

## Windows 11 notes

- **Location access:** since Windows 11 24H2 `netsh wlan show interfaces|networks` fails with error 5 unless
  *Settings > Privacy & security > Location > Location services* and *Let desktop apps access your location* are on.
  The script detects this, warns before the capture and reports it in `Summary.txt`. Without it, signal/BSSID and
  neighbour AP data are empty (link state sampling via `Get-NetAdapter` still works).
- **Traces:** Windows 11 24H2+ has no WLAN scenario in `netsh trace`, and enabling many providers in one `netsh trace`
  call fails as a whole (error 5) if one is protected. The script therefore runs two independent captures:
  a `logman` ETW session `WifiLogCollector` (WLAN-AutoConfig, NWiFi, OneX, EapHost, DHCP, NCSI, ... providers; a denied
  provider is skipped and reported) writing `01_Traces\<host>_wifi_etw.etl`, plus a `netsh trace` NDIS packet capture
  (or the Wi-Fi scenario if the build has one). `netsh_trace_show_scenarios.txt` and `netsh_trace_show_providers.txt`
  document what the build offers. If a foreign `netsh trace` session is running the script stops with a clear message
  (`-Force` stops it).
- **Hangs:** external commands run with a time limit and file-redirected output (a pipe can block forever when a
  helper process keeps it open, as seen with `netsh trace stop`). `netsh trace stop` may take up to 20 minutes.

## Privacy

The archive contains internal data (computer/user names, SSIDs, RADIUS/EAP settings, certificates, Security log,
screenshots, packets). Wi-Fi pre-shared keys are not exported (`key=clear` is never used).

## Output layout

```
<COMPUTERNAME>_<timestamp>/
  00_Summary/        Summary.txt, event_timeline.csv, manifest.csv
  01_Traces/         netsh trace .etl/.cab, CAPI2 .evtx, PSR zip, RAS traces
  02_EventLogs/      .evtx exports
  03_Wireless/       netsh wlan/lan output, WLAN report, exported profiles
  04_Network/        IP config, routes, adapter settings
  05_System/         systeminfo, GPO report, drivers, services, registry
  06_Certificates/   certutil dumps, personal certificate summary
  07_Monitor/        signal/BSSID samples, ping.csv, neighbour APs
  collector.log
```

## License

[MIT](LICENSE). The script is provided as is, without warranty. It changes system state temporarily (RAS tracing,
CAPI2 log, trace sessions) and restores it afterwards, but you run it at your own risk.
