# Windows Wifi Log Collector

Single PowerShell script (`Collect-WifiLogs.ps1`) that collects logs, traces
and configuration to troubleshoot Wi-Fi and wired 802.1X problems on a
Windows host, following Microsoft's 802.1X data collection guide, and writes
an automatic first-pass analysis plus an LLM-friendly report. I use it as a
network engineer on customer machines. Public repo.

Follows the SG303 baseline v2 (`sgstack/global/AGENTS.md`,
`sgstack/baseline/tools.md`). If you cannot read those: work on a branch,
open a PR, merge only with green checks (squash); never commit secrets or
personal data; English for everything in the repo; talk to me in German.

## Commands

- Lint: PSScriptAnalyzer as in `.github/workflows/ci.yml` (needs PowerShell
  7.4.6+; on this host via Docker:
  `docker run --rm -v "$PWD":/w:ro -w /w mcr.microsoft.com/powershell:7.5-ubuntu-24.04 pwsh -c "Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; Invoke-ScriptAnalyzer -Path . -Recurse"`).
- Run: only on a Windows host, elevated:
  `powershell.exe -ExecutionPolicy Bypass -File .\Collect-WifiLogs.ps1`.
  It cannot be run or tested on this Linux host; say so instead of claiming
  a test.

## Release

No releases or tags; users download the script from `main`.

## Conventions

- Target Windows PowerShell 5.1 first (PowerShell 7 should work). No external
  modules or downloads; only tools shipped with Windows.
- Keep the script ASCII-only: Windows PowerShell 5.1 reads BOM-less files as
  ANSI, so non-ASCII characters break.
- Every temporary system change (RAS tracing, CAPI2 log, trace sessions) must
  be restored afterwards, also on errors and Ctrl+C.
- Never export Wi-Fi keys (`key=clear`). The redaction map is written next to
  the archive, never into it.
- Output folder layout and file names are documented in the README; keep both
  in sync.
- Verified on Windows 11 Enterprise (German UI) only; other languages and the
  wired path are best effort. Parse output language-independently where
  possible.

## Deviations from baseline

- none
