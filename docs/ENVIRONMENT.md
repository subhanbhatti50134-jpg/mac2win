# Environment Report (M0)

Detected at project start. Re-run instructions at the bottom.

## Host

| Item | Value |
|---|---|
| OS | Windows 11 Pro, build 26300 (version 24H2/25xx era, "WindowsVersion 2009") |
| Architecture | x64 (assumed; verified by `dotnet --info` after SDK install) |
| Shell | PowerShell |
| Free disk | C: 48 GB, E: 144.8 GB (project drive) |
| Network | Local LAN + internet (winget reachable) |

## Toolchains

| Tool | Status | Notes |
|---|---|---|
| git 2.56.0.windows.4 | ✅ installed | repo initialized at project root |
| winget 1.29.380 | ✅ installed | used to install SDKs |
| .NET 10 SDK | 🔄 installing via `winget install Microsoft.DotNet.SDK.10` | required for win-receiver |
| .NET 11 SDK | available in feed, **not** used | spec targets .NET 10 |
| Swift / Xcode | ❌ not installed, **cannot be used on Windows** | Network.framework, SwiftUI, CryptoKit are Apple-only; Swift sender builds/tests run on macOS (CI or a real Mac) |
| Python 3 (Anaconda) | ✅ installed | used only for tooling (golden-vector generator, PDF text extraction) |
| iperf3 | ❌ not installed | needed for M5 link-capacity baseline (NOT RUN until installed) |

## What can run locally vs. only in CI

| Work | Local (Windows 11) | CI |
|---|---|---|
| .NET receiver core build/unit/integration tests (net10.0, loopback, real TLS) | ✅ yes | windows-latest, macos-latest, ubuntu-latest |
| Protocol golden-vector conformance (JSON Schemas + hash vectors) | ✅ yes (Python check + .NET tests) | ubuntu-latest |
| Chaos/fault-injection proxy tests (in-process) | ✅ yes | all three |
| Swift sender core build/tests | ❌ no | macos-latest |
| Cross-implementation test (real Swift sender ↔ real .NET receiver, loopback TLS) | ❌ no | macos-latest (Swift runs, .NET core runs there too) |
| SwiftUI app build, XCUITest | ❌ no | macos-latest (unsigned) |
| WinUI/WPF app build | ✅ yes | windows-latest |
| Installer build (Inno Setup) | ✅ yes (script in repo) | windows-latest |
| Apple codesign / notarization | ❌ no Apple identity | NOT RUN — scripted pipeline with placeholders |
| Windows code signing | ❌ no certificate | NOT RUN — scripted pipeline with placeholders |
| Real Mac ↔ real Windows device test | ❌ single Windows machine | NOT RUN — docs/REAL_DEVICE_TEST_PLAN.md |
| exFAT/FAT32 destination tests | ⚠️ only if a spare volume is formatted | NOT RUN until a volume is available |

## Consequences for verification strategy

1. Everything .NET is verified here locally **and** in CI; every result is labeled AUTOMATED.
2. Swift and cross-implementation results are NOT RUN locally. They are covered by the CI `macos` and `cross-impl` jobs, which run on every push to `master` (the repository is public at github.com/subhanbhatti50134-jpg/mac2win); the exact commands are recorded in docs/VERIFICATION.md.
3. No result is ever reported as PASSED without a command/log/CI link as evidence.

## Repository inspection (SPEC §1.3)

The project directory `E:\Projects\Mac2Win` contained **no files** at start (glob `*` returned
nothing) → greenfield per SPEC §1.3; nothing was overwritten. The repo was also not yet a git
repository → `git init` performed as part of M0.

## Re-detect (human or agent)

```powershell
Get-ComputerInfo -Property OsName,OsBuildNumber
git --version
dotnet --list-sdks
swift --version            # expect: not found on Windows
Get-PSDrive C,E | Select Name,@{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}}
iperf3 --version           # M5 baseline
```
