# Verification Matrix

Feature × level × status × evidence. Levels: **AUTOMATED** (real sockets/TLS, CI or local run),
**SIMULATED** (mocks/fault-injection/synthetic), **REAL-DEVICE** (physical Mac ↔ physical PC).
Status: **PASSED** / **FAILED** / **NOT RUN**. Nothing is PASSED without evidence.

Legend for evidence: command output captured in this repo's build log, or CI run link (once a
remote exists). Until the repository has a GitHub remote, CI jobs are **written but NOT RUN**;
their local-equivalent commands are run and recorded here instead.

## M0 — Foundations

| Feature | Level | Status | Evidence |
|---|---|---|---|
| Environment report (OS/toolchains/disk) | — | PASSED | `docs/ENVIRONMENT.md` (detected on this machine: Win11 build 26300, .NET SDK 10.0.404, git 2.56) |
| Repository inspection (greenfield) | — | PASSED | Directory was empty at start (glob `*` → no files); recorded in ADR-008 layout |
| ADRs written (001–012) | — | PASSED | `docs/DECISIONS.md` |
| Golden vectors generated + self-test | AUTOMATED | PASSED | `python tools/gen_vectors.py` → 5 files; built-in asserts validate every case |
| Vectors current + docs mirror in sync | AUTOMATED | PASSED | `python tools/gen_vectors.py --check` → `OK: 5 vector files current; docs mirror in sync.` |
| .NET protocol conformance (pairing HKDF/HMAC, manifest digest, chunk hashes+boundaries, error table, path policy, NFC, collisions) | AUTOMATED | PASSED | `dotnet test win-receiver/WinReceiver.sln` → **11/11 passed** (local, this machine) |
| Swift sender core: same vector suite | AUTOMATED | **NOT RUN** | No Swift toolchain on Windows (ADR-010). Run: on macOS `swift test --package-path mac-sender/Core`, or push to GitHub → `macos-latest` job in `.github/workflows/ci.yml` |
| GitHub Actions CI (all 4 jobs) | AUTOMATED | **NOT RUN** | No GitHub remote yet. Steps: `git remote add origin <url> && git push -u origin main` → CI badge/link recorded here |
| Windows receiver build (Release, warnings-as-errors) | AUTOMATED | PASSED | `dotnet build win-receiver/WinReceiver.sln -c Release` → 0 warnings, 0 errors (local) |
| JSON Schemas validate sample messages | AUTOMATED | **NOT RUN** | Schema-validation test not yet implemented; planned for M1 with `JsonSchema.Net`/`ajv` in CI |
| Cross-implementation test (Swift ↔ .NET, loopback, real TLS) | AUTOMATED | **NOT RUN** | M1 deliverable; runs on `macos-latest` (Swift + .NET both available there) |
| Dependency vulnerability audit | AUTOMATED | **NOT RUN** | Wired in CI (`dotnet list package --vulnerable`); requires NuGet audit pass in M6 |

## M1 — Walking skeleton (planned rows, fill as completed)

| Feature | Level | Status | Evidence |
|---|---|---|---|
| Single-file transfer, verified SHA-256 both ends | AUTOMATED | NOT RUN | M1 |
| Folder transfer (nested, Unicode names) | AUTOMATED | NOT RUN | M1 |
| Atomic write (no partial file at final path) | AUTOMATED | NOT RUN | M1 |
| Source byte-identical before/after (invariant) | AUTOMATED | NOT RUN | M1 |
| TLS loopback with pinned test certificate | AUTOMATED | NOT RUN | M1 |

## M2–M7 (rows added as milestones start)

See `docs/SPEC.md` §10 for the required coverage; each milestone adds its rows here before exit.

## REAL-DEVICE (all stay NOT RUN until a human executes docs/REAL_DEVICE_TEST_PLAN.md)

| Feature | Level | Status | Evidence |
|---|---|---|---|
| Mac ↔ PC end-to-end over Wi-Fi | REAL-DEVICE | NOT RUN | Requires physical Mac + PC on same LAN |
| Bonjour discovery ≤5 s on home network | REAL-DEVICE | NOT RUN | M4 |
| Installer + firewall rule (Private profile) on clean Win10/11 | REAL-DEVICE | NOT RUN | M7 |
| Codesign + notarization (Apple) / signtool (Windows) | REAL-DEVICE | NOT RUN | Requires Developer ID + code-signing cert; pipelines are scripted with placeholders |
| exFAT/FAT32 destination behavior | REAL-DEVICE | NOT RUN | Requires a formatted test volume |
| 4 GiB±1 boundary files, >10 GB large-data run | SIMULATED/AUTOMATED | NOT RUN | Requires free disk (E: has 144 GB) — generated data is never committed |
| iperf3 LAN baseline + 85–90% link budget | REAL-DEVICE | NOT RUN | M5; needs iperf3 + second machine |

## How to re-run everything locally (Windows)

```powershell
python tools/gen_vectors.py --check
dotnet build win-receiver/WinReceiver.sln -c Release
dotnet test  win-receiver/WinReceiver.sln -c Release
```

On macOS (human or CI):

```bash
python3 tools/gen_vectors.py --check
dotnet test win-receiver/WinReceiver.sln -c Release
swift test --package-path mac-sender/Core
```
