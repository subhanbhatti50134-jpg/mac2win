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
| ADRs written (001–014) | — | PASSED | `docs/DECISIONS.md` (001–012 at M0; 013–014 added during M1) |
| Golden vectors generated + self-test | AUTOMATED | PASSED | `python tools/gen_vectors.py` → 5 files; built-in asserts validate every case |
| Vectors current + docs mirror in sync | AUTOMATED | PASSED | `python tools/gen_vectors.py --check` → `OK: 5 vector files current; docs mirror in sync.` |
| .NET protocol conformance (pairing HKDF/HMAC, manifest digest, chunk hashes+boundaries, error table, path policy, NFC, collisions) | AUTOMATED | PASSED | `dotnet test win-receiver/WinReceiver.sln` → **11/11 passed** (local, this machine) |
| Swift sender core: same vector suite | AUTOMATED | **NOT RUN** | No Swift toolchain on Windows (ADR-010). Run: on macOS `swift test --package-path mac-sender/Core`, or push to GitHub → `macos-latest` job in `.github/workflows/ci.yml` |
| GitHub Actions CI (all 4 jobs) | AUTOMATED | **NOT RUN** | No GitHub remote yet. Steps: `git remote add origin <url> && git push -u origin main` → CI badge/link recorded here |
| Windows receiver build (Release, warnings-as-errors) | AUTOMATED | PASSED | `dotnet build win-receiver/WinReceiver.sln -c Release` → 0 warnings, 0 errors (local) |
| JSON Schemas validate sample messages | AUTOMATED | **NOT RUN** | Schema-validation test not yet implemented; planned for M1 with `JsonSchema.Net`/`ajv` in CI |
| Cross-implementation test (Swift ↔ .NET, loopback, real TLS) | AUTOMATED | **NOT RUN** | M1 deliverable; runs on `macos-latest` (Swift + .NET both available there) |
| Dependency vulnerability audit | AUTOMATED | **NOT RUN** | Wired in CI (`dotnet list package --vulnerable`); requires NuGet audit pass in M6 |

## M1 — Walking skeleton (receiver core + protocol integration)

All rows below are from `dotnet test win-receiver/WinReceiver.sln -c Release` on this machine,
2026-11-18: **40/40 passed** (11 M0 vector tests + 29 M1 integration tests), 0 build warnings.

| Feature | Level | Status | Evidence |
|---|---|---|---|
| Single-file transfer, verified SHA-256 both ends | AUTOMATED | PASSED | `TransferTests.SingleFile_TransfersAndVerifiesSha256` (5 MiB + 123 B, multi-chunk); on-disk hash == source, ledger `BytesVerified` == payload length |
| Boundary sizes 0 / 1 / chunk−1 / chunk / chunk+1 / 3·chunk+7 | AUTOMATED | PASSED | `TransferTests.BoundarySizes_ZeroOneChunkMinusOneChunkChunkPlus1_AllVerify` (6 sizes, each its own session) |
| Folder transfer (nested, Unicode: NFC/NFD/emoji/RTL/CJK/reserved/trailing-dot/case-collision) | AUTOMATED | PASSED | `TransferTests.FolderTransfer_UnicodeAndSpecialNames_PreservesBytes`: 12 files + 8 dirs; asserts `CON_.txt`, `trailing`, `README (2).txt`, NFD does not survive on disk |
| Atomic write (no `*.m2wpart` at any final path) | AUTOMATED | PASSED | `AssertTransferInvariants` runs after every completed/cancelled transfer: `Directory.GetFiles(dst, "*.m2wpart", AllDirectories)` is empty |
| Source byte-identical before/after (invariant) | AUTOMATED | PASSED | `AssertTransferInvariants` re-hashes every source file against its recorded bytes after each transfer |
| Ledger totals reconcile (exactly one terminal outcome per item) | AUTOMATED | PASSED | `AssertTransferInvariants`: `Σ(outcomes) == Totals.Items == report.Items.Count` on every report |
| Multi-batch manifest beyond the 1000-entry cap | AUTOMATED | PASSED | `MultiBatchManifest_BeyondEntryCap_TransfersAll` (1010 files, batch 0 + final batch 1, digest over all batches) |
| Resume: state reports verified chunks, re-upload idempotent | AUTOMATED | PASSED | `Resume_StateReportsVerifiedChunks_AndReuploadIsIdempotent`: `verifiedChunks [0,1]`, `nextChunk 2`, boundary re-upload → `ALREADY_VERIFIED` |
| Pause rejects chunks (409 `E_SESSION_STATE`), resume accepts | AUTOMATED | PASSED | `Pause_RejectsChunks_ResumeAccepts` |
| Cancel keeps verified files, purges staging, one FAILED outcome | AUTOMATED | PASSED | `Cancel_KeepsVerifiedFiles_PurgesIncompleteStaging` |
| `E_SOURCE_CHANGED` on size mismatch, ledger `CHANGED_DURING_TRANSFER` | AUTOMATED | PASSED | `SourceSizeChange_ReturnsE_SOURCE_CHANGED_AndFlagsLedger` (409) |
| Conflicts: unresolved → 409 before bytes; KEEP_BOTH rename; REPLACE | AUTOMATED | PASSED | `Conflict_WithoutResolution_IsRejectedBeforeAnyBytes` (existing bytes untouched), `Conflict_KeepBoth_RenamesAndPreservesOriginal`, `Conflict_Replace_OverwritesOnlyAfterVerification` |
| Symlinks + Apple metadata excluded by policy, ledger reconciles | AUTOMATED | PASSED | `SymlinkAndAppleMetadata_AreExcludedByPolicy_LedgerReconciles`: 3× `EXCLUDED_BY_POLICY` (`POLICY_SYMLINK_NOT_PRESERVED`, `POLICY_DOT_DS_STORE`), excluded bytes never appear in destination |
| Verify-after-write OFF still matches declared hash | AUTOMATED | PASSED | `VerifyAfterWriteDisabled_StillMatchesDeclaredHash` |
| Sender-declared UNREADABLE / CLOUD_PLACEHOLDER never transfer | AUTOMATED | PASSED | `SenderDeclaredUnreadable_NeverTransfers` (ledger 1 verified / 1 unreadable / 1 cloud-placeholder) |
| TLS loopback with pinned test certificate (real Kestrel + `SslStream`) | AUTOMATED | PASSED | Every integration test uses pinned-fingerprint client; `CertificatePinMismatch_IsRejectedByTheClient` proves a wrong pin fails the handshake |
| Wrong PIN → 403 `E_PIN_INVALID`; 5 failures → 429 `E_PIN_LOCKED` + backoff | AUTOMATED | PASSED | `WrongPin_ReturnsE_PIN_INVALID`, `FiveFailedAttempts_ThenE_PIN_LOCKED` (correct PIN also refused during lockout) |
| Anonymous health, no auth, exposes pinned fingerprint | AUTOMATED | PASSED | `Health_RequiresNoAuth_AndAdvertisesPinnedFingerprint` |
| Bearer required (401), session-token scoping, unknown session 404 | AUTOMATED | PASSED | `MissingBearer_Returns401E_UNAUTHORIZED`, `SessionEndpoints_RequireSessionToken_NotDeviceToken`, `UnknownSession_Returns404E_SESSION_NOT_FOUND` |
| Safe default: no approval handler ⇒ every session DENIED (SPEC §7) | AUTOMATED | PASSED | `ApprovalHandlerMissing_SessionIsDenied` |
| Hostile paths (traversal ×2, rooted, drive letter, UNC) rejected, nothing escapes destination | AUTOMATED | PASSED | `PathTraversalManifest_IsRejected_AndNothingIsWrittenOutsideDestination`: 5× `FAILED/E_PATH_REJECTED` + leak checks above/below destination |
| Deep path (40 segments) stays inside destination | AUTOMATED | PASSED | `DeeplyNestedPath_IsStillInsideDestination` (final path prefix-checked) |
| Insufficient storage → 507 at confirm | AUTOMATED | PASSED | `InsufficientStorage_FailsConfirmWith507` (fake destination, 10 B free) |
| FAT32 4 GiB predicted at preflight, 413 `E_LIMIT_EXCEEDED` at confirm | AUTOMATED | PASSED | `Fat32Destination_FailsPreflightForFilesOver4GiB` (`P_FAT32_4GB` before any byte moves) |
| Out-of-order manifest batch → 400; digest mismatch → 400 | AUTOMATED | PASSED | `OutOfOrderManifestBatch_IsRejected`, `ManifestDigestMismatch_IsRejected` |
| Corrupted chunk hash → 422 `E_CHUNK_HASH_MISMATCH`, retry succeeds | AUTOMATED | PASSED | `CorruptedChunkHash_IsRejected_AndNothingPersisted` (no `.m2wpart` persisted for the bad chunk) |
| Windows receiver build (Release, warnings-as-errors) | AUTOMATED | PASSED | `dotnet build win-receiver/WinReceiver.sln -c Release` → 0 warnings, 0 errors (local, 2026-11-18) |
| Cross-implementation test (Swift ↔ .NET, loopback, real TLS) | AUTOMATED | **NOT RUN** | `CrossImplTransferTests.testEndToEndTransferVerifiesAgainstDotNetReceiver`: full flow (pin → pair → hello → 2-batch manifest → confirm → chunk PUTs → commit → complete) with on-disk/source-identity/ledger invariants; harness `ReceiverHost --auto-approve --pin`; job `cross-impl` added to ci.yml. Not runnable locally (ADR-010, no macOS toolchain); no remote → CI **NOT RUN** |
| GitHub Actions CI (all 5 jobs) | AUTOMATED | **NOT RUN** | No GitHub remote yet |

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
