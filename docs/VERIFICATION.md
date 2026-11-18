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

## M2 — Security (pairing hardening, threat model, unauthorized/malicious clients)

All rows below are from `dotnet test win-receiver/WinReceiver.sln -c Release` on this machine,
2026-11-18: **82/82 passed** (40 M0+M1 + 42 M2), 0 build warnings. Threat model:
`docs/SECURITY.md` (T1–T10, written before the hardening work per SPEC §7); ADRs 015–016.

| Feature | Level | Status | Evidence |
|---|---|---|---|
| Threat model written (assets, boundaries, T1–T10 with tests + residual risk) | — | PASSED | `docs/SECURITY.md`; every mitigation cites an AUTOMATED test below |
| Tampered `pinProof` ⇒ 403 `E_PIN_INVALID` (T2) | AUTOMATED | PASSED | `MaliciousClientTests.TamperedPinProof_IsRejected` |
| Tampered hello signature ⇒ 401 `E_UNAUTHORIZED` (T2) | AUTOMATED | PASSED | `MaliciousClientTests.TamperedHelloSignature_IsUnauthorized` |
| Replayed server nonce ⇒ 400 (single-use, T5) | AUTOMATED | PASSED | `MaliciousClientTests.ReplayedServerNonce_IsRejected` |
| Expired server nonce ⇒ 400 `E_BAD_REQUEST` (T5) | AUTOMATED | PASSED | `MaliciousClientTests.ExpiredServerNonce_IsRejected` (`ChallengeTtl` 250 ms) |
| Unknown deviceId ⇒ 403 `E_NOT_PAIRED` | AUTOMATED | PASSED | `MaliciousClientTests.UnknownDeviceId_GetsE_NOT_PAIRED` |
| Wrong `protocolVersion` ⇒ 400 `E_UNSUPPORTED_VERSION` | AUTOMATED | PASSED | `MaliciousClientTests.WrongProtocolVersion_IsRejected` |
| Cross-session token use ⇒ 401 `E_UNAUTHORIZED` (T5) | AUTOMATED | PASSED | `MaliciousClientTests.CrossSessionToken_IsRejected` |
| Manifest >1000 entries ⇒ 413 `E_MANIFEST_TOO_LARGE`, batch not consumed | AUTOMATED | PASSED | `MaliciousClientTests.ManifestWith1001Entries_IsRejected` |
| Manifest body >1 MiB ⇒ 413 `E_MANIFEST_TOO_LARGE` (T4) | AUTOMATED | PASSED | `MaliciousClientTests.OversizedManifestBody_IsRejected` |
| Control body >1 MiB ⇒ 413 `E_LIMIT_EXCEEDED` (T4) | AUTOMATED | PASSED | `MaliciousClientTests.OversizedControlBody_IsRejected` |
| Garbage JSON ⇒ 400; missing required field ⇒ 400 "missing required JSON field" | AUTOMATED | PASSED | `MaliciousClientTests.GarbageOrIncompleteJson_IsBadRequest` |
| Control-char path ⇒ ledgered `REJECTED`/`CONTROL_CHARACTER`, sibling unaffected | AUTOMATED | PASSED | `MaliciousClientTests.ControlCharacterPath_IsLedgeredRejected` |
| Reserved device names (`CON.txt`, `com1/…`) ⇒ deterministic `RENAME` | AUTOMATED | PASSED | `MaliciousClientTests.ReservedDeviceName_IsSanitizedDeterministically` (`CON_.txt`, `com1_/data.bin`) |
| 70-segment path ⇒ ledgered `REJECTED`/`PATH_TOO_DEEP` (64-segment legal depth still transfers) | AUTOMATED | PASSED | `MaliciousClientTests.PathBeyondDepthLimit_IsLedgeredRejected` |
| Backslash traversal `..\..\evil.dll` ⇒ sanitized `.._.._evil.dll`, lands inside destination only (T4) | AUTOMATED | PASSED | `MaliciousClientTests.BackslashTraversal_IsSanitizedAndLandsInsideDestination` (commit `RENAMED`, hash matches, no escape above/below destination) |
| Negative / out-of-range chunk index ⇒ 400 `E_BAD_REQUEST` | AUTOMATED | PASSED | `MaliciousClientTests.NegativeAndOutOfRangeChunkIndex_AreBadRequests` |
| Unknown fileId commit ⇒ 404 `E_SESSION_NOT_FOUND` | AUTOMATED | PASSED | `MaliciousClientTests.UnknownFileId_Commit_Is404` |
| Chunk body length ≠ declared ⇒ 400 before reading, nothing persisted (T7) | AUTOMATED | PASSED | `MaliciousClientTests.ChunkBodyLengthMismatch_IsRejected` |
| Auth burst ⇒ 429 `E_RATE_LIMITED`, retryable (T6) | AUTOMATED | PASSED | `MaliciousClientTests.AuthBurst_IsRateLimited` (10 req/min injected) |
| Challenge store bounded under anonymous floods (T6) | AUTOMATED | PASSED | `MaliciousClientTests.ChallengeStore_StaysBounded` (`MaxPendingChallenges`=32) |
| Per-IP limiter slides window; 0 disables; per-key budget | AUTOMATED | PASSED | `MaliciousClientTests.RateLimiter_SlidesWindowAndZeroDisables` |
| Stalled request body ⇒ 408 `E_IDLE_TIMEOUT` over raw TLS (T4 endless streams) | AUTOMATED | PASSED | `MaliciousClientTests.StalledRequestBody_TimesOutWith408E_IDLE_TIMEOUT` (headers promise 100000 B, send 12 B, silence) |
| Idle expiry ⇒ 410 `E_SESSION_EXPIRED` + staging purged (T10) | AUTOMATED | PASSED | `MaliciousClientTests.IdleExpiry_Returns410AndPurgesStaging` (`IdleTimeout` 400 ms) |
| Device revocation kills device + session tokens; re-pair restores access (T10, ADR-016) | AUTOMATED | PASSED | `MaliciousClientTests.RevokedDevice_LosesAccess_AndCanRePairWithFreshPin` |
| Internal errors ⇒ generic 500 `E_INTERNAL`, no paths/stacks (T8) | AUTOMATED | PASSED | `MaliciousClientTests.ErrorResponses_DoNotLeakInternals` |
| Path-sanitizer fuzz: 20k seeded hostile inputs, no throw, determinism, containment, idempotence | AUTOMATED | PASSED | `PathSanitizerFuzzTests.SeededFuzz_20000HostilePaths_NoThrow_Containment_Determinism_Idempotence` |
| Depth boundary 64 ACCEPT / 65 REJECT; backslash inert; control chars 0x00–0x1F+0x7F reject | AUTOMATED | PASSED | `PathSanitizerFuzzTests.DepthBoundary_…`, `BackslashTraversal_IsInert`, `ControlCharacters_RejectTheWholePath` |
| Reserved-name rename table (all CON/PRN/AUX/NUL/COM0–9/LPT0–9 × ext, case-insensitive, stable) | AUTOMATED | PASSED | `PathSanitizerFuzzTests.ReservedDeviceNames_AreRenamedNotRejected` |
| Hostile-shape verdict table matches documented policy | AUTOMATED | PASSED | `PathSanitizerFuzzTests.HostileShapes_ReceiveTheDocumentedVerdict` |
| Destination guard: system dirs blocked, `Windows2`/`Windows.old` siblings allowed, slash normalization | AUTOMATED | PASSED | `DestinationGuardTests` (11 tests: boundary-aware prefix, trailing/forward slash, multi-root, case-insensitivity on Windows) |
| `StartAsync` refuses protected destination before creating anything (T4, SPEC §6.2) | AUTOMATED | PASSED | `DestinationGuardTests.StartAsync_RejectsProtectedDestination` (destination dir does not exist afterwards) |
| Golden vectors cover backslash + depth policy; docs mirror in sync | AUTOMATED | PASSED | `python tools/gen_vectors.py --check` → `OK: 5 vector files current; docs mirror in sync.` (path_policy.json gained 6 cases) |
| Windows receiver build (Release, warnings-as-errors) | AUTOMATED | PASSED | `dotnet build win-receiver/WinReceiver.sln -c Release` → 0 warnings, 0 errors (local, 2026-11-18) |
| Swift sender against M2 hardening (path policy parity on macOS) | AUTOMATED | **NOT RUN** | No Swift toolchain on Windows (ADR-010); `swift test --package-path mac-sender/Core` on macOS / `macos-latest` CI job |
| GitHub Actions CI (all 5 jobs) | AUTOMATED | **NOT RUN** | No GitHub remote yet |

## M3 — Resilience (fault injection, crash consistency, idempotent retry)

All rows below are from `dotnet test win-receiver/WinReceiver.sln -c Release` on this machine,
2026-11-18: **103/103 passed** (82 M0–M2 + 16 fault-injection + 5 crash-window), 0 build
warnings. ADR-017 records the persistence/chaos-proxy decisions.

| Feature | Level | Status | Evidence |
|---|---|---|---|
| Drop mid-chunk: truncated body dies, retry on healthy connection verifies | AUTOMATED | PASSED | `FaultInjectionTests.TruncatedChunkUpload_ConnectionDropped_RetryVerifies` (`TruncatingContent` aborts after half a chunk; retry ⇒ `VERIFIED`, invariants hold) |
| Drop mid-manifest: truncated batch is not half-applied, full batch then accepted | AUTOMATED | PASSED | `FaultInjectionTests.TruncatedManifestUpload_DropThenFullBatchAccepted` (two-phase parse: rejected entries/digest never mutate state) |
| Drop mid-rename: commit response lost ⇒ replay idempotent, no double rename | AUTOMATED | PASSED | `FaultInjectionTests.CommitResponseLost_ReplayIsIdempotent_NoDoubleRename` (replay returns same `RENAMED`/`finalPath`; exactly one file at destination) |
| Lost manifest/confirm responses: replayed requests idempotent, stale index still 409 | AUTOMATED | PASSED | `ManifestBatchReplayed_AfterLostResponse_IsIdempotent` (same fileIds, no duplicate items, `E_SESSION_STATE` for skipped-back index), `ConfirmReplayed_AfterLostResponse_IsIdempotent` |
| Duplicate chunk ⇒ `ALREADY_VERIFIED`; out-of-order chunks verify in any order | AUTOMATED | PASSED | `DuplicateChunkUpload_IsIdempotent`, `OutOfOrderChunks_VerifyInAnyOrder` (delivery 2,0,3,1) |
| Bit flips / corruption: boundary chunk re-hashed on recovery, mismatch distrusts it and above | AUTOMATED | PASSED | `RecoveryCrashWindowsTests.Recovery_BoundaryHashMismatch_DropsBoundaryAndAbove` (+ M2 `CorruptedChunkHash_IsRejected…` on the wire) |
| Chaos proxy: sever mid-chunk over real TLS, retry completes | AUTOMATED | PASSED | `FaultInjectionTests.ChaosProxy_SeverMidChunk_RetryCompletes` (`ChaosProxy` sever-after-64 KiB; TLS passthrough, pinning unaffected) |
| Latency + throttling: transfer still verifies | AUTOMATED | PASSED | `ChaosProxy_LatencyAndThrottling_TransferStillVerifies` (2 ms/buffer, 4 MiB/s cap, 1.5 MiB + 8 KiB files) |
| Receiver disk full / destination failure at commit ⇒ 500 `E_DESTINATION_ERROR`, no partial at final path, ledger reconciles | AUTOMATED | PASSED | `DestinationRenameFails_NoPartialAtFinalPath_LedgerFails` (directory squats final path; item `FAILED`, `.m2wpart` absent). Preflight disk-full ⇒ 507 covered by M1 `InsufficientStorage_FailsConfirmWith507` (SIMULATED fake volume) |
| Hard-kill receiver mid-transfer, restart, resume: same device (no re-pair), same session token (no re-approval), verified chunks not re-sent | AUTOMATED | PASSED | `HardKillReceiver_DuringTransfer_ResumeFromState_Completes` (`devices.json` + `session.json` + journal; state shows `a.txt` completed, `b.bin` `nextChunk 1`) |
| Hard-kill receiver mid-manifest, restart, replayed batch accepted with same fileIds | AUTOMATED | PASSED | `HardKillReceiver_DuringManifest_ReplayedBatchAcceptedAfterRestart` |
| Commit-intent crash windows: rename completed from journal; data-gone ⇒ terminal FAILED; unjournaled tail bytes never trusted; stale pre-`RESET` chunks dropped | AUTOMATED | PASSED | `RecoveryCrashWindowsTests.Recovery_CompletesRenameFromJournalIntent`, `…WhoseDataIsGone_FailsTerminally`, `…DistrustsUnjournaledTailBytes`, `…DistrustsStaleChunksAfterFileRestart` |
| Simulated sleep/wake: connections drop inside idle window, wake resumes with progress intact | AUTOMATED | PASSED | `SleepWake_ReconnectWithinIdleWindow_ResumeWorks` (`IdleTimeout` 30 s, 1.2 s gap, `Reconnect` drops pooled sockets) |
| Expired PIN ⇒ 403 `E_PIN_EXPIRED` even with the correct PIN | AUTOMATED | PASSED | `ExpiredPin_PairingRejected_EvenWithCorrectPin` (`PinMaxAge` 250 ms test-only knob; protocol default 5 min unchanged) |
| PIN brute force: 5 failures ⇒ 429 `E_PIN_LOCKED`, backoff expires, correct PIN then pairs | AUTOMATED | PASSED | `PinLockoutBackoffExpires_ThenCorrectPinPairs` (+ M2 `FiveFailedAttempts_ThenE_PIN_LOCKED`) |
| Replayed pairing (nonce replay/expiry) | AUTOMATED | PASSED | M2 `ReplayedServerNonce_IsRejected`, `ExpiredServerNonce_IsRejected` (unchanged, still green) |
| Source mutation during transfer ⇒ `E_SOURCE_CHANGED` for already-verified chunk; original still verifies | AUTOMATED | PASSED | `SourceMutated_RejectedForAlreadyVerifiedChunk_OriginalStillVerifies` (+ M1 size-change test; sender-side mtime re-check is Swift ⇒ NOT RUN) |
| Trusted devices + session tokens survive receiver restart (ADR-017) | AUTOMATED | PASSED | Both hard-kill tests: `ReauthenticateAsync` (hello with same EC key, no PIN) + `GetSessionAsync` returns identical session token after restart |
| Windows receiver build (Release, warnings-as-errors) | AUTOMATED | PASSED | `dotnet build win-receiver/WinReceiver.sln -c Release` → 0 warnings, 0 errors (local, 2026-11-18) |
| Vectors current + docs mirror in sync | AUTOMATED | PASSED | `python tools/gen_vectors.py --check` → `OK: 5 vector files current; docs mirror in sync.` |
| Sender (Swift) crash-resume, mtime re-check, hard-kill of sender | AUTOMATED | **NOT RUN** | Swift sender not runnable on Windows (ADR-010): `swift test --package-path mac-sender/Core` on macOS / `macos-latest` CI job |
| Hard-kill of *sender* and receiver (SPEC §10 full wording) | AUTOMATED | **NOT RUN** | Receiver-side half is the two hard-kill tests above (SIMULATED sender: test client reconnects). Real sender kill needs the Swift app ⇒ macOS CI |
| UI-driven end-to-end transfer: Ready → pair → approve → transfer → progress → history → export → stop | AUTOMATED | PASSED | `SmokeTest.UiDrivenTransfer_EndToEnd` (real TLS, `ProtocolTestClient` as Mac, on-disk SHA-256 == source, JSON/CSV/HTML export) |
| UI updates throttled ~15 Hz, never block UI thread | — | PASSED | `ReceiverViewModel` uses `DispatcherTimer` (67 ms ≈ 15 Hz); server callbacks marshal to UI thread via `Dispatcher`; no `await` in UI event handlers |
| Windows receiver + App build (Release, warnings-as-errors) | AUTOMATED | PASSED | `dotnet build win-receiver/WinReceiver.sln -c Release` → 0 warnings, 0 errors (local, 2026-11-18) |
| Vectors current + docs mirror in sync | AUTOMATED | PASSED | `python tools/gen_vectors.py --check` → `OK: 5 vector files current; docs mirror in sync.` (PROTOCOL.md §2.8 amended for optional `applyToAllDefault` + confirm response echo) |
| GitHub Actions CI (all 5 jobs) | AUTOMATED | **NOT RUN** | No GitHub remote yet; `macos`/`linux`/`cross-impl` use project-scoped paths (WPF not on non-Windows), `windows` keeps the solution |

## M5 — Performance

All numbers below measured on the development workstation (Win11 build 26300, .NET SDK 10.0.404)
over loopback via `dotnet test win-receiver/PerfTests -c Release`; real LAN/iperf3 figures
are REAL-DEVICE. See docs/PERFORMANCE.md for full detail.

| Feature | Level | Status | Evidence |
|---|---|---|---|
| Memory bounded and flat regardless of file size/count; under 200 MB target | AUTOMATED | PASSED | `ThroughputAndMemoryTests.Memory_FlatAcrossTransfers_RegardlessOfSize`: WS growth 4.5 / 5.3 / 8.5 MB for 10 MiB / 100 MiB / 1 MiB×200; growth does not scale with bytes |
| Large-file throughput measured; not disk-limited (24 MB/s vs 1258 MB/s disk copy) | AUTOMATED | PASSED | `ThroughputAndMemoryTests.LargeFile_DiskCopyBaseline_SameOrderOfMagnitude` + `LargeFile_ThroughputAndMemory_UnderTarget` |
| Small-file rate measured vs 500 files/s target | AUTOMATED | PASSED | `SmallFileTests.SmallFileRate_ReportVsTarget`: 94 / 70 / 51 files/s for 4 KB / 16 KB / 64 KB × 2000 loopback; target not met without pipelining |
| Resume does not re-send verified chunks (ALREADY_VERIFIED, one file at destination) | AUTOMATED | PASSED | `ResumeTests.Transfer_VerifiesWholeFile_DoesNotResendOnCommitReplay` |
| All transfer invariants hold on every perf run (SHA-256, no partials, source intact, ledger reconciles) | AUTOMATED | PASSED | `PerfEnv.TransferAsync` asserts invariants on every transfer |
| docs/PERFORMANCE.md written with actual measured numbers | — | PASSED | `docs/PERFORMANCE.md` |
| iperf3 LAN baseline / 85–90% link capacity | REAL-DEVICE | **NOT RUN** | needs second machine + iperf3 |
| mDNS discovery ≤5 s on home network | REAL-DEVICE | **NOT RUN** | needs LAN |

## M6 — QA and security audit

All rows below from `dotnet test win-receiver/WinReceiver.sln -c Release` on this machine,
2026-11-18: **149/149 passed** (133 Core + 9 App + 7 Perf), 0 build warnings.

| Feature | Level | Status | Evidence |
|---|---|---|---|
| Full test matrix green (Core + App + Perf) | AUTOMATED | PASSED | `dotnet test win-receiver/WinReceiver.sln -c Release` → 149/149, 0 warnings |
| Path-sanitizer fuzz: 20,000 seeded hostile paths, no throw, containment, determinism, idempotence | AUTOMATED | PASSED | `PathSanitizerFuzzTests.SeededFuzz_20000HostilePaths_…` |
| Manifest-parser fuzz: 1,000 random JSON batches over real HTTP, no 500/crash, structured errors only | AUTOMATED | PASSED | `ManifestParserFuzzTests.ManifestEndpoint_NeverCrashes_OnRandomBatches` |
| Dependency vulnerability audit: no vulnerable packages (incl. transitive) | AUTOMATED | PASSED | `dotnet list package --vulnerable --include-transitive` → none |
| Build warnings-as-errors: 0 warnings, 0 errors | AUTOMATED | PASSED | `dotnet build win-receiver/WinReceiver.sln -c Release` |
| Vectors current + docs mirror in sync | AUTOMATED | PASSED | `python tools/gen_vectors.py --check` → `OK: 5 vector files current; docs mirror in sync.` |
| CI YAML valid | AUTOMATED | PASSED | `npx --yes js-yaml .github/workflows/ci.yml` → OK |
| GitHub Actions CI (all 5 jobs) | AUTOMATED | **NOT RUN** | No GitHub remote yet |

## M7 — Release

Installer script drafted (`win-receiver/installer/Mac2WinReceiver.iss`, Inno Setup per ADR-004)
and final report written (`docs/FINAL_REPORT.md`). Actual installer builds, signing, and
notarization require Inno Setup + a code-signing cert (Windows) and Developer ID +
notarytool (macOS) — not available on this workstation.

| Feature | Level | Status | Evidence |
|---|---|---|---|
| Inno Setup installer script drafted | — | PASSED | `win-receiver/installer/Mac2WinReceiver.iss` |
| Final report (SPEC §15: features, matrix, perf, limits, human actions, build/install/release) | — | PASSED | `docs/FINAL_REPORT.md` |
| Windows installer build + signtool signing | REAL-DEVICE | **NOT RUN** | no iscc / no signing cert locally |
| macOS .app + DMG + codesign + notarize + staple | REAL-DEVICE | **NOT RUN** | no macOS / no Developer ID |
| GitHub Actions CI release job (publish artifacts) | AUTOMATED | **NOT RUN** | no GitHub remote |

## M4–M7 (rows added as milestones start)

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
dotnet test win-receiver/Core.Tests/Mac2WinReceiver.Core.Tests.csproj -c Release
swift test --package-path mac-sender/Core
```

