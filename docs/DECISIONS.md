# Architecture Decision Records (ADR)

Format per SPEC §1.3: Context / Options / Decision / Consequences.

---

## ADR-001: Windows receiver UI framework — WPF (not WinUI 3)

- **Context:** SPEC §3 defaults to WinUI 3 but allows WPF "if an ADR shows a better Windows 10 and installer story". Target is Windows 10 (22H2) + Windows 11 x64.
- **Options:**
  1. WinUI 3 via Windows App SDK (default).
  2. WPF (mature, in-box on .NET, no runtime deploy package).
  3. WinForms.
- **Decision:** **WPF** on .NET 10 (`net10.0-windows`), dark/light theming via resource dictionaries, Fluent-ish styling applied manually.
- **Consequences:**
  - No Windows App SDK deployment/runtime dependency; a self-contained publish + Inno Setup installer works identically on Win10 22H2 and Win11. Unpacking/dev runs are trivial.
  - Fluent design is emulated (styles in-repo) instead of taken from WinUI — extra styling work, acceptable for a utility app.
  - WinForms rejected: weaker accessibility/templating story. WinUI 3 rejected: Windows App SDK self-contained vs framework-dependent packaging complexity, unpackaged-app limitations, and heavier installer for zero functional gain here.
  - Revisit only if native Fluent controls become a hard requirement (new ADR).

## ADR-002: Receiver core targets cross-platform `net10.0`

- **Context:** SPEC §3 requires a UI-free core as a .NET class library, cross-platform where possible so integration tests run on macOS/Linux CI.
- **Options:** `net10.0` (cross-platform) vs `net10.0-windows`.
- **Decision:** All protocol/transfer logic lives in `win-receiver/Core` targeting **`net10.0`**. Windows-only pieces (DPAPI key protection, firewall rule, `SetThreadExecutionState`, `\\?\` long-path specifics, filesystem-type detection) live behind interfaces in the same core with Windows implementations in a separate `net10.0-windows` file/namespace compiled conditionally, or in the app project.
- **Consequences:** Core tests run on macOS/Linux/Windows CI; DPAPI and other Windows APIs are exercised only on Windows jobs (and locally).

## ADR-003: Pairing = HMAC binding to TLS cert fingerprint (PAKE deferred)

- **Context:** SPEC §4 order of preference: (1) vetted PAKE library, (2) HMAC over TLS certificate fingerprint keyed by PIN with residual risk documented. Never invent crypto.
- **Options:**
  1. SPAKE2/OPAQUE via a vetted library — requires a library that is maintained, cross-platform (.NET **and** Swift), and audited. No such library meets the bar for both platforms today.
  2. HMAC-SHA256 binding: `proof = HMAC-SHA256(HKDF(PIN), serverCertFingerprint || clientNonce || devicePublicKey)`.
- **Decision:** **Option 2** for v1, with mitigations: single-use PIN (≤5 min, 5-attempt lockout + backoff), TLS channel required, fingerprint prefix shown in QR/connection code so the user can compare, and residual MITM risk (an active MITM that terminates both TLS sessions before pairing) documented in docs/SECURITY.md.
- **Consequences:** A first-pairing MITM in the tiny window before fingerprints are compared remains theoretically possible; mitigated by QR/manual fingerprint comparison UX. Revisit PAKE when a vetted dual-platform library exists. No custom primitives are used.

## ADR-004: Windows installer — Inno Setup

- **Context:** SPEC §11 requires an installer choice by ADR (MSIX, Inno Setup, WiX).
- **Options:** MSIX (store-style, signing strongly encouraged, firewall-rule custom actions awkward), WiX (MSI, heavier toolchain, custom actions need care), Inno Setup (scriptable Pascal脚本, easy UAC firewall rule, Start Menu, uninstaller).
- **Decision:** **Inno Setup** (`win-receiver/installer/mac2win-receiver.iss`), script-driven firewall rule creation for the **Private profile only** with UAC consent, uninstaller removes the rule and prompts before deleting app data/trusted devices.
- **Consequences:** No Microsoft Store distribution; sideload instructions required (documented in INSTALLATION.md). Firewall rule scripting must be tested on a real device (REAL-DEVICE).

## ADR-005: Self-contained publish for the Windows app

- **Context:** SPEC §11 requires a decision on self-contained vs framework-dependent.
- **Decision:** **Self-contained** single-file publish (`win-x64`, trimmed off to avoid reflection issues).
- **Consequences:** Users need no .NET runtime (Win10 22H2 does not ship .NET 10); larger artifact (~70–90 MB); framework-dependent would need a runtime bootstrapper and a second failure mode on user machines. ARM64: build self-contained `win-arm64` when a runner is available, otherwise documented as NOT RUN.

## ADR-006: mDNS/DNS-SD on Windows — Windows DNS-SD API (dnsapi) first

- **Context:** Receiver must advertise `_mac2win._tcp` for the Mac's NWBrowser; SPEC allows "a vetted mDNS library or the Windows DNS-SD API".
- **Options:**
  1. P/Invoke the built-in Windows DNS-SD API (`DnsServiceRegister`/`DnsServiceBrowse` in dnsapi.dll, available since Windows 10) — no third-party dependency.
  2. Managed library (e.g. Zeroconf) — pure managed mDNS implementation, extra dependency to pin/audit.
  3. Apple Bonjour SDK — requires installing Apple software on the PC, unacceptable.
- **Decision:** **Option 1**, with Option 2 as a documented fallback if the API proves unusable on Win10 22H2 (fallback recorded here as an amendment, not silently).
- **Consequences:** Zero third-party deps to audit; needs P/Invoke + interop tests on Windows only (testable locally on this machine during M4); behavior on hostile networks identical to other mDNS stacks.

## ADR-007: Transport = Kestrel HTTPS with per-install self-signed cert

- **Context:** SPEC §3 protocol row.
- **Decision:** Kestrel with a per-install self-signed certificate (TLS 1.3 preferred, 1.2 floor), bound **only to local interfaces**, listening only while "Ready to receive" is on. Client pins the cert fingerprint after pairing. No "accept all" path ever.
- **Consequences:** Certificate lifecycle (generation, DPAPI-protected private key, rotation) is ours to implement and test (M2).

## ADR-008: Monorepo layout per SPEC §3 suggestion

- **Decision:** `docs/`, `protocol/`, `mac-sender/`, `win-receiver/`, `tools/`, `.github/workflows/`, shared `VERSION` file, MIT `LICENSE`.
- **Consequences:** Single CI matrix, atomic protocol+implementation changes.

## ADR-009: License = MIT

- **Decision:** MIT unless a later ADR says otherwise (SPEC §11).

## ADR-010: Swift sender cannot build on Windows — CI is the verification path

- **Context:** This dev machine is Windows-only; Network.framework/SwiftUI/CryptoKit are Apple-only. A Windows Swift toolchain exists but cannot compile the sender's Apple-framework dependencies.
- **Options:** (a) CI-only verification for Swift, (b) install Windows Swift and abstract all Apple frameworks away (dilutes the design, still can't test NWBrowser/TLS pinning), (c) dual transport abstraction with a POSIX/WinSock test transport.
- **Decision:** **(a)** for Apple-specific code. The Swift core is structured so its pure-logic layer (manifest building, chunk math, path normalization, ledger) is platform-independent — but its tests run on macOS CI like everything else Swift. Local Windows verification covers the .NET side of the protocol plus golden vectors shared with Swift tests.
- **Consequences:** Swift results are NOT RUN locally; recorded as such in VERIFICATION.md with exact `macos-latest`/Mac commands. Cross-implementation test (SPEC §3) runs on macOS CI: real Swift sender ↔ real .NET receiver core over loopback with real TLS.

## ADR-011: Golden vectors are generated by one committed script, checked in CI

- **Context:** Two codebases must test against the same vectors (SPEC §3).
- **Decision:** `tools/gen_vectors.py` (Python, stdlib only) deterministically generates `protocol/vectors/*` (manifests, chunk hashes, error responses, pairing transcripts with fixed test PIN/keys). CI runs `gen_vectors.py --check` to prove the committed vectors are current; .NET and Swift tests read the committed files.
- **Consequences:** No network, no randomness, no clock in vector generation. Python needed only for regeneration (dev machines/CI), not for runtime.

## ADR-012: Chunked upload via HTTP PUT with hash header (not multipart)

- **Context:** SPEC §3 says "JSON control endpoints, streamed binary chunk bodies".
- **Decision:** Control plane = JSON over HTTPS; data plane = `PUT /v1/sessions/{sid}/files/{fid}/chunks/{index}` with the raw bytes as body and `X-Chunk-SHA256` header. Receiver verifies the header hash before persisting the journal entry.
- **Consequences:** Simple, curl-testable, streams through Kestrel with backpressure; no multipart boundary overhead. Small-file pipelining (SPEC §5) will be added at M3/M5 via a batched endpoint if round-trip cost shows up in benchmarks — recorded now so the endpoint shape is versioned.

## ADR-013: Symlinks are excluded, not preserved (recorded in ledger)

- **Context:** SPEC requires byte-fidelity for file contents; symlink preservation (re-creating links on Windows) needs privilege/developer-mode semantics and can escape the destination tree.
- **Decision:** A manifest entry with `type: "symlink"` is planned as `EXCLUDED_BY_POLICY` with reason `POLICY_SYMLINK_NOT_PRESERVED`, counted in ledger `Excluded`, and never written. Apple metadata (`.DS_Store` → `POLICY_DOT_DS_STORE`, `._*` AppleDouble) is excluded the same way. Symlink *targets* are never followed for reading.
- **Consequences:** Destination is always a tree of real files/dirs; no reparse-point injection vector. Users who need links must re-create them manually; the ledger makes the omission explicit rather than silent.

## ADR-014: Ephemeral TLS key must round-trip through a PFX (schannel constraint)

- **Context:** M1's first integration run failed every TLS handshake with *"Authentication failed because the platform does not support ephemeral keys"*. CertificateRequest.CreateSelfSigned returns a certificate whose private key lives in an in-memory (ephemeral) CNG key; Windows schannel refuses to use such a key as a server certificate, closing the connection before ServerHello.
- **Decision:** `CertificateProvider.CreateEphemeral` now exports the fresh certificate to PFX and re-imports it via `X509CertificateLoader.LoadPkcs12(..., X509KeyStorageFlags.Exportable)`. No `PersistKeySet` flag, so the key container is deleted when the certificate is disposed — per-process ephemerality (M1 behavior) is preserved; M2's DPAPI persistence (ADR-007) will import with `PersistKeySet | UserKeySet` instead. The cert also gains an explicit `serverAuth` EKU.
- **Alternatives considered:** (a) `X509KeyStorageFlags.EphemeralKeySet` on import — same schannel rejection; (b) disable TLS — violates SPEC §4/§7; (c) `AllowSynchronousIO`/other Kestrel tweaks — unrelated to the failure.
- **Consequences:** Fingerprint is computed after the round-trip (DER is unchanged, so pinning is unaffected). Any test that constructs a server certificate must use this factory; a raw `CreateSelfSigned` cert will handshake-fail on Windows.

## ADR-015: Resource limits and hostile-input defenses are explicit, configurable options

- **Context:** SPEC §7 requires documented resource limits so a hostile LAN client cannot exhaust the receiver: unbounded JSON parsing, unlimited auth requests, endless request-body streams, unbounded path depth, and destinations inside Windows system directories.
- **Decision:** Every limit is a named `ReceiverOptions` knob with a safe default, enforced in the core (not the UI):
  - JSON bodies bounded at read time: manifest batches ≤ 1 MiB (`E_MANIFEST_TOO_LARGE`), all other control bodies ≤ 1 MiB (`E_LIMIT_EXCEEDED`); malformed/shape-invalid JSON ⇒ 400 (missing field / wrong type are bad requests, not internal errors).
  - Auth endpoints (`challenge`/`pair`/`hello`) rate-limited per client IP: 60 requests / 10 s sliding window ⇒ 429 `E_RATE_LIMITED` (`AuthRateLimiter`; 0 disables). `/v1/health` stays open for discovery, but the challenge store is capped (`MaxPendingChallenges`, default 1024, oldest-expiring evicted first) so anonymous nonce floods cannot grow memory.
  - Request-body reads wrapped in `StallTimeoutStream`: no progress for 60 s (`BodyStallTimeout`, 0 disables) ⇒ 408 `E_IDLE_TIMEOUT`; chunk PUT additionally asserts `Content-Length == expected chunk length` before reading.
  - Path depth ≤ 64 segments (`MaxPathDepth`) ⇒ `PATH_TOO_DEEP`; backslash on the wire is a filename character, sanitized to `_` (parity with `tools/gen_vectors.py`, vectors pinned in `path_policy.json`). Traversal is still caught by `/`-separated `..` plus canonicalization containment.
  - Session expiry has two clocks: `SessionTtl` (7 days from creation) and post-approval `IdleTimeout` (default 7 days to honor SPEC §5 resume-after-sleep); expiry ⇒ 410 `E_SESSION_EXPIRED` + staging purge. `E_IDLE_TIMEOUT` (408) is reserved for request-body stalls only.
  - Kestrel caps concurrent connections at 128; `DestinationGuard` refuses `StartAsync` when the destination is (or resolves into) Windows/Program Files/Program Data — boundary-aware so `C:\Windows2` passes and `C:\Windows\System32` fails, checked before any directory is created; tests inject `ProtectedDestinationRoots` synthetic roots.
- **Alternatives considered:** (a) hard-coded constants — untestable against synthetic system roots and inflexible for embedders; (b) relying only on Kestrel's `MaxRequestBodySize` (64 MiB) — far too large for a JSON manifest and does not catch shape errors; (c) a reverse proxy in front of Kestrel — out of scope for a LAN desktop app.
- **Consequences:** Threats T4/T6/T7 in `docs/SECURITY.md` cite these knobs and their tests (`MaliciousClientTests`, `PathSanitizerFuzzTests`, `DestinationGuardTests`). The protocol documents the caps (`E_LIMIT_EXCEEDED` bytes/entries, `E_PATH_REJECTED` + depth) so the Swift sender can pre-validate and fail fast.

## ADR-016: Trusted-device revocation is an in-process API first, no wire endpoint

- **Context:** SPEC §4 requires a trusted-devices list with revocation, but M2 has no UI (M4) and no multi-receiver synchronization. Exposing a revocation endpoint on the wire would let any paired device unpair others — a confused-deputy problem — before the product has an approval UI to gate it.
- **Decision:** Revocation is `ReceiverServer.RevokeDevice(deviceId)`: it removes the device record, revokes its device tokens, and revokes session tokens of sessions it owns (`TokenVault.RevokeOwner`). The trusted list is exposed read-only as `ReceiverServer.TrustedDevices` (`TrustedDevice { DeviceId, DeviceName, PairedAt }`) for the future M4 UI to render and call. No HTTP route exists in v1; re-pairing after revocation goes through the normal PIN flow (production PINs rotate per pairing; `FixedTestPin` keeps the PIN for tests). Every transfer still requires explicit approval regardless of trust.
- **Alternatives considered:** (a) `DELETE /v1/devices/{id}` callable by any device — any paired Mac could revoke every other device; needs an owner concept the protocol does not have; (b) persisting the trusted list — premature before M4's storage design (ledger/history) and restart semantics are specified; (c) revoking by IP — devices roam between addresses.
- **Consequences:** Test: `MaliciousClientTests.RevokedDevice_LosesAccess_AndCanRePairWithFreshPin`. Residual risk documented in `docs/SECURITY.md` T10: revocation affects new requests immediately; an in-flight chunk body already accepted completes its (still hash-verified) write to staging, and the trusted list does not survive receiver restarts (M4 work).

## ADR-017: Crash consistency via session snapshot + journal intents; chaos proxy stays in-process

- **Context:** M3 requires SPEC §5 "sessions survive app restarts" and §10 "hard-kill of sender and receiver followed by resume". The receiver previously kept all session state in memory and the journal only recorded per-chunk progress, so a kill mid-commit could leave a staged file that was verified but never renamed (or renamed but never ledgered), and a kill during manifest receipt lost the plan entirely. SPEC §10 also says the fault injector is an "in-process chaos proxy".
- **Decision:**
  - **Two-tier persistence.** Every state transition writes `<stagingRoot>/<sessionId>.session.json` atomically (temp file + rename): status, ledger outcomes, manifest progress, conflicts, session token — but *not* per-chunk progress. Chunk durability stays in the fsynced write-ahead `journal.log` (chunk bytes flush first, then the `CHUNK` line), so a crash between transitions never corrupts the last good snapshot and per-chunk fsync cost stays off the metadata path.
  - **Journal `FILE` records are commit write-ahead intents.** `FILE <fileId> <sha> <finalRel>` is journaled *before* the atomic rename; on recovery an intent is reconciled three ways: final exists with matching hash ⇒ done; staged exists with matching hash ⇒ finish the rename (with `NextFreeName` when overwriting is not allowed); neither ⇒ the item fails terminally with `E_DESTINATION_ERROR`. A new `RESET <fileId>` line marks earlier `CHUNK` records stale after a file restart, so replay never resurrects pre-restart hashes; recovery re-hashes the resume boundary chunk and distrusts it (and everything above) on mismatch. Metadata sits *beside* the staging directory (not inside it) so `PurgeStaging` can delete staged bytes without losing the terminal ledger.
  - **Trusted devices persist, tokens do not.** Paired device public keys are stored in `<stagingRoot>/devices.json` (re-pairing would need a fresh PIN the user may not have); bearer tokens are in-memory only and the device re-hellos with its EC key after a restart; session tokens are re-registered from the snapshot during recovery.
  - **Chaos proxy is an in-process class in the test project**, not a `tools/` binary: it is a loopback TCP byte tunnel (sever-after-N-bytes, latency, throttle) that passes TLS through untouched, runs without extra processes in CI, and disappears with the test run. Mid-body drops are simulated client-side by a `TruncatingContent` that dies after N bytes.
  - **Cert ownership on restart:** the test harness creates the certificate once and hands it to every server instance; `ReceiverServer` disposes only certificates it created, so restarts keep the pinned fingerprint the sender trusts.
- **Alternatives considered:** (a) per-chunk snapshot writes — doubles fsync traffic and puts the ledger at risk of half-written JSON (mitigated by atomic rename, but slower for no gain since the journal already covers chunks); (b) SQLite for session state — a dependency and a migration surface for what is one file per session; (c) a standalone `tools/chaosproxy` binary — SPEC §10 says in-process, and a separate binary needs build/publish wiring in every CI job before it can run; (d) process-level kill (`Process.Kill`) for hard-kill tests — can't kill only the server inside the test host without killing the tests too, so the restart path disposes the server and relies on "no extra flush" to model the kill faithfully.
- **Consequences:** `TransferSession.Recover` + `ReceiverServer.RecoverSessions` run before Kestrel accepts traffic; corrupt snapshots are skipped, never fatal. Tests: `FaultInjectionTests` (16) and `RecoveryCrashWindowsTests` (5) — restart tests reuse `TestEnv.RestartServerAsync` and re-hello without re-pairing. Residual gap: a kill *between* the snapshot write and the rename for a non-journaled operation (directory creation) is harmless because directory creation is idempotent.

## ADR-018: M4 App layering — WPF UI in `win-receiver/App`, Windows-only services in App, STA smoke tests, QRCoder/ZXing deps

- **Context:** M4 adds the Windows receiver UI (SPEC §8: Ready toggle, PIN, connection code, QR, approval dialog, destination picker, conflict policy, progress, history, report export). ADR-002 requires Core to stay cross-platform `net10.0`; Windows-only pieces (DPAPI, DNS-SD P/Invoke, firewall COM, WinForms dialogs) must live in the App project. The App's automated smoke test must drive a real `ReceiverServer` + `ProtocolTestClient` over real TLS without blocking the UI thread or showing real dialogs.
- **Decision:**
  - **App project:** `win-receiver/App` (`net10.0-windows`, `UseWPF`, `UseWindowsForms`) referencing Core + QRCoder 1.8.1. `win-receiver/App.Tests` (`net10.0-windows`) referencing Core.Tests + ZXing.Net 0.16.11 (test-only, for QR matrix round-trip via `ModuleMatrix` → `RGBLuminanceSource`, no PNG/System.Drawing).
  - **Windows-only services in App:** `CertificatePersistence` (DPAPI `ProtectedData` + PFX round-trip, `PersistKeySet|UserKeySet`), `MdnsAdvertiser`/`MdnsBrowser` (P/Invoke `dnsapi.dll`, layouts from Microsoft Learn), `NetworkProfileChecker` (`HNetCfg.FwPolicy2` COM, Public-profile check), `WinFormsFolderPicker`/`WinFormsFileSaver`/`WinFormsShellLauncher` (WinForms dialogs), `WpfApprovalUi` (non-modal `ApprovalDialog`, X/close ⇒ Deny).
  - **Dialog/shell abstractions:** `IFolderPicker`/`IFileSaver`/`IShellLauncher`/`IApprovalUi` injected into `ReceiverViewModel` — production uses real dialogs; smoke tests inject fakes that record calls and approve/deny programmatically.
  - **UI threading:** `ReceiverViewModel` polls `_server.GetSessionInfos()` on a `DispatcherTimer` (~15 Hz, SPEC §14 10–20 Hz throttle); all server callbacks marshal to the UI thread via `Dispatcher`. No `await` in UI event handlers; long-running work fires tasks.
  - **Connection code:** `Mac2WinReceiver.Core.ConnectionCode` builds/parses `m2w://` (protocol §1.1), IPv6-bracketed, 64-hex fingerprint, 6–16 digit PIN; validated round-trip in `ConnectionCodeTests` (14 cases incl. hostile inputs).
  - **Default conflict policy:** `ReceiverOptions.DefaultConflictPolicy` ("ASK" default) fills sender-omitted `applyToAllDefault` in `HandleConfirmAsync`; the confirm response echoes effective resolutions so the sender never uploads SKIPped files; chunk/commit guards reject uploads to SKIP-resolved items (`E_SESSION_STATE`).
- **Consequences:** Core stays `net10.0` (Core.Tests run on macOS/Linux/Windows). App+App.Tests are `net10.0-windows` (Windows CI only). CI jobs `macos`/`linux`/`cross-impl` switched to project-scoped paths (`Core.Tests` for tests, `ReceiverHost` for builds); `windows` job keeps the solution. mDNS/DPAPI tests are environment-dependent (mDNS register may fail on sandboxed CI). Swift sender UI (`mac-sender/App`) remains NOT RUN until macOS CI (ADR-010).
