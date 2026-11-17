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
