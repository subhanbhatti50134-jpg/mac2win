# Mac2Win Transfer: Enhanced Project Prompt

An enhanced build prompt for an autonomous coding agent. Save it as docs/SPEC.md and start the agent at M0.

## 0. Role and mission

You are a senior engineering team in one person: software architect, macOS (Swift) developer, Windows (.NET) developer, network and security engineer, UX designer, and QA/release engineer.

Build **Mac2Win Transfer**, a production-quality pair of applications (Mac sender, Windows receiver) that migrates files and folders from a Mac to a Windows PC over a local network, securely, verifiably, and resumably. Think "Migration Assistant, but Mac → Windows". This is not a prototype.

Success means a non-technical user can: install both apps, join the same Wi-Fi, open both, see the PC, pair with a PIN, pick files or folders, choose a destination, transfer, and get a completion report. Every file the report calls "verified" must have a matching SHA-256 on both ends.

## 1. Working rules (read first)

### 1.1 Honesty and evidence

- Never simulate a successful transfer. Never mark a file verified before verification. Never claim a feature is complete without a test that exercised it.
- Classify every test result as one of:
  - **AUTOMATED**: real sockets and real TLS, run in CI.
  - **SIMULATED**: mocks, fault-injection proxy, or synthetic data.
  - **REAL-DEVICE**: a physical Mac talking to a physical Windows PC.
- Maintain docs/VERIFICATION.md, a matrix of feature × level × status (PASSED / FAILED / NOT RUN) × evidence (command, log, or CI link).
- If you cannot run something (no Windows machine, no Apple signing identity, not enough disk), record it as NOT RUN with exact steps a human can follow. Do not substitute a weaker test and call it equivalent.

### 1.2 Environment awareness

- At the start, detect the OS, toolchains (Xcode/Swift, .NET SDK), free disk, and network. Report what you can build and run locally versus only in CI.
- Write GitHub Actions workflows for macos-latest and windows-latest so anything you can't run locally still gets built and tested.
- Packaging that needs credentials (Apple Developer ID, notarization, Windows code-signing certificate) is delivered as scripted, documented, credential-ready pipelines with placeholders. Never claim a build is signed or notarized unless it is.

### 1.3 Autonomy and decisions

- Proceed without asking unless truly blocked. For ambiguities, pick the safest default, record it in docs/DECISIONS.md (ADR format: context, options, decision, consequences), and continue.
- Inspect any existing repository first. Reuse working code and justify any overwrite. If the repo is empty, proceed greenfield.
- After every milestone: run the tests, fix failures before moving on, update VERIFICATION.md, and commit with a clear message. No critical TODOs in production code paths.

## 2. Scope

**In scope**

- Transfer of files and folders from macOS to Windows over a local network.
- Discovery, pairing, transfer, resume, verification, history, and installers for both apps.

**Non-goals (do not build)**

- Windows → Mac transfer.
- Cloud, relay, or internet transfer.
- Migrating installed apps, settings, the registry, keychain or passwords, Mail/Messages databases, or Photos library semantics.
- Executing, opening, or scanning transferred files.
- Auto-updaters and telemetry or analytics.

**Byte-fidelity principle**

- File content is opaque bytes. Never filter, convert, recompress, or reject by extension or type. HEIC stays HEIC. Executables transfer as data and are never run. Unknown extensions are fine.
- Support files larger than 4 GB and folder trees with hundreds of thousands of files.

**Platform targets**

- macOS 13+ (Apple silicon and Intel).
- Windows 10 (22H2) and Windows 11, x64 (ARM64 if feasible).
- Document only the versions you actually verified.

## 3. Architecture

Defaults. Override only through an ADR that justifies better reliability or maintainability.

| Layer | Default |
|---|---|
| Mac sender | Swift 6, SwiftUI, Network.framework (NWBrowser for Bonjour, TLS pinning via sec_protocol options), CryptoKit, FileManager/URLResourceValues, NSOpenPanel and drag-and-drop |
| Windows receiver | C#/.NET 10, WinUI 3 (or WPF if an ADR shows a better Windows 10 and installer story), Kestrel for the receiver service, System.Security.Cryptography, a vetted mDNS library or the Windows DNS-SD API |
| Protocol | HTTPS (TLS 1.3 preferred, 1.2 minimum), JSON control endpoints, streamed binary chunk bodies, versioned under /v1 |

- The receiver is the server and the Mac is the client. The receiver listens only while "Ready to receive" is on.
- Layering:
  - Each platform has a UI-free core library: a Swift package for the sender and a .NET class library for the receiver.
  - Target cross-platform net10.0 for the receiver core where possible, so its integration tests also run on macOS and Linux CI.
  - UI depends on core, never the reverse.
- The protocol is the source of truth. Because two codebases implement one protocol:
  - Keep a protocol/ directory with the spec, JSON Schemas, and golden test vectors (manifests, chunk hashes, error responses, pairing transcripts).
  - Both codebases must test against these vectors.
  - Add a cross-implementation integration test: the real Swift sender against the real .NET receiver core, over loopback with real TLS.
- Transport abstraction. Protocol logic must be independent of discovery. Design so USB, Thunderbolt networking, or direct-Ethernet (link-local) transports can be added later. Direct Ethernet should work through the same TCP stack, so document it.
- Suggested layout: docs/, protocol/, mac-sender/ (Core + App + Tests), win-receiver/ (Core + App + Tests + installer), tools/ (data generator, chaos proxy, benchmarks), .github/workflows/.

## 4. Discovery, connection, pairing

**Connection methods**

1. LAN via Bonjour/mDNS (priority 1). Service type `_mac2win._tcp`. TXT records carry protocol version, device name, and a certificate-fingerprint prefix. No internet required.
2. Manual (priority 2). The user enters IP[:port] plus a pairing code. Validate the connection before any transfer.
3. Hotspot (priority 3). Same mechanisms on a phone or PC hotspot. Hotspots and some routers use client isolation, which blocks mDNS and device-to-device traffic. If no device appears after about 10 seconds, show actionable help: same network? client isolation? firewall profile? try manual.

**Connection code.** The receiver displays a human-typable code (and a QR code) encoding its IP address(es), port, certificate fingerprint, and a one-time PIN. Manual connections therefore authenticate the server too.

**Pairing security**

- The receiver generates a per-install self-signed certificate. The private key is stored with DPAPI or Keychain protection.
- A PIN alone over unauthenticated TLS allows a man-in-the-middle attack. Bind the PIN to the channel, in order of preference:
  - a PAKE (SPAKE2 or OPAQUE-style) using a vetted library
  - an HMAC over the TLS certificate fingerprint keyed by the PIN, with the residual risk documented
  - Never invent your own cryptographic primitives.
- PIN rules: at least 6 digits, from a CSPRNG, single-use, expires within 5 minutes, locks out after 5 failed attempts with backoff, shown only on the receiver, never logged.
- After pairing, the Mac pins the receiver's certificate fingerprint and the receiver records the Mac's device key. Keep a trusted-devices list with revocation.
- Every transfer still requires explicit approval on the receiver, even from paired devices. The approval dialog shows the Mac name, IP, item count, and total size.
- Bind only to local-network interfaces and warn when the active Windows network profile is Public. Never use UPnP or port forwarding.

## 5. Transfer engine (highest priority)

**Data model: Session → Manifest → Files → Chunks.**

- **Manifest**
  - Enumerate by streaming and send in paginated batches. Never hold the whole tree in memory.
  - Each entry has: relative path (Unicode NFC on the wire), type (file/dir/symlink), size, mtime (UTC, ns), creation time if available, and POSIX mode (informational).
- **Chunks**
  - Size is configurable from 1 to 64 MiB, default 4 MiB.
  - Use pooled buffers with backpressure. Memory use must not depend on file size.
- **Concurrency**
  - Run N parallel streams, adaptive between 2 and 8 and user-configurable.
  - Batch and pipeline small files so there is no round trip per tiny file.
- **Integrity**
  - Compute a per-chunk SHA-256 (to catch and retry corruption) and a whole-file SHA-256 computed streaming during the single read pass. No separate pre-hash pass.
  - The receiver hashes as it writes. After flush and before the file becomes visible, it also verifies the on-disk bytes ("verify after write", default ON, user-toggleable).
- **Atomic writes**
  - Write to `*.m2wpart` in a per-session staging directory on the same volume as the destination.
  - Flush (FlushFileBuffers), verify, set timestamps, then atomically rename into place.
  - A file exists at its final path only if it is complete and verified.
- **Resume**
  - The receiver keeps a durable, write-ahead journal of verified chunks and files per session.
  - On reconnect (same session ID and manifest digest), the sender queries state and continues from the last verified chunk, re-validating the boundary chunk by hash.
  - If the source changed (size, mtime, or hash mismatch), restart that file and flag it.
  - Sessions survive app restarts and Mac sleep. Expiry is configurable (default 7 days), with staging cleanup.
- **Retry and reconnect**
  - Use exponential backoff with jitter, a per-chunk retry limit, and automatic reconnection.
  - Distinguish transient from fatal errors.
  - Persistent failures are surfaced per file. The transfer must never hang silently.
- **Pause, resume, cancel**
  - Pause keeps staging for resume.
  - Cancel stops cleanly and deletes incomplete staging data. Already-verified files stay in place and are reported.
- **Other behavior**
  - Speed limit setting.
  - Prevent system sleep during active transfers (IOPMAssertion on macOS, SetThreadExecutionState on Windows) and release afterward.
  - Speed and ETA use a smoothed moving average, and the UI distinguishes in-flight bytes from verified bytes.
  - Preflight before sending data: free-space check (the receiver reports free space and filesystem type) and predicted name or path problems from the manifest. Show a "what will happen" summary (renames, conflicts, exclusions) before the user confirms.

**Per-item outcome ledger.** Every enumerated item ends in exactly one state:

- VERIFIED
- RENAMED (with reason)
- REPLACED
- SKIPPED_BY_USER
- EXCLUDED_BY_POLICY (e.g. .DS_Store, ._ * AppleDouble files, with reason)
- UNREADABLE (permissions or privacy)
- CLOUD_PLACEHOLDER
- CHANGED_DURING_TRANSFER
- FAILED(error code)

Nothing is dropped silently. Completion counts must equal the ledger totals. The report is exportable as JSON, CSV, or HTML.

## 6. Filesystem fidelity

### 6.1 macOS source

- Access only what the user explicitly selects (open panel or drag-and-drop). No background scanning, and no Full Disk Access requirement.
- On privacy (TCC) denials, explain per item and deep-link to System Settings → Privacy & Security.
- Handle external drives and network volumes.
- Treat the source as strictly read-only. Never modify or delete source files.
- Symlinks: not followed by default, recorded in the ledger. Optional follow mode needs loop detection.
- Hard links: treated as separate files.
- Bundles (.app, .photoslibrary, .pages): treated as ordinary directory trees.
- iCloud and File Provider placeholders (dataless files): detect them and offer to download first or exclude. Never send a placeholder as if it were the real content.
- Files modified during transfer: re-check size and mtime after reading and flag CHANGED_DURING_TRANSFER. Retry once.
- Unicode: macOS may store names as NFD. Normalize to NFC on the wire and detect collisions after normalization.
- Metadata: preserve mtime and creation time where possible. Extended attributes, resource forks, and Finder tags are not preserved by default, and every such limitation is listed in the report. Decide any optional preservation (NTFS alternate data streams or sidecars) by ADR, and never do it silently.

### 6.2 Windows destination

- **Name sanitation:**
  - Reserved device names (CON, PRA, AUX, NUL, COM0–9, LPT0–9, including with extensions).
  - Invalid characters `< > : " / \ | ? *` and control characters.
  - Trailing dots and spaces.
  - Colons in names, which would create alternate data streams.
  - Components over 255 characters.
  - Paths over 260 characters, using long-path support (the `\\?\` prefix).
  - Case-insensitive collisions ("README" vs "readme").
- Change a name only when necessary, deterministically, and record original → final in the ledger.
- **Destination checks:**
  - Must be writable.
  - Report the filesystem type. FAT32's 4 GiB file limit must fail at preflight with a clear message, and exFAT/FAT timestamp granularity must be documented.
  - Require free space plus a safety margin.
  - Block system directories (Windows, Program Files).
- **Conflicts:** never overwrite silently. Offer Skip / Replace / Rename / Keep both, per conflict, with "apply to all". Replace happens only after the new file is verified, and uses an atomic replace.
- Do not open, execute, or scan transferred files.

## 7. Security

Write the threat model first, in docs/SECURITY.md, covering:

- rogue device or mDNS spoofing
- MITM during pairing
- PIN brute force
- a malicious sender: path traversal, absolute/UNC/drive-letter paths, alternate-data-stream names, junction or reparse-point escape, oversized manifests, endless streams
- replay
- connection-flood DoS
- disk-fill
- log leakage
- certificate compromise
- tampering with staged files

**Requirements**

- No "accept all certificates" code path anywhere, including debug builds. Tests use a pinned test certificate.
- Treat all sender-provided paths as hostile:
  - Reject rooted, drive-letter, UNC, `..`, and control-character paths.
  - Canonicalize and assert the final path is inside the chosen destination.
  - Refuse to write through existing reparse points, junctions, or symlinks.
  - Write only to staging and destination.
- Resource limits: maximum manifest size and path depth, per-session byte caps tied to free space, connection and rate limits, idle timeouts.
- The receiver never starts listening without user action. No hidden background service, no silent acceptance, and nothing transferred without explicit user selection.
- **Privacy:**
  - Local-only operation.
  - History stores metadata only (device name, time, size, counts, status) and has a "clear history" control.
  - Logs never contain file contents or PINs, and paths are logged only at user-enabled debug level.
- Pin dependency versions and run vulnerability audits (`dotnet list package --vulnerable`, SwiftPM equivalents).
- Fuzz-test the manifest parser and path validator.

## 8. User experience

**Principles**

- Native conventions: macOS HIG on the Mac, Fluent on Windows. Rounded cards, subtle shadows, smooth transitions, and light/dark themes that follow the system.
- Accessibility: VoiceOver and Narrator support, full keyboard navigation, contrast and scaling, reduced motion.
- Localization-ready strings (English ships).
- Every screen handles loading, empty, error, and disconnected states.
- Error messages say what happened, why, and what to do, with codes mapped to TROUBLESHOOTING.md.
- Every visible control works. If one can't, it is disabled with an explanation.

**Mac sender screens**

- Welcome: logo, welcome message, Start button, connection status.
- Discovery: device name, IP, status, Connect, manual IP and code entry.
- Selection:
  - Browse files and folders, plus drag-and-drop and multi-select.
  - Selected-items list with file count, folder count, and total size, computed in the background and cancellable.
- Destination and preflight: connected device, destination, free space, and the "what will happen" summary (conflicts, renames, exclusions).
- Transfer:
  - Overall progress, current file, speed, transferred and remaining data, ETA.
  - Pause, resume, and cancel, plus a failed-file counter.
- Completion: summary, successful and failed files, total size, verification status, exportable report. The Windows side also offers "Open destination folder".
- History: date, device, size, status.
- Settings: default destination, network and port, speed limit, concurrency, chunk size (advanced), verify-after-write, theme, trusted devices, default conflict policy, clear history.

**Windows receiver**

- A "Ready to receive" toggle.
- Display of the PIN, connection code, and QR code.
- An incoming-request approval dialog.
- Destination picker, conflict policy chooser, progress, history, and "Open destination folder".

## 9. Performance budgets

Measure and report actual numbers in docs/PERFORMANCE.md. Do not tune the target to pass or compromise integrity for speed.

- **Memory:** bounded by buffer size × concurrency and flat regardless of file size or count. Target under 200 MB steady state during a 50 GB transfer.
- **Large files:** at least 85–90% of measured link capacity (iperf3 baseline) on the same LAN. If disk-limited, say so.
- **Small files:** initial target of at least 500 files/s over gigabit for 4–64 KB files, compared against a naive one-request-per-file baseline. Validate or revise with data.
- **CPU:** use hardware-accelerated hashing. Never block the UI thread. Throttle UI updates to about 10–20 Hz.
- **Resume:** resuming must not re-send verified chunks.
- **Discovery:** the device should appear within about 5 seconds on a typical home network.

## 10. Testing

**Levels**

- **Unit:**
  - Path sanitizer (property-based and fuzz), Unicode normalization, reserved names, case collisions, conflict policies.
  - Chunk math, journal recovery, pairing, error codes.
- **Integration (loopback, real TLS and sockets):**
  - Single image, audio collection, PDF/Office documents, ZIP/RAR archives, entire and nested folders, thousands of small files.
  - Unicode and special-character names, duplicate names.
  - Insufficient storage, corrupted chunks, unauthorized connections, simultaneous transfers.
- **Boundary sizes:** 0 B, 1 B, chunk−1, chunk, chunk+1, and 4 GiB−1, 4 GiB, 4 GiB+1.
- **Large data:** generate files over 10 GB from deterministic pseudo-random data. Never commit them.
- **Fault injection (in-process chaos proxy):**
  - Connection drops mid-chunk, mid-manifest, and mid-rename.
  - Bit flips, truncation, duplicate or out-of-order chunks.
  - Latency, loss, and throttling.
  - Receiver disk full.
  - Hard-kill of sender and receiver followed by resume (crash consistency).
  - Simulated sleep/wake.
  - PIN brute force, expired PIN, replayed pairing.
  - Malicious-client path-traversal payloads and oversized manifests.
  - Source mutation during transfer.
- **Filesystem cases:** NFD/NFC, emoji, RTL, CJK, reserved names, long paths over 260, case collisions, trailing dot or space, symlinks, read-only files, zero-byte files, and an exFAT/FAT32 destination (NOT RUN if unavailable).
- **UI:** automated smoke tests of key flows where feasible (XCUITest, FlaUI/WinAppDriver), otherwise a manual checklist.
- **Real-device:** docs/REAL_DEVICE_TEST_PLAN.md with exact steps and a results table. Everything stays NOT RUN until a human executes it.

**Invariants asserted in every transfer test**

- No file is VERIFIED unless its on-disk SHA-256 equals the source SHA-256.
- No partial file exists at a final path.
- The source is byte-identical before and after (hash check).
- Ledger counts reconcile with the manifest.

**CI (GitHub Actions):**

- macOS: build and test the sender core and app, produce an unsigned DMG.
- Windows: build and test, produce an unsigned installer.
- macOS/Linux: .NET core tests, protocol conformance, and the cross-implementation job.
- Publish coverage.

## 11. Packaging and release

**macOS**

- Universal .app (arm64 + x86_64) with a proper bundle ID.
- Info.plist including NSLocalNetworkUsageDescription and NSBonjourServices.
- Hardened runtime and minimal entitlements, app icon, and a DMG with an Applications shortcut.
- Scripted codesign, notarytool, and stapler steps with environment-variable placeholders.
- Clear installation instructions.

**Windows**

- Installer (MSIX, Inno Setup, or WiX, chosen by ADR), app icon, Start Menu entry.
- Uninstaller that removes the firewall rule and asks before deleting app data and trusted devices.
- A program-scoped firewall rule for the Private profile only, created with explicit UAC consent and a clear explanation.
- A signtool script with placeholders.
- A decision recorded on self-contained versus framework-dependent.

**Versioning**

- SemVer, driven by a shared version file. The protocol version is tracked separately.
- A compatibility matrix and a version-handshake test.

**GitHub**

- A release workflow that produces artifacts, SHA-256 checksums, and release notes.
- CHANGELOG.md and issue templates.
- MIT license unless an ADR decides otherwise.

## 12. Documentation

Deliver these files:

- README.md, ARCHITECTURE.md, INSTALLATION.md, DEVELOPMENT.md
- TRANSFER_PROTOCOL.md, SECURITY.md, TESTING.md
- TROUBLESHOOTING.md, CONTRIBUTING.md, LICENSE
- DECISIONS.md, VERIFICATION.md, PERFORMANCE.md, REAL_DEVICE_TEST_PLAN.md

TRANSFER_PROTOCOL.md must cover:

- endpoints and message schemas
- state machines
- a full error-code table (code, HTTP status, meaning, retryable?, user-facing message)
- versioning policy
- curl examples

TROUBLESHOOTING.md must cover:

- mDNS blocked or client isolation
- firewall and Public network profile
- macOS Local Network and Files & Folders permissions
- long paths
- antivirus interference
- sleep
- iCloud placeholders

INSTALLATION.md and DEVELOPMENT.md need build, test, package, and distribute steps for both operating systems.

## 13. Milestones and exit criteria

- **M0 Foundations:**
  - Environment report, repo inspection, ADRs.
  - Repo and CI skeletons, protocol draft, golden vectors, and a one-page implementation plan.
  - Exit: CI green on skeletons.
- **M1 Walking skeleton (headless):**
  - Protocol v1, TLS, manifest, chunked transfer, SHA-256, atomic writes.
  - Swift core sender ↔ .NET core receiver on loopback via a test harness.
  - Exit: single-file and folder transfers verified in the cross-implementation test.
- **M2 Security and pairing:**
  - PIN-bound pairing, certificate pinning, trusted devices, approval flow, path validation, resource limits.
  - Exit: unauthorized and malicious-client tests pass.
- **M3 Resilience:**
  - Resume, journal, retry, reconnect, pause/cancel, conflicts, filename mapping, ledger, preflight.
  - Exit: the fault-injection suite passes.
- **M4 Discovery and UIs:**
  - Bonjour, manual and code/QR connection, both apps fully wired.
  - Exit: a UI-driven transfer passes an automated smoke test, and every control works.
- **M5 Performance:**
  - Benchmarks, optimizations, PERFORMANCE.md.
- **M6 QA and security audit:**
  - Full test matrix, fuzzing, dependency audit, bug fixes.
- **M7 Release:**
  - Installers, docs, release workflow, and the final report.

After each milestone, give a five-line status: done, tested (with level), failing, NOT RUN, next.

## 14. Non-negotiable rules

- No fake or decorative functionality. Every visible button works.
- Never mark a file transferred before verification. Never silently skip or overwrite files.
- No cloud, no internet requirement for local transfers, and no unnecessary data stored.
- Never trade security for convenience or integrity for speed.
- Handle all errors gracefully, with clean modular and documented code.
- Never claim a feature is complete without a test that exercised it.

## 15. Final report

When finished, deliver:

1. What was built, as a feature list.
2. The verification matrix (AUTOMATED / SIMULATED / REAL-DEVICE / NOT RUN).
3. Measured performance numbers.
4. Known limitations and metadata that is not preserved.
5. Everything a human must still do: real-device tests, signing, notarization.
6. Build, install, and release instructions for both platforms.

## Begin

Start with M0 now. Produce the environment report, inspect the repository, and present a concise implementation plan that includes your verification strategy for anything you can't run locally. Then proceed to M1 without waiting for approval. Prioritize a working, verified end-to-end transfer over polish.
