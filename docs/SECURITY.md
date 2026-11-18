# Mac2Win Transfer — Threat Model (SPEC §7)

Status: living document, written before the M2 hardening work (SPEC §7: "Write the threat
model first"). Every threat below lists the implemented mitigation, the test that exercises
it, and the residual risk that remains after mitigation. Test results and their level
(AUTOMATED / SIMULATED / REAL-DEVICE / NOT RUN) are tracked in
[VERIFICATION.md](VERIFICATION.md); decisions referenced here are in
[DECISIONS.md](DECISIONS.md).

## 1. Scope and assets

**What we protect**

| Asset | Why it matters |
|---|---|
| Transferred file bytes | Must arrive byte-identical (SHA-256 verified end to end). |
| Destination filesystem | Must never be written outside the user-chosen destination (system dirs, other user data). |
| Receiver host availability | A local attacker must not be able to wedge the receiver with floods or stalls. |
| The PIN and pairing trust | Whoever pairs becomes a trusted device that can request transfers. |
| User privacy | File names, paths, PINs, and contents must not leak into logs, history, or the network beyond the LAN. |
| The receiver's TLS private key | Compromise allows silent man-in-the-middle of future pairing. |

**Trust boundaries**

- The transport is a hostile LAN: any host on the same L2/L3 segment can speak to the
  receiver's TCP port while "Ready to receive" is on. Everything the sender sends is
  attacker-controlled input.
- The receiver is the server (`Kestrel`, TLS 1.3 preferred / 1.2 minimum, ADR-007); the Mac
  sender is the client. The receiver binds only to a configured local address
  (`ReceiverOptions.BindAddress`, loopback in tests); no UPnP, no port forwarding, ever.
- The user is trusted on their own machine. The receiver never listens without the user's
  explicit "Ready to receive" action, never auto-accepts a session (a receiver without a
  wired approval handler denies everything — `ApprovalHandler == null ⇒ deny`),
  and never writes anything before explicit per-transfer approval.
- Out of scope (SPEC §2 non-goals): Windows→Mac transfer, cloud/relay, executing or
  scanning transferred content, malicious receiver (the user installed it), physical
  access to either endpoint at rest.

## 2. Threats, mitigations, tests, residual risk

### T1 — Rogue device / mDNS spoofing

An attacker advertises a fake `_mac2win._tcp` service (or answers ARP/DNS with their own
IP) so the Mac connects to the wrong receiver.

- **Mitigation:** trust is not derived from discovery. The Mac pins the receiver's
  certificate fingerprint out of band — via the QR/connection code (encodes IP, port,
  fingerprint prefix, PIN) or by the user comparing the fingerprint shown on both screens.
  The sender performs fingerprint pinning during the TLS handshake and there is no
  "accept any certificate" code path anywhere, including debug builds
  (`ProtocolTestClient` and the Swift `ProtocolClient` both pin; the Swift client rejects
  on mismatch without ever evaluating trust anchors for the self-signed leaf — ADR-014).
  Even if the transport is spoofed, pairing still requires the PIN.
- **Test:** `AuthAndSecurityTests.CertificatePinMismatch_IsRejectedByTheClient`
  (AUTOMATED) — a client pinning the wrong fingerprint fails the handshake. The cross-impl
  CI job pairs over a fingerprint printed out of band by the harness.
- **Residual risk:** a user who scans a QR from an attacker and never compares anything
  visible could be tricked; the PIN shown only on the real receiver still gates pairing
  (T3/T4), so the attacker must also know the PIN.

### T2 — MITM during pairing

A network attacker intercepts the pairing exchange to steal the PIN or impersonate a side.

- **Mitigation:** the pairing proof (ADR-003, protocol §2.3) binds the PIN to the TLS
  channel: `HKDF-SHA256(PIN, salt=certFingerprintHex, info="mac2win-pair-v1")` derives a
  key, then `HMAC-SHA256` over `clientNonce|serverNonce|devicePublicKey`. The server
  verifies the proof against **its own certificate fingerprint**, so a proof captured for
  one certificate is worthless against another: an MITM terminating TLS with their own
  self-signed certificate cannot verify a proof computed for the real fingerprint, and the
  client pins the real fingerprint anyway (T1). Standard primitives only — no custom
  cryptography. After pairing, every subsequent request signs fresh nonces with the Mac's
  EC P-256 device key (hello signature) and carries bearer tokens.
- **Test:** `MaliciousClientTests.TamperedPinProof_IsRejected` (AUTOMATED),
  `AuthAndSecurityTests.WrongPin_ReturnsE_PIN_INVALID` (AUTOMATED).
- **Residual risk:** ADR-003 records the choice explicitly — an HMAC-over-fingerprint
  binding is not a PAKE, so the PIN itself is transmitted *neither* to the server nor in
  the clear (only the HMAC leaves the Mac), but a fully online attacker who can MITM can
  attempt PIN guesses through the server (bounded by T3). Documented per SPEC §4 order of
  preference: a vetted PAKE (SPAKE2/OPAQUE) can replace it later via ADR without protocol
  breakage if a vetted library becomes available for both platforms.

### T3 — PIN brute force

An attacker guesses the 6-digit PIN to pair.

- **Mitigation:** PINs are ≥6 digits from a CSPRNG, single-use, expire in 5 minutes,
  rotate after every successful pairing (production; `FixedTestPin` is test-only), are
  never logged, and lock out after 5 failed attempts with exponential backoff
  (1/2/4/8/16 s — `PinVault`). Each attempt costs the attacker a full pairing round; the
  challenge nonce is single-use and TTL-bounded (5 min default), so proofs cannot be
  replayed or precomputed against a stale nonce.
- **Test:** `AuthAndSecurityTests.FiveFailedAttempts_ThenE_PIN_LOCKED` (AUTOMATED) —
  5 wrong proofs ⇒ 429 `E_PIN_LOCKED`, and even the correct PIN is refused during backoff.
- **Residual risk:** a 6-digit space (10⁶) is exhaustible offline by anyone who can
  *predict* the CSPRNG or read the screen; the 5-minute window plus lockout keeps online
  guessing to ~5 attempts per backoff cycle (≤ 31 attempts in the first minutes), far
  below what a fixed 6-digit code would otherwise allow. A shorter code cannot be shown
  legibly to a human; accepted per SPEC §4.

### T4 — Malicious sender (hostile paths and oversized input)

A paired (or, for pre-pair endpoints, anonymous) sender sends paths or bodies designed to
write outside the destination or exhaust receiver resources.

- **Path defense** (`PathSanitizer`, SPEC §6.2; policy pinned by
  `protocol/vectors/path_policy.json`, byte-identical with the Python reference in
  `tools/gen_vectors.py`):
  - Reject (item is ledgered `FAILED` / `E_PATH_REJECTED`, never written): empty path,
    control characters (`< 0x20`, `0x7F`), UNC (`\\server\share`), rooted (`/x`, `\x`),
    drive letter (`C:…`), `..` as a `/`-separated segment, and depth > 64 segments
    (`PATH_TOO_DEEP`).
  - Sanitize deterministically (item ledgered `RENAME`, original → final recorded):
    invalid Windows characters `< > : " | ? *` **and backslash** → `_` (a `\` in a wire
    path is a filename character, never a separator — so `..\..\evil.dll` becomes the
    inert literal `.._.._evil.dll` instead of escaping), control characters → `_`,
    trailing dots/spaces trimmed, reserved device names (`CON`, `PRN`, `AUX`, `NUL`,
    `COM0–9`, `LPT0–9`, with or without extension) get a `_` before the extension,
    components over 255 UTF-16 units are truncated + hash-suffixed, case-insensitive
    NFC collisions get a deterministic ` (n)` suffix.
  - **Defense in depth:** after sanitizing, `TransferSession.DestinationFullPath`
    canonicalizes with `Path.GetFullPath` and asserts the result is inside the destination
    root (boundary-aware prefix check); `AssertNoReparseAncestor` refuses to write through
    an existing junction/symlink/reparse point; writes only ever target the per-session
    staging directory and the destination root; conflicts over an existing path are never
    silent (Skip/Replace/Rename/Keep both).
- **Resource limits:** JSON control bodies ≤ 1 MiB (`E_LIMIT_EXCEEDED`), manifest batches
  ≤ 1000 entries *and* ≤ 1 MiB (`E_MANIFEST_TOO_LARGE`), path depth ≤ 64, chunk size
  1–64 MiB with the body length asserted against the declared size (mismatch ⇒
  `E_BAD_REQUEST`), per-session planned bytes checked against free space plus margin at
  confirm (`E_INSUFFICIENT_STORAGE`), request-body reads time out when a client stalls
  mid-body (`E_IDLE_TIMEOUT`) so endless streams cannot pin connections, challenge store
  capped (1024 pending), 128 max concurrent connections.
- **Tests:** `MaliciousClientTests` (path cases, oversized manifest/control bodies,
  garbage JSON, negative chunk index, unknown fileId, stalled body, rate-limit burst),
  `PathSanitizerFuzzTests` (seeded fuzz: no exceptions, containment property
  `GetFullPath(Combine(root, final))` stays inside root, reserved-name table,
  determinism), `AuthAndSecurityTests.PathTraversalManifest_IsRejected_AndNothingIsWrittenOutsideDestination`
  and `DeeplyNestedPath_IsStillInsideDestination` (AUTOMATED).
- **Residual risk:** 8.3 short-name aliases inside the destination are not expanded
  (a component like `PROGRA~1` is treated literally; containment is asserted on the
  canonical text form, and reparse ancestors are refused). NTFS alternate data streams are
  prevented by colon sanitization but not by an explicit `:$DATA` scan — covered by the
  fuzz corpus and reserved-name tests. The destination root itself is the user's choice.

### T5 — Replay

Replaying captured pairing, hello, or chunk requests.

- **Mitigation:** server nonces are 32-byte CSPRNG values, single-use (removed on
  consume) and TTL-bound (5 min default) — a replayed pair/hello fails with
  `E_BAD_REQUEST`. Hello signatures cover `clientNonce|serverNonce` (fresh each call).
  Device and session tokens are 32-byte CSPRNG bearer values with TTLs (1 h / session
  TTL), stored server-side only. Chunks are idempotent by design: a re-sent chunk with
  the *same* declared hash returns `ALREADY_VERIFIED` (resume), with a *different* hash
  returns `E_SOURCE_CHANGED` — replay cannot corrupt an already-verified chunk.
- **Test:** `MaliciousClientTests.ReplayedServerNonce_IsRejected`,
  `MaliciousClientTests.ExpiredServerNonce_IsRejected` (AUTOMATED).
- **Residual risk:** within its TTL a *stolen* (not replayed) live nonce can be used once
  by whoever holds it; using it requires already being on the LAN and yields at most one
  pairing/hello attempt that still needs the PIN or the device's private key.

### T6 — Connection-flood / resource DoS

- **Mitigation:** unauthenticated auth endpoints (`/v1/auth/challenge`, `/v1/pair`,
  `/v1/auth/hello`) are rate-limited per client IP (default 60 requests / 10 s sliding
  window ⇒ 429 `E_RATE_LIMITED`); PIN failures are separately locked out (T3); Kestrel
  caps concurrent connections at 128 and request bodies at 64 MiB + 1 MiB; all JSON reads
  are bounded (1 MiB) with a no-progress stall timeout; the challenge store is capped at
  1024 pending nonces with oldest-first eviction so anonymous health/challenge floods
  cannot grow memory without bound; `/v1/health` stays reachable because discovery polls
  it.
- **Test:** `MaliciousClientTests.AuthBurst_IsRateLimited`,
  `MaliciousClientTests.ChallengeStore_StaysBounded` (AUTOMATED), plus the stall test in
  T4.
- **Residual risk:** an attacker with many source addresses (spoofing is impractical for
  TCP, but multiple LAN hosts are not) multiplies the per-IP budget; the 128-connection
  ceiling still bounds total concurrency. Legitimate clients behind one IP share the
  budget — 60 auth requests/10 s is far above the ~4 requests a real pairing needs.

### T7 — Disk fill

- **Mitigation:** free space (minus a configurable safety margin, default 64 MiB) is
  checked at confirm before any byte flows (`E_INSUFFICIENT_STORAGE`), declared file
  sizes are checked against the destination filesystem's per-file limit (FAT32 4 GiB
  fails preflight with `P_FAT32_4GB` + `E_LIMIT_EXCEEDED`), and a sender cannot exceed
  its declared size because chunk indices are bounds-checked against the manifest size
  (a body longer/shorter than the expected chunk length is rejected). Staging is
  per-session under the destination volume and is purged on cancel, complete, and
  session expiry.
- **Test:** `AuthAndSecurityTests.InsufficientStorage_FailsConfirmWith507`,
  `AuthAndSecurityTests.Fat32Destination_FailsPreflightForFilesOver4GiB`,
  `MaliciousClientTests.ChunkBodyLengthMismatch_IsRejected` (AUTOMATED).
- **Residual risk:** free space can shrink *during* a transfer (other processes); writes
  then fail with `E_DESTINATION_ERROR` per file rather than a silent partial — surfaced
  in the ledger. A filesystem without quotas can still be filled by an approved transfer
  up to the predicted size; approval is per-transfer and explicit.

### T8 — Log leakage

- **Mitigation:** logs record endpoint paths and error codes only — never request bodies,
  never file contents, never the PIN (the PIN exists only inside `PinVault` and the HKDF
  derivation), and never bearer tokens. Paths appear in log messages only at debug level
  behind user-enabled diagnostics (M4); default logging is method/status/exception.
  History stores metadata only (device name, time, size, counts, status) with a
  clear-history control (M4). Error responses to clients are generic (`internal error`
  for unexpected exceptions) so internals and filesystem details never leak over the
  wire.
- **Test:** `MaliciousClientTests.ErrorResponses_DoNotLeakInternals` (AUTOMATED —
  internal failures return `E_INTERNAL` with no stack/path detail); log-content scanning
  is a review item for M6.
- **Residual risk:** ASP.NET's own console logging in the headless host can log URL
  paths (which contain session/file ids, not filenames) — the shipping UI (M4) switches
  this to the debug-gated logger.

### T9 — Certificate compromise

- **Mitigation:** the per-install self-signed certificate's private key is stored with
  DPAPI user-scope protection on Windows (ADR-014; ephemeral in-memory certificates are
  used only for tests/CI, never persisted). The certificate is used for server auth only
  (`serverAuth` EKU). Trust on the Mac side is a pinned SHA-256 fingerprint, not a chain,
  so a compromised key cannot be swapped in without the user noticing a fingerprint
  mismatch (T1). Revocation of a *device* is separate (T10). Re-pairing after key loss
  rotates the fingerprint, which the user re-verifies via the connection code.
- **Test:** pin-mismatch test (T1) plus `CertificateProvider` PFX round-trip tests
  (AUTOMATED).
- **Residual risk:** if the Windows user profile is fully compromised, the key and DPAPI
  context go with it — the attacker already has the user's files. Key rotation/expiry
  policy is a documented follow-up (self-signed cert currently has a multi-year validity).

### T10 — Tampering with staged files, and trusted-device revocation

- **Staged tampering:** staging lives in a per-session directory under the destination
  volume (same volume ⇒ atomic rename). Every chunk is written with `WriteThrough`,
  journaled with its SHA-256, and the whole file is re-hashed from disk before the atomic
  rename ("verify after write", default ON) — on-disk bytes must equal the declared
  whole-file SHA-256 or the file fails with `E_FILE_HASH_MISMATCH` and never reaches its
  final path. A file exists at its final path only if complete and verified (SPEC §5
  invariant). An attacker who can modify the destination volume directly can already
  modify the destination — that user is outside the threat model; what the protocol
  defends against is *transport* corruption and partial writes being mistaken for
  complete files.
- **Revocation:** `ReceiverServer.RevokeDevice(deviceId)` (ADR-016, UI wiring in M4)
  removes the device from the trusted list and invalidates its device tokens and the
  session tokens of sessions it owns — subsequent requests fail `E_UNAUTHORIZED` /
  `E_NOT_PAIRED`. Re-pairing requires a fresh PIN (production PINs rotate per pairing)
  and every transfer still needs explicit approval regardless of trust.
- **Test:** `MaliciousClientTests.RevokedDevice_LosesAccess_AndCanRePairWithFreshPin`,
  `MaliciousClientTests.CrossSessionToken_IsRejected`,
  `TransferTests.*` verify-after-write invariants (AUTOMATED).
- **Residual risk:** revocation takes effect for *new* requests immediately but an
  in-flight chunk body already accepted completes its write to staging (it is still
  hash-verified and never appears unverified at a final path); sessions that are already
  terminal keep their reports readable until session TTL. Revocation is in-process state
  — the trusted-device list is not yet persisted across receiver restarts (M4).

## 3. Privacy and operating rules

- **Local only.** No cloud, no relay, no telemetry, no auto-updater. The receiver listens
  only while the user's "Ready to receive" toggle is on, and only on the configured
  local address; the installer creates a firewall rule for the Private profile only,
  with explicit UAC consent (M7).
- **No hidden acceptance.** Every transfer requires explicit approval on the receiver
  showing Mac name, IP, item count, and total size; `ApprovalHandler == null` denies
  everything by construction (test: `ApprovalHandlerMissing_SessionIsDenied`).
- **Read-only source.** The sender never writes to or deletes from the Mac source
  (invariant asserted in every transfer test: source hash before == after).
- **No execution.** Transferred bytes are never opened, executed, or scanned by either
  app; executables transfer as opaque data (byte-fidelity principle).
- **History** stores metadata only with a clear-history control (M4).

## 4. Dependency hygiene

- Both dependency sets are pinned (lockfiles / `packages.lock.json`) and audited in CI:
  `dotnet list package --vulnerable` and SwiftPM equivalents run in the M6 audit
  milestone; results are recorded in VERIFICATION.md.
- Cryptography is limited to platform libraries: .NET `System.Security.Cryptography`
  (HKDF, HMAC-SHA256, SHA-256, ECDsa P-256, CSPRNG) and Apple CryptoKit/Security on
  macOS. No third-party crypto, no custom primitives (SPEC §4).

## 5. Verification

Every mitigation row above is a test; results, levels (AUTOMATED / SIMULATED /
REAL-DEVICE / NOT RUN), commands, and CI references live in
[VERIFICATION.md](VERIFICATION.md). Anything not exercised by a test is recorded as NOT
RUN — never as complete.
