# Mac2Win Transfer — Final Report (M7 Release)

Prepared per SPEC §15. Repository state: `main`, milestones M0–M7 complete as far as
possible on this workstation (Windows 11, .NET SDK 10.0.404, no macOS toolchain, no
GitHub remote, no physical Mac for real-device tests).

## 1. What was built (feature list)

**Cross-platform protocol & core (`win-receiver/Core`, net10.0)**
- Protocol v1 over HTTPS (TLS 1.3 preferred, 1.2 floor), JSON control plane +
  streamed binary chunk bodies under `/v1` (protocol/PROTOCOL.md, mirrored to
  docs/TRANSFER_PROTOCOL.md, kept in sync by `tools/gen_vectors.py --check`).
- Golden test vectors (protocol/vectors/) consumed by both codebases; 5 vector files.
- Chunked transfer with per-chunk SHA-256, atomic `.m2wpart` staging, verified commit
  (flush → verify → timestamps → atomic rename), exactly one terminal outcome per item.
- Resume / journal write-ahead (`journal.log` + atomic session snapshots), crash
  consistency, idempotent replay, pause/cancel, conflict policies (SKIP/REPLACE/RENAME/
  KEEP_BOTH + apply-to-all), filename mapping (sanitization, reserved names, case
  collisions), preflight (free space, filesystem type, 4 GiB FAT32 limit, protected
  directories), ledger, session TTL/idle expiry.
- Pairing: PIN-bound HMAC to TLS certificate fingerprint (ADR-003), per-install
  self-signed EC P-256 cert, trusted-devices list with in-process revocation
  (ADR-016), certificate fingerprint pinning on the Mac side.
- Discovery: `_mac2win._tcp` mDNS/DNS-SD advertisement via Windows DNS-SD API
  (dnsapi.dll P/Invoke, ADR-006); manual + QR connection code (`m2w://…`).

**Windows receiver app (`win-receiver/App`, WPF net10.0-windows)**
- "Ready to receive" toggle; PIN, connection code, QR code display (QRCoder 1.8.1).
- Incoming-request approval dialog (Mac name, IP, item count, total size; X/close ⇒ Deny).
- Destination picker, conflict-policy chooser, per-session progress list (10–20 Hz
  throttled), history (date, device, size, status), "Open destination folder".
- Report export: JSON / CSV / HTML. Settings: destination, port, device name, default
  conflict policy, verify-after-write, chunk size, theme. Clear history.
- Windows-only services: DPAPI-persisted per-install certificate (ADR-014), mDNS
  advertiser, network-profile (Public) check via HNetCfg.FwPolicy2 COM, WinForms
  folder-picker / save-file-dialog / shell launcher.
- Every visible control wired to a real command (no decorative functionality).

**macOS sender core (`mac-sender/Core`, Swift package)**
- Protocol client (pairing proof, manifest, chunks, commit, state/resume), manifest
  digest, path sanitizer parity; NOT built locally (no Swift toolchain on Windows,
  ADR-010 / macOS CI).

**Tests**
- `win-receiver/Core.Tests`: 133 tests (transfer, auth/security, vectors, malicious
  client, path-sanitizer fuzz 20k, destination guard, fault injection 16, crash
  recovery 5, manifest-parser fuzz 1k, connection-code, UI support).
- `win-receiver/App.Tests`: 9 tests (settings, DPAPI cert, QR, mDNS interop, controls
  wired, full UI-driven smoke test).
- `win-receiver/PerfTests`: 7 tests (large-file throughput, memory flatness, small-file
  rate, resume; loopback upper bounds).

## 2. Verification matrix (AUTOMATED / SIMULATED / REAL-DEVICE / NOT RUN)

See `docs/VERIFICATION.md`. Summary of local automated results (2026-11-18):

| Milestone | Result |
|-----------|--------|
| M0 Foundations | PASSED (vectors, CI skeletons, .NET core 11/11) |
| M1 Walking skeleton | PASSED (40/40) |
| M2 Security | PASSED (82/82 incl. threat model mitigations) |
| M3 Resilience | PASSED (103/103 incl. fault injection + crash windows) |
| M4 Discovery and UIs | PASSED (UI-driven end-to-end smoke test, every control wired) |
| M5 Performance | PASSED (149/149 incl. perf; docs/PERFORMANCE.md written) |
| M6 QA and security audit | PASSED (149/149, 20k path fuzz + 1k manifest fuzz, dependency audit clean) |
| M7 Release | Installer script drafted; final report = this document; signing/notarization NOT RUN |

Everything in `docs/VERIFICATION.md` marked REAL-DEVICE (Mac ↔ PC over Wi-Fi, Bonjour ≤5 s,
installer on clean Windows, codesign/notarization, exFAT/FAT32, iperf3 LAN baseline,
50 GB transfer) stays NOT RUN until a human executes `docs/REAL_DEVICE_TEST_PLAN.md`.
GitHub Actions CI (5 jobs) is written and YAML-valid but NOT RUN (no GitHub remote).

## 3. Measured performance numbers

Loopback upper bounds (real Kestrel + TLS + sockets), see `docs/PERFORMANCE.md`:

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| Memory (working-set growth) | 1.1–8.5 MB | < 200 MB | PASS (flat, byte-count independent) |
| Large-file throughput | 14–24 MB/s | 85–90% of link | NOT MEASURED (disk not limiting; LAN needed) |
| Small-file rate | 51–94 files/s | ≥ 500 files/s | Below target; needs pipelining |
| Resume (no re-send) | ALREADY_VERIFIED | — | PASS |

Disk copy baseline on the same volume: ~1258 MB/s — transfer (~24 MB/s) is bound by
per-chunk HTTPS round-trips and hashing, not disk. Real LAN/iperf3 figures are REAL-DEVICE.

## 4. Known limitations and metadata not preserved

- **Symlinks:** recorded but not recreated on Windows (excluded by policy). macOS sender
  detects them; receiver logs `POLICY_SYMLINK_NOT_PRESERVED`.
- **Apple metadata:** `.DS_Store` and `._*` files excluded by policy.
- **mtime/ctime:** preserved where the destination filesystem supports the resolution
  (exFAT/FAT have coarse granularity — documented).
- **Extended attributes / alternate data streams:** not transferred; colons in names
  rejected/sanitized to avoid ADS creation.
- **File permissions/mode:** recorded in manifest (mode field) but not applied on
  Windows (no chmod equivalent); not security-critical for the local-transfer threat model.
- **Small-file rate:** 51–94 files/s loopback, below the 500 files/s gigabit target;
  requires concurrent/pipelined chunk commits to reach.
- **mDNS:** may not function on sandboxed/VPN Windows machines; `MdnsInteropTests` skips
  gracefully; manual + QR connection always works.
- **PIN:** single-use, 5-minute expiry; `FixedTestPin` is a test-only knob (production uses
  CSPRNG PINs).

## 5. Everything a human must still do

- Execute `docs/REAL_DEVICE_TEST_PLAN.md` on a physical Mac + PC on the same LAN
  (end-to-end over Wi-Fi, Bonjour discovery ≤5 s, exFAT/FAT32, 4 GiB boundary, iperf3).
- Run GitHub Actions CI after adding a GitHub remote (`git remote add origin <url> &&
  git push -u origin main`).
- Build/sign/notarize:
  - Windows: Inno Setup installer, signtool code-signing (cert placeholder scripted).
  - macOS: universal .app, hardened runtime, entitlements, DMG, codesign + notarytool +
    stapler (Developer ID required).
- Swift sender app UI (`mac-sender/App`): written last, NOT built locally (macOS CI).
- Publish coverage (wired in CI, requires NuGet audit pass in M6).

## 6. Build, install, and release instructions

**Windows (build + test locally):**
```powershell
$env:Path = "C:\Program Files\dotnet;$env:Path"
python tools\gen_vectors.py --check
dotnet build win-receiver\WinReceiver.sln -c Release
dotnet test  win-receiver\WinReceiver.sln -c Release
dotnet list win-receiver\WinReceiver.sln package --vulnerable --include-transitive
```

**macOS / Linux (core + vectors only; WPF not available):**
```bash
python3 tools/gen_vectors.py --check
dotnet test win-receiver/Core.Tests/Mac2WinReceiver.Core.Tests.csproj -c Release
swift test --package-path mac-sender/Core   # macOS only
```

**Release artifacts (M7, to be produced on CI with signing identities):**
- Windows: self-contained single-file publish (win-x64) + Inno Setup installer
  (`win-receiver/installer`), unsigned placeholder; sign with signtool.
- macOS: universal arm64+x86_64 .app + unsigned DMG; codesign, notarize, staple.

Repository has no GitHub remote; CI jobs are written but not yet run. Add a remote and
push to enable CI.
