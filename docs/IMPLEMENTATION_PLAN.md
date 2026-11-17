# Mac2Win Transfer — Implementation Plan (one page, M0)

## Goal
Mac sender (Swift 6/SwiftUI) + Windows receiver (.NET 10/WPF) transferring files Mac → Windows over LAN, verified byte-for-byte with SHA-256, resumable, paired with a PIN. SPEC: `docs/SPEC.md`.

## Verification strategy (who runs what)

| Layer | Where it runs | Level |
|---|---|---|
| Protocol conformance (golden vectors, schemas) | Local Windows + ubuntu CI | AUTOMATED |
| .NET receiver: unit + loopback integration + chaos | Local Windows + win/linux/mac CI | AUTOMATED |
| Swift sender core tests | macOS CI only (Apple frameworks; ADR-010) | AUTOMATED (CI), NOT RUN locally |
| Cross-impl: real Swift sender ↔ real .NET receiver, loopback TLS | macOS CI | AUTOMATED (CI), NOT RUN locally |
| Windows UI smoke (WPF) | Local + windows CI (headless where possible) | AUTOMATED where feasible, else checklist |
| macOS UI smoke (XCUITest) | macOS CI | AUTOMATED where feasible, else checklist |
| Real Mac ↔ real PC end-to-end | Human, per docs/REAL_DEVICE_TEST_PLAN.md | REAL-DEVICE, NOT RUN until executed |
| Signing/notarization | Credential-holder, scripted pipelines | NOT RUN (placeholders) |

Everything NOT RUN locally is written as a GitHub Actions job (`macos-latest`, `windows-latest`, `ubuntu-latest`) plus exact local commands in `docs/VERIFICATION.md`.

## Milestone order (from SPEC §13)

- **M0 Foundations (this):** env report ✅, ADRs ✅, repo+CI skeletons, protocol draft + golden vectors, plan ✅. Exit: skeleton build/test green locally (CI files committed; CI on GitHub = NOT RUN until remote exists).
- **M1 Walking skeleton:** protocol v1 + TLS + manifest streaming + chunked PUT + SHA-256 + atomic `.m2wpart` writes + journal. Cross-impl loopback test (Swift ↔ .NET). Exit: single file + folder verified end-to-end.
- **M2 Security/pairing:** PIN HMAC binding (ADR-003), cert pinning, trusted devices, approval dialog, path sanitizer (fuzzed), resource limits. Exit: unauthorized/malicious-client tests pass.
- **M3 Resilience:** resume/journal recovery, retry/backoff, pause/cancel, conflicts, filename mapping, ledger, preflight, chaos proxy suite. Exit: fault-injection suite green.
- **M4 Discovery/UIs:** `_mac2win._tcp` via Windows DNS-SD (ADR-006) + NWBrowser, QR/manual code, both UIs wired. Exit: UI-driven smoke test green, every control works.
- **M5 Performance:** benchmarks vs budgets (SPEC §9), PERFORMANCE.md.
- **M6 QA/security audit:** full matrix, fuzzing, `dotnet list package --vulnerable`, bug fixes.
- **M7 Release:** installers, docs, release workflow, final report (SPEC §15).

## Build order inside each milestone
1. `protocol/` spec+schemas+vectors first (source of truth).
2. Receiver core (.NET) — locally testable.
3. Sender core (Swift) — CI-tested.
4. Cross-impl test — CI glue.
5. UIs last per milestone's exit criteria.

## Repo layout
```
docs/           SPEC.md ENVIRONMENT.md DECISIONS.md TRANSFER_PROTOCOL.md SECURITY.md VERIFICATION.md ...
protocol/       spec, schema/*.schema.json, vectors/ (golden), README.md
mac-sender/     Core/ (Swift package: Sources+Tests), App/ (SwiftUI)
win-receiver/   Core/ (net10.0 class lib + tests), App/ (WPF), installer/ (Inno Setup)
tools/          gen_vectors.py, chaos proxy, data generator, benchmarks
.github/workflows/  ci-macos.yml ci-windows.yml ci-linux.yml release.yml
VERSION         shared SemVer (protocol version separate: protocol/VERSION)
```

## Risk register (top 5)
1. **No Mac locally** → Swift/cross-impl NOT RUN until macOS CI or human runs it; mitigate by keeping Swift core logic thin over a protocol contract tested by vectors.
2. **Pairing MITM residual risk** → ADR-003 + fingerprint-in-QR comparison UX; documented in SECURITY.md.
3. **Windows DNS-SD API behavior** → prototype early in M4 on this machine; fallback ADR-006 option 2.
4. **>4 GB files / FAT32** → boundary tests (4 GiB±1) gated by disk space; FAT32 test NOT RUN unless a volume is formatted.
5. **Performance budgets without a second machine** → loopback + iperf3 baseline locally; LAN numbers need a real second device (REAL-DEVICE).
