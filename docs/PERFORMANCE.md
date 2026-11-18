# Performance — Mac2Win Transfer (M5)

Measured numbers per SPEC §9 ("Measure and report actual numbers in docs/PERFORMANCE.md.
Do not tune the target to pass or compromise integrity for speed.").

All numbers below were measured on the development workstation (Win11 build 26300,
.NET SDK 10.0.404) over **loopback** with real Kestrel + real TLS + real sockets
(`win-receiver/PerfTests`). Loopback is an **upper bound** — it excludes WAN/LAN latency
and contention. Anything marked REAL-DEVICE requires a second machine on a LAN and has
**not** been run (see docs/VERIFICATION.md).

Test machine: single SSD volume; loopback is disk/CPU bound, not network bound.

## Method

The perf harness (`win-receiver/PerfTests`) drives the real `ReceiverServer` over real
TLS with `ProtocolTestClient` playing the Mac sender, then asserts the SPEC §10
invariants on every run:

- on-disk SHA-256 == source SHA-256
- no `*.m2wpart` at any final path
- source byte-identical before and after
- ledger totals reconcile with the manifest

Source files are streamed from disk chunk-by-chunk, so measured memory growth is
receiver-attributable (buffer size × concurrency), not test-data size.

## Results

### Memory — bounded, flat regardless of size or count

Target: under 200 MB steady state during a 50 GB transfer.

| Scenario | Working-set growth* | Managed heap (testhost-inclusive) |
|----------|---------------------|-----------------------------------|
| 10 MiB × 1 file | 4.5 MB | 57.8 MB |
| 100 MiB × 1 file | 5.3 MB | 80.2 MB |
| 1 MiB × 200 files | 8.5 MB | 63.0 MB |

\* Receiver-attributable: process working-set at transfer start subtracted from peak
during transfer (test baseline removed).

Growth does **not** scale with total bytes (10 MiB ≈ 100 MiB single-file: 4.5 vs 5.3 MB)
and stays under 50 MB even for 200 files — bounded by chunk buffer (1 MiB) × concurrency
plus bounded per-file metadata. Extrapolated to a 50 GB transfer, steady state remains far
below the 200 MB target. Receiver ships as a separate process (ReceiverHost / WPF app),
so its real footprint is measured independently of the test host.

### Large files — throughput

| Scenario | Throughput | Time | Note |
|----------|------------|------|------|
| 100 MiB × 1 file (1 MiB chunks) | 14–24 MB/s | ~7 s | loopback upper bound |
| Disk copy baseline (same volume) | ~1258 MB/s | — | plain `File.Copy` |

The m2w transfer (~24 MB/s) is far **below** the disk-copy baseline (~1258 MB/s), so the
transfer is **not disk-limited** on this machine. It is bound by per-chunk HTTPS
round-trips (one request + one commit per chunk) and SHA-256 hashing. On a real LAN it
would additionally be network-bound; the 85–90% of link-capacity target (SPEC §9) is
REAL-DEVICE / iperf3 and has not been measured locally.

### Small files — rate

Target: ≥500 files/s for 4–64 KB files (compared against a naive one-request-per-file
baseline). Our protocol **is** the one-request-per-file baseline (one PUT + one commit
per file), so these numbers measure that path end to end.

| File size | Count | Files/s | MB/s | vs 500 files/s target |
|-----------|-------|---------|------|-----------------------|
| 4 KB | 2000 | 94 | 0.4 | below target |
| 16 KB | 2000 | 70 | 1.1 | below target |
| 64 KB | 2000 | 51 | 3.2 | below target |

Loopback upper bound; real gigabit-LAN figures are REAL-DEVICE. The 500 files/s target is
**not met** with the current one-request-per-file protocol on this machine (~51–94
files/s loopback). Per SPEC §9 ("validate or revise with data"), the target would require
concurrency/pipelining (multiple files in flight) or batch commits — a post-M5
optimization, not something to compromise integrity for.

### Resume — verified chunks are not re-sent

A re-uploaded chunk that was already verified answers `ALREADY_VERIFIED` and is not
re-persisted; replaying a commit returns the same outcome and writes exactly one file
(no duplicate, no `*.m2wpart`). Verified chunks are never re-sent on resume (SPEC §9).

### Discovery — not measured locally

Target: device appears within ~5 seconds on a typical home network. Requires real mDNS
broadcast on a LAN; not run locally (REAL-DEVICE). The mDNS register/browse/resolve code
exists in `win-receiver/App/Services` (P/Invoke `dnsapi.dll`) and is exercised by
`MdnsInteropTests`, which skips when the DNS-SD API is unavailable on the machine.

## What was NOT run

| Item | Level | Reason |
|------|-------|--------|
| iperf3 LAN baseline + 85–90% link capacity | REAL-DEVICE | needs second machine + iperf3 |
| mDNS discovery ≤5 s on home network | REAL-DEVICE | needs LAN |
| 50 GB transfer / 200 MB steady-state at scale | SIMULATED/AUTOMATED | 50 GiB never committed locally; extrapolated |
| exFAT/FAT32 destination behavior | REAL-DEVICE | needs formatted test volume |

## How to re-run locally (Windows)

```powershell
dotnet test win-receiver\PerfTests\Mac2WinReceiver.PerfTests.csproj -c Release
```

The full suite (Core + App + Perf) runs via `dotnet test win-receiver\WinReceiver.sln -c Release`.
Numbers vary by machine; treat these as the development-workstation baseline, not a
guarantee.
