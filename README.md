# Mac2Win Transfer

"Migration Assistant, but Mac → Windows": a pair of apps that migrate files and folders
from a macOS computer to a Windows PC over the local network — securely, verifiably,
and resumably. No cloud, no internet required.

| | |
|---|---|
| **Mac sender** | Swift 6 + SwiftUI (macOS 13+, Apple silicon & Intel) |
| **Windows receiver** | C# / .NET 10 + WPF (Windows 10 22H2 & Windows 11, x64) |
| **Wire protocol** | HTTPS (TLS 1.3 preferred), JSON control plane, streamed binary chunks, `/v1` |
| **Integrity** | Per-chunk + whole-file SHA-256; a file is only visible after verify + atomic rename |
| **License** | MIT |

> **Status:** in development. See [`docs/SPEC.md`](docs/SPEC.md) for the full specification,
> [`docs/VERIFICATION.md`](docs/VERIFICATION.md) for what is actually tested (and what is not),
> and [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) for the milestone plan.

## Repository layout

```
docs/                 Specification, ADRs, protocol docs, verification matrix, test plans
protocol/             Source of truth: spec, JSON Schemas, golden test vectors
mac-sender/           Swift package (Core) + SwiftUI app + tests
win-receiver/         .NET solution: Core (net10.0) + WPF app + tests + Inno Setup installer
tools/                Vector generator, chaos proxy, data generator, benchmarks
.github/workflows/    CI: macOS, Windows, Linux, release
```

## Quick start (development)

```powershell
# Windows receiver (this repo's local toolchain)
dotnet test win-receiver/WinReceiver.sln

# Protocol golden vectors (regenerate + verify committed vectors are current)
python tools/gen_vectors.py --check
```

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for full build/test/package steps on
both operating systems, and [`docs/INSTALLATION.md`](docs/INSTALLATION.md) for end-user
installation.

## Documentation index

| File | Purpose |
|---|---|
| `docs/SPEC.md` | Full project specification (the contract for this build) |
| `docs/ARCHITECTURE.md` | Layering, components, data flow |
| `docs/TRANSFER_PROTOCOL.md` | Endpoints, schemas, state machines, error table, curl examples |
| `docs/SECURITY.md` | Threat model and controls |
| `docs/TESTING.md` | Test levels, invariants, how to run |
| `docs/VERIFICATION.md` | Feature × level × status × evidence matrix |
| `docs/PERFORMANCE.md` | Measured numbers vs budgets |
| `docs/TROUBLESHOOTING.md` | Error codes → fixes for end users |
| `docs/DECISIONS.md` | ADRs |
| `docs/REAL_DEVICE_TEST_PLAN.md` | Manual Mac ↔ PC test plan |
| `docs/INSTALLATION.md` / `docs/DEVELOPMENT.md` | Install / build guides |
