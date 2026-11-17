# protocol/ — source of truth for the wire protocol

| Path | What it is |
|---|---|
| `PROTOCOL.md` | The normative protocol specification v1 (mirrored at `docs/TRANSFER_PROTOCOL.md`, sync enforced by `tools/gen_vectors.py --check`) |
| `VERSION` | Protocol version integer (independent of app SemVer in `/VERSION`) |
| `schema/*.schema.json` | JSON Schemas (draft 2020-12) for every message body |
| `vectors/*.json` | Golden test vectors consumed by **both** implementations |

## Golden vectors

Generated **deterministically** by `tools/gen_vectors.py` (stdlib-only Python, no network,
no clock, no randomness — ADR-011). Never hand-edit; regenerate instead:

```bash
python tools/gen_vectors.py          # rewrite vectors
python tools/gen_vectors.py --check  # CI gate: fail on drift (also checks docs mirror)
```

| File | Pins |
|---|---|
| `chunk_hashes.json` | Deterministic data recipe (SHA-256 chain), per-chunk and whole-file hashes, chunk boundary math (0/1/4 MiB±1) |
| `manifest_digest.json` | Canonical manifest bytes + SHA-256 digest over Unicode (NFC, CJK, RTL, emoji, symlink) entries |
| `path_policy.json` | Path sanitizer verdicts (ACCEPT/SANITIZE/REJECT), Apple policy exclusions, NFC normalization, case-fold collisions, deterministic rename example |
| `error_responses.json` | Every error code ↔ HTTP status ↔ retryable flag + exact body shape |
| `pairing_transcript.json` | HKDF/PIN proof (`pinKeyHex`, `pinProofHex`) and device-auth message bytes with fixed test values |

Both `win-receiver` (xUnit) and `mac-sender` (XCTest) test suites read these files at runtime;
a vector change that is not regenerated fails CI everywhere at once.
