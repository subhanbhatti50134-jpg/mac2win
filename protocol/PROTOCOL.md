# Mac2Win Transfer Protocol — v1

Canonical protocol specification. `docs/TRANSFER_PROTOCOL.md` is a mirrored copy (checked by
`tools/gen_vectors.py --check`). Two codebases (Swift sender, .NET receiver) implement this
document; both MUST pass the golden vectors in `protocol/vectors/`.

- **Protocol version:** `1` (file `protocol/VERSION`). Wire prefix: `/v1`.
- **Transport:** HTTPS over TCP. TLS 1.3 preferred, TLS 1.2 floor. Receiver = server, Mac = client.
- **Content types:** `application/json; charset=utf-8` (control plane), `application/octet-stream` (chunk bodies).
- **Default port:** `48600` (configurable; advertised via mDNS TXT and the connection code/QR).
- **JSON compatibility:** clients MUST ignore unknown object fields. Servers MUST reject unknown *required* semantics via error codes, never by silently ignoring.

---

## 1. Roles, discovery, and endpoints

### 1.1 Discovery (not part of HTTPS)

Service type: **`_mac2win._tcp`** (Bonjour/mDNS). Instance name = receiver device name.
TXT records:

| Key | Meaning | Example |
|---|---|---|
| `pv` | protocol version | `1` |
| `fp` | first 8 hex chars (lowercase) of SHA-256 of the receiver certificate DER | `a1b2c3d4` |
| `ver` | receiver app version (SemVer) | `0.1.0` |
| `port` | redundant with SRV; omitted | — |

Discovery is advisory: the certificate fingerprint (full, via QR/manual code or `fp` prefix via mDNS)
is always verified against the TLS channel before any credential is used (see §4).

Manual connection code (human-typable and QR): `m2w://<host>:<port>?fp=<full-sha256-hex>&pin=<6+ digits>`.
The PIN is single-use and never stored in the code's QR beyond display lifetime (see §4).

### 1.2 Endpoint table

| # | Method & path | Auth | Purpose |
|---|---|---|---|
| 1 | `GET /v1/health` | none | liveness, protocol version, device name, full cert fingerprint, `serverNonce` |
| 2 | `POST /v1/auth/challenge` | none | fresh `serverNonce` for pairing/device-auth proofs |
| 3 | `POST /v1/pair` | TLS + PIN proof | enroll a Mac device key (first pairing) |
| 4 | `POST /v1/auth/hello` | TLS + device key signature | obtain a `deviceToken` for a paired device |
| 5 | `GET /v1/destination` | deviceToken | destination path, free bytes, filesystem type (preflight) |
| 6 | `POST /v1/sessions` | deviceToken | request a transfer session (triggers receiver approval dialog) |
| 7 | `GET /v1/sessions/{id}` | deviceToken | poll session status / approval |
| 8 | `POST /v1/sessions/{id}/manifest` | sessionToken | upload manifest batches; receive planned actions |
| 9 | `POST /v1/sessions/{id}/confirm` | sessionToken | user-approved conflict resolutions; start transfer |
| 10 | `GET /v1/sessions/{id}/state` | sessionToken | resume state (verified chunks/files) |
| 11 | `PUT /v1/sessions/{id}/files/{fileId}/chunks/{index}` | sessionToken | upload one chunk (raw bytes) |
| 12 | `POST /v1/sessions/{id}/files/{fileId}/commit` | sessionToken | finalize one file (verify → timestamp → atomic rename) |
| 13 | `POST /v1/sessions/{id}/pause` · `/resume` · `/cancel` | sessionToken | session controls |
| 14 | `GET /v1/sessions/{id}/report` | sessionToken | per-item outcome ledger (JSON) |
| 15 | `POST /v1/sessions/{id}/complete` | sessionToken | close session, freeze report |

Bodies are UTF-8 JSON. Timestamps are **UTC nanoseconds since epoch encoded as decimal strings**
(JSON numbers cannot carry ns precision portably). Sizes are JSON numbers (bytes, ≤ 2^53−1 per
value; manifests paginate so totals never exceed safe integer in one message).

---

## 2. Message schemas

Canonical JSON Schemas (draft 2020-12) live in `protocol/schema/`. Summary below.

### 2.1 `GET /v1/health` → 200

```json
{
  "service": "mac2win-receiver",
  "protocolVersion": 1,
  "appVersion": "0.1.0",
  "deviceName": "OFFICE-PC",
  "certFingerprintSha256": "a1b2…ff (64 lowercase hex)",
  "serverNonce": "base64(32 random bytes)"
}
```

### 2.2 `POST /v1/auth/challenge` → 200

```json
{ "serverNonce": "base64(32 random bytes)", "expiresIn": 300 }
```

`serverNonce` values are single-use and expire after `expiresIn` seconds; a missing,
replayed, or expired nonce fails with `E_BAD_REQUEST`. The auth endpoints
(`challenge`/`pair`/`hello`) are rate-limited per client IP (default 60 requests per 10 s
sliding window) and fail with `E_RATE_LIMITED` when exceeded (SPEC §7).

### 2.3 `POST /v1/pair` → 200

Request:

```json
{
  "protocolVersion": 1,
  "deviceName": "MacBook Pro",
  "devicePublicKey": "base64(DER SubjectPublicKeyInfo, EC P-256)",
  "clientNonce": "base64(32 random bytes)",
  "serverNonce": "base64(echo of challenge)",
  "pinProof": "base64(HMAC-SHA256)"
}
```

`pinProof` construction (exactly):

```
pinKey = HKDF-SHA256(
           ikm  = ASCII bytes of the PIN (e.g. "483920"),
           salt = ASCII bytes of the lowercase-hex server cert SHA-256 fingerprint,
           info = ASCII "mac2win-pair-v1",
           len  = 32)
message = UTF8(clientNonce_b64) || 0x7C || UTF8(serverNonce_b64) || 0x7C || UTF8(devicePublicKey_b64)
pinProof = HMAC-SHA256(pinKey, message)
```

Response:

```json
{ "deviceId": "uuid-v4", "issuedAt": "1712345678123456789" }
```

Server verifies: PIN valid & unexpired & unused & not locked out; proof matches; then marks the
PIN **used** and stores the device public key. Errors: `E_PIN_INVALID`, `E_PIN_EXPIRED`,
`E_PIN_LOCKED`, `E_UNSUPPORTED_VERSION`.

### 2.4 `POST /v1/auth/hello` → 200 (paired devices)

Request:

```json
{
  "deviceId": "uuid-v4 (returned by /v1/pair)",
  "deviceName": "MacBook Pro",
  "clientNonce": "base64(32B)",
  "serverNonce": "base64(echo of challenge)",
  "signature": "base64(ECDSA-P256-SHA256 over UTF8(clientNonce_b64) || 0x7C || UTF8(serverNonce_b64))"
}
```

Response:

```json
{ "deviceToken": "base64(32B)", "expiresIn": 3600 }
```

`deviceToken` is a bearer token (header `Authorization: Bearer <token>`), single-session-use,
rotatable; invalidated on unpair/revocation. Errors: `E_NOT_PAIRED`, `E_UNAUTHORIZED`.

### 2.5 `GET /v1/destination` → 200

```json
{ "path": "D:\\Migrated", "freeBytes": 512000000000, "fileSystem": "NTFS",
  "writable": true, "longPathsEnabled": true }
```

### 2.6 `POST /v1/sessions` → 202

Request:

```json
{
  "summary": { "fileCount": 120, "dirCount": 9, "symlinkCount": 1, "totalBytes": 987654321 },
  "sourceDevice": { "name": "MacBook Pro" }
}
```

The receiver shows the approval dialog (Mac name, IP, item count, total size — SPEC §4).
Response (immediately):

```json
{ "sessionId": "uuid-v4", "status": "AWAITING_APPROVAL" }
```

Poll `GET /v1/sessions/{id}` until `status` becomes `MANIFEST_RECEIVING`; that response also
carries the `sessionToken`:

```json
{ "sessionId": "…", "status": "MANIFEST_RECEIVING", "sessionToken": "base64(32B)",
  "approvedAt": "…ns", "chunkSizeMax": 67108864, "chunkSizeDefault": 4194304 }
```

Denied: `status: "DENIED"` (terminal). Approval timeout (5 min): `status: "EXPIRED"`.

### 2.7 `POST /v1/sessions/{id}/manifest` → 200

Request:

```json
{
  "batchIndex": 0,
  "final": false,
  "entries": [
    { "path": "Vacation/IMG_0001.HEIC", "type": "file", "size": 3145728,
      "mtimeUtcNs": "1712345678123456789", "ctimeUtcNs": "1712340000000000000", "mode": 420 },
    { "path": "Vacation", "type": "dir", "size": 0, "mtimeUtcNs": "…", "mode": 493 },
    { "path": "Vacation/link", "type": "symlink", "size": 0, "mtimeUtcNs": "…",
      "mode": 120000, "symlinkTarget": "../IMG_0001.HEIC" }
  ]
}
```

- `path`: **relative, NFC-normalized**, `/` separators, no leading `/`, no `.`/`..` segments, at most 64 segments (sender-normalized; receiver re-validates and may reject with `E_PATH_REJECTED`).
- `mode`: POSIX, informational only.
- Batches: ≤ 1000 entries or ≤ 1 MiB JSON per batch, whichever first. `batchIndex` is 0-based, contiguous.
- On `final: true` the request includes `"manifestDigest": "<hex sha256, canonical form §2.7.1>"`.

Response (per batch):

```json
{
  "planned": [
    { "path": "Vacation/IMG_0001.HEIC", "fileId": "f-0001", "action": "CREATE" },
    { "path": "readme.txt", "fileId": "f-0002", "action": "CONFLICT", "existingSize": 12 }
  ],
  "batchAccepted": true
}
```

`action ∈ CREATE | RENAME | CONFLICT | EXCLUDED_BY_POLICY | REJECTED`.
`RENAME` entries include `"finalPath"`. `REJECTED` entries include `"reason"` (they never transfer).

After the final batch the response additionally carries preflight:

```json
{
  "status": "PREFLIGHT_READY",
  "manifestDigest": "…",
  "totals": { "files": 120, "dirs": 9, "symlinks": 1, "bytes": 987654321 },
  "conflicts": [ { "path": "readme.txt", "existingSize": 12, "existingMtimeUtcNs": "…" } ],
  "renames": [ { "path": "a.txt", "finalPath": "a (2).txt", "reason": "CASE_COLLISION" } ],
  "excluded": [ { "path": "Vacation/.DS_Store", "reason": "POLICY_APPLEDSTORE" } ],
  "rejected": [ { "path": "../../etc/passwd", "reason": "PATH_TRAVERSAL" } ],
  "destination": { "path": "D:\\Migrated", "freeBytes": 512000000000, "fileSystem": "NTFS" },
  "predictedProblems": [ { "code": "P_FAT32_4GB", "path": "big.iso", "message": "…" } ]
}
```

#### 2.7.1 Canonical manifest digest

```
manifestDigest = HEX( SHA-256 over the byte stream formed by concatenating, for every entry
in batch order across all batches:
    UTF8(path) || 0x00 || ASCII(type) || 0x00 || ASCII(decimal(size))
    || 0x00 || ASCII(mtimeUtcNs) || 0x00 || ASCII(decimal(mode)) || 0x0A )
```

`type` ∈ `file` | `dir` | `symlink`. Golden vector: `protocol/vectors/manifest_digest.json`.

### 2.8 `POST /v1/sessions/{id}/confirm` → 200

```json
{
  "conflictResolutions": { "readme.txt": "REPLACE" },
  "applyToAllDefault": "ASK"
}
```

Per-path policy ∈ `SKIP | REPLACE | RENAME | KEEP_BOTH`. Unlisted conflicts → `E_CONFLICT_UNRESOLVED`.

`applyToAllDefault` is **optional**. When omitted, the receiver applies its configured default
conflict policy (a receiver setting; factory default `ASK`, i.e. ask-the-sender, so omitting it
alone still yields `E_CONFLICT_UNRESOLVED` on conflicts). When present, it overrides the
receiver default for conflicts with no per-path entry.

Response: `{ "status": "TRANSFERRING", "chunkSize": 4194304, "conflictResolutions": { … } }`
(server may pick ≤ requested size). `conflictResolutions` in the response echoes the **effective**
per-path resolutions the receiver applied (sender entries merged with the receiver default; empty
when there were no conflicts). The sender MUST skip uploading files resolved as `SKIP` — the
receiver rejects chunk uploads for them (`E_SESSION_STATE`).

### 2.9 `GET /v1/sessions/{id}/state` → 200 (resume)

```json
{
  "status": "TRANSFERRING",
  "manifestDigest": "…",
  "chunkSize": 4194304,
  "completed": [ { "path": "Vacation/IMG_0001.HEIC", "fileSha256": "…" } ],
  "partial": [ { "path": "big.iso", "fileId": "f-0100", "verifiedChunks": [0,1,2], "nextChunk": 3 } ],
  "cursor": null
}
```

Paginated with `?cursor=<opaque>` when large; `cursor: null` = end. Sender MUST re-validate the
boundary chunk (PUT it again; server answers `alreadyVerified` if it matches, `E_CHUNK_HASH_MISMATCH`
if not → restart that file).

### 2.10 `PUT /v1/sessions/{id}/files/{fileId}/chunks/{index}` → 200

Headers: `Content-Type: application/octet-stream`, `X-Chunk-Sha256: <lowercase hex>`.
Body: raw chunk bytes.

Chunk `i` covers `[i·chunkSize, min((i+1)·chunkSize, size))`. `size = 0` ⇒ no chunk requests,
go straight to commit.

Response: `{ "status": "VERIFIED", "bytesStored": 4194304 }` or
`{ "status": "ALREADY_VERIFIED", "bytesStored": … }` (idempotent retry).
Server recomputes SHA-256 of the received body; mismatch ⇒ `E_CHUNK_HASH_MISMATCH` (retryable,
nothing persisted).

### 2.11 `POST /v1/sessions/{id}/files/{fileId}/commit` → 200

```json
{ "fileSha256": "<hex, whole-file>", "size": 3145728, "mtimeUtcNs": "…", "ctimeUtcNs": "…" }
```

Receiver: flush staged `.m2wpart` → verify on-disk bytes (verify-after-write, default ON) match
`fileSha256` → set timestamps → atomic rename to final path → journal the file.
Response:

```json
{ "outcome": "VERIFIED", "finalPath": "D:\\Migrated\\Vacation\\IMG_0001.HEIC" }
```

`outcome ∈ VERIFIED | RENAMED | REPLACED | CHANGED_DURING_TRANSFER | FAILED`.
On `FAILED`/`CHANGED_DURING_TRANSFER` the sender restarts that file (once, per SPEC §5).

### 2.12 Controls

- `POST …/pause` → `{ "status": "PAUSED" }` (staging kept).
- `POST …/resume` → `{ "status": "TRANSFERRING" }`.
- `POST …/cancel` → `{ "status": "CANCELLED", "report": {…} }` (staging deleted; already-verified files remain and appear in the report).

### 2.13 `GET /v1/sessions/{id}/report` → 200 · `POST …/complete` → 200

```json
{
  "sessionId": "…", "status": "COMPLETED", "startedAt": "…", "finishedAt": "…",
  "totals": { "items": 130, "verified": 128, "renamed": 1, "replaced": 0, "skipped": 0,
              "excluded": 1, "unreadable": 0, "cloudPlaceholder": 0, "changed": 0, "failed": 0,
              "bytesVerified": 987654321 },
  "items": [
    { "path": "Vacation/IMG_0001.HEIC", "finalPath": "D:\\Migrated\\Vacation\\IMG_0001.HEIC",
      "outcome": "VERIFIED", "size": 3145728, "fileSha256": "…" },
    { "path": "Vacation/.DS_Store", "outcome": "EXCLUDED_BY_POLICY", "reason": "POLICY_APPLEDSTORE" }
  ]
}
```

**Invariant:** every manifest entry appears exactly once in `items`; counts reconcile with `totals`
(SPEC §5). `POST /complete` freezes the report and expires the session (staging purged).

---

## 3. State machines

### 3.1 Session

```
POST /sessions
    │
    ▼
AWAITING_APPROVAL ──(user denies)──────────────► DENIED (terminal)
    │ (user approves ≤5 min)
    ▼
MANIFEST_RECEIVING ──(batches…)──► PREFLIGHT_READY
    │                                   │ POST /confirm (conflicts resolved)
    │ (server timeout/expiry)          ▼
    └──────────────► EXPIRED    TRANSFERRING ⇄ PAUSED
                                   │  │  │
                    cancel ────────┘  │  └──── failures exhausted ──► FAILED (terminal)
                                      │
                                 POST /complete ──► COMPLETED (terminal)
```

Rules: only `TRANSFERRING` accepts chunk PUTs and commit; `PAUSED` rejects them with
`E_SESSION_STATE` (retryable after resume); chunk PUTs are idempotent in every accepting state;
`CANCELLED` can be reached from any non-terminal state.

### 3.2 Session token issuance

`deviceToken` (from `/auth/hello`) → `POST /sessions` → poll → `sessionToken` (on approval).
All in-session endpoints require `Authorization: Bearer <sessionToken>`.

### 3.3 Chunk/file lifecycle (receiver, durable journal)

```
RECEIVED → HASH_OK → PERSISTED(append journal, fsync) → [all chunks] → COMMITTING
   │ hash mismatch: nothing persisted, sender retries
   ▼
FILE_COMMITTED (flush → verify-after-write → timestamps → atomic rename → journal fsync)
```

Journal is write-ahead: a chunk entry is only recorded after its bytes are on disk and hashed.
Recovery on restart: replay journal; unjournaled `.m2wpart` bytes are discarded (sender
re-uploads from the last journaled chunk).

---

## 4. Pairing & authentication (summary; full threat model in docs/SECURITY.md)

1. TLS first, always. Client validates server cert against fingerprint from QR/manual code (`fp` in mDNS is a prefix check only).
2. PIN: ≥6 CSPRNG digits, shown only on the receiver, single-use, 5-minute expiry, 5 failed attempts → lockout with exponential backoff (1s, 2s, 4s, 8s, 16s), never logged.
3. Proof = HKDF/HMAC binding (§2.3) — no custom primitives.
4. After pairing: Mac pins full cert fingerprint (persists in Keychain); receiver stores device public key in trusted-devices list (revocable).
5. Paired devices still authenticate per connection (`/auth/hello` signature) and **every session still needs explicit receiver approval** (SPEC §4).
6. Bearer tokens are random 32-byte values, scoped (`deviceToken` vs `sessionToken`), expire (1 h / session lifetime), and are constant-time compared.

---

## 5. Error model

Error body (all non-2xx):

```json
{ "error": { "code": "E_CHUNK_HASH_MISMATCH", "message": "chunk 17 hash mismatch",
             "retryable": true, "details": { "fileId": "f-0100", "chunkIndex": 17 } } }
```

| Code | HTTP | Meaning | Retryable | User-facing message (maps to TROUBLESHOOTING.md) |
|---|---|---|---|---|
| `E_BAD_REQUEST` | 400 | Malformed JSON/headers/params | no | The receiver could not understand the request. |
| `E_UNSUPPORTED_VERSION` | 400 | `protocolVersion` unsupported | no | Update both apps to the same version. |
| `E_UNAUTHORIZED` | 401 | Missing/invalid/expired token | re-auth | Connection expired — reconnecting. |
| `E_NOT_PAIRED` | 403 | Device not in trusted list | no | Pair this Mac with the PIN shown on the PC. |
| `E_PIN_INVALID` | 403 | Wrong PIN/proof | yes* | The PIN is incorrect. Check the code on the PC. |
| `E_PIN_EXPIRED` | 403 | PIN older than 5 min | no | The PIN expired — a new one is on screen. |
| `E_PIN_LOCKED` | 429 | Too many attempts | after backoff | Too many tries. Wait a moment and try again. |
| `E_APPROVAL_DENIED` | 403 | User declined the request | no | The transfer was declined on the PC. |
| `E_SESSION_NOT_FOUND` | 404 | Unknown session | no | The transfer session no longer exists. |
| `E_SESSION_EXPIRED` | 410 | Session past expiry/TTL | new session | The session expired. Start the transfer again. |
| `E_SESSION_STATE` | 409 | Wrong state for this call | after state change | The transfer is paused or busy — resume and retry. |
| `E_MANIFEST_TOO_LARGE` | 413 | Over manifest caps | no | Too many items in one request. |
| `E_LIMIT_EXCEEDED` | 413 | Resource cap hit (bytes/entries) | no | This transfer exceeds a receiver limit. |
| `E_PATH_REJECTED` | 400 | Unsafe path (traversal/drive/UNC/ADS/control/depth) | no | An item path was rejected as unsafe. |
| `E_CONFLICT_UNRESOLVED` | 409 | Confirm without resolutions | no | Choose what to do with existing files. |
| `E_CHUNK_HASH_MISMATCH` | 422 | Chunk bytes ≠ declared hash | yes | A corrupted chunk was retried. |
| `E_FILE_HASH_MISMATCH` | 422 | Final verify failed | no (restart file) | A file failed verification and was restarted. |
| `E_SOURCE_CHANGED` | 409 | Source changed mid-transfer | yes (restart file) | A file changed while sending and was re-sent. |
| `E_INSUFFICIENT_STORAGE` | 507 | Not enough free space | when freed | Free up space on the PC or choose another folder. |
| `E_DESTINATION_ERROR` | 500 | Unwritable destination/disk error | no | The destination folder is not writable. |
| `E_RATE_LIMITED` | 429 | Connection/rate limit | yes | Slow down — retrying automatically. |
| `E_IDLE_TIMEOUT` | 408 | Idle timeout | yes | The connection went idle — reconnecting. |
| `E_INTERNAL` | 500 | Unexpected server error | yes (backoff) | Something went wrong on the PC — retrying. |

\* `E_PIN_INVALID` retries are subject to lockout backoff; after 5 failures → `E_PIN_LOCKED`.

---

## 6. Versioning policy

- `protocolVersion` integer, in `/v1/health`, `POST /pair`, and mDNS TXT `pv`.
- **Additive, backward-compatible changes** (new fields, new optional endpoints): stay in `/v1`;
  clients MUST ignore unknown fields; servers MUST NOT require them from older clients.
- **Breaking changes** (removed/renamed fields, changed semantics): new prefix `/v2`, new `pv`,
  both advertised during a transition window; compatibility matrix in `docs/ARCHITECTURE.md`.
- App SemVer (`VERSION` file) and protocol version are independent. A version-handshake test
  asserts: sender with protocol `N` can talk to receiver advertising `pv ∈ {N, N+1}` only if
  `/v1` semantics still hold (receiver never advertises a `pv` it cannot serve).

## 7. curl examples

> These run against a receiver on localhost. Certificates are self-signed, hence `-k` **only in
> these examples** — production clients pin the fingerprint and never disable verification
> (SPEC §7: no "accept all" path anywhere).

```bash
# 1. Health / fingerprint check
curl -sk https://127.0.0.1:48600/v1/health

# 2. Pairing challenge
curl -sk -X POST https://127.0.0.1:48600/v1/auth/challenge -d '{}'

# 3. Pair (proof per §2.3 — computed offline from PIN + fingerprint + nonces)
curl -sk -X POST https://127.0.0.1:48600/v1/pair \
  -H 'Content-Type: application/json' \
  -d '{"protocolVersion":1,"deviceName":"MacBook Pro","devicePublicKey":"…",\
       "clientNonce":"…","serverNonce":"…","pinProof":"…"}'

# 4. Device auth
curl -sk -X POST https://127.0.0.1:48600/v1/auth/hello \
  -H 'Content-Type: application/json' \
  -d '{"deviceName":"MacBook Pro","clientNonce":"…","serverNonce":"…","signature":"…"}'

# 5. Destination preflight
curl -sk https://127.0.0.1:48600/v1/destination -H "Authorization: Bearer $DEVICE_TOKEN"

# 6. Create session → poll for approval
curl -sk -X POST https://127.0.0.1:48600/v1/sessions \
  -H "Authorization: Bearer $DEVICE_TOKEN" -H 'Content-Type: application/json' \
  -d '{"summary":{"fileCount":1,"dirCount":0,"symlinkCount":0,"totalBytes":5},\
       "sourceDevice":{"name":"MacBook Pro"}}'
curl -sk https://127.0.0.1:48600/v1/sessions/$SESSION_ID \
  -H "Authorization: Bearer $DEVICE_TOKEN"

# 7. Upload manifest batch (final)
curl -sk -X POST https://127.0.0.1:48600/v1/sessions/$SESSION_ID/manifest \
  -H "Authorization: Bearer $SESSION_TOKEN" -H 'Content-Type: application/json' \
  -d '{"batchIndex":0,"final":true,"manifestDigest":"…",\
       "entries":[{"path":"hello.txt","type":"file","size":5,\
                   "mtimeUtcNs":"1712345678123456789","mode":420}]}'

# 8. Confirm and upload one chunk
curl -sk -X POST https://127.0.0.1:48600/v1/sessions/$SESSION_ID/confirm \
  -H "Authorization: Bearer $SESSION_TOKEN" -H 'Content-Type: application/json' \
  -d '{"conflictResolutions":{},"applyToAllDefault":"ASK"}'
printf 'hello' | curl -sk -X PUT \
  "https://127.0.0.1:48600/v1/sessions/$SESSION_ID/files/$FILE_ID/chunks/0" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  -H "X-Chunk-Sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" \
  --data-binary 'hello'

# 9. Commit, report, complete
curl -sk -X POST https://127.0.0.1:48600/v1/sessions/$SESSION_ID/files/$FILE_ID/commit \
  -H "Authorization: Bearer $SESSION_TOKEN" -H 'Content-Type: application/json' \
  -d '{"fileSha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","size":5,\
       "mtimeUtcNs":"1712345678123456789"}'
curl -sk https://127.0.0.1:48600/v1/sessions/$SESSION_ID/report \
  -H "Authorization: Bearer $SESSION_TOKEN"
curl -sk -X POST https://127.0.0.1:48600/v1/sessions/$SESSION_ID/complete \
  -H "Authorization: Bearer $SESSION_TOKEN"
```

## 8. Transport abstraction note (SPEC §3)

Everything above assumes "some reliable byte stream with TLS". Discovery only supplies
`host:port`. USB/Thunderbolt/link-local Ethernet all terminate in the same TCP+TLS stack, so a
future transport needs only a different way to learn `host:port` (and, for link-local, a
link-local address). No protocol change required.
