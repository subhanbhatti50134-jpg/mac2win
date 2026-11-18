#!/usr/bin/env python3
"""Golden test vector generator for the Mac2Win Transfer protocol.

Deterministic (no network, no clock, no randomness): regenerating must reproduce the
committed files byte-for-byte. Both the Swift sender and the .NET receiver test suites
consume these files; CI runs `gen_vectors.py --check` to prove they are current and that
docs/TRANSFER_PROTOCOL.md mirrors protocol/PROTOCOL.md (ADR-011).

Usage:
    python tools/gen_vectors.py            # (re)write protocol/vectors/*.json
    python tools/gen_vectors.py --check    # verify committed vectors + doc mirror (exit 1 on drift)

Stdlib only (hashlib/hmac implement RFC 5869 HKDF and HMAC-SHA256; no custom crypto).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "protocol" / "vectors"
PROTOCOL_MD = ROOT / "protocol" / "PROTOCOL.md"
DOCS_MIRROR = ROOT / "docs" / "TRANSFER_PROTOCOL.md"

# --------------------------------------------------------------------------------------
# Fixed test constants (never secret; PIN here is a TEST pin, not a runtime PIN)
# --------------------------------------------------------------------------------------
TEST_PIN = "483920"
TEST_CERT_FP = hashlib.sha256(b"mac2win-test-cert-v1").hexdigest()
SERVER_NONCE_B64 = base64.b64encode(bytes(range(32))).decode()          # 00..1f
CLIENT_NONCE_B64 = base64.b64encode(bytes(range(32, 64))).decode()      # 20..3f
DEVICE_PUBKEY_B64 = base64.b64encode(
    bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
    + bytes(range(64))
).decode()

# --------------------------------------------------------------------------------------
# Crypto helpers (RFC 5869 HKDF, HMAC-SHA256) — identical construction on Swift/.NET
# --------------------------------------------------------------------------------------

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def pin_proof(pin: str, cert_fp_hex: str, client_nonce_b64: str,
              server_nonce_b64: str, device_pubkey_b64: str) -> tuple[str, str]:
    """Returns (pinKeyHex, pinProofHex) exactly as protocol/PROTOCOL.md §2.3."""
    pin_key = hkdf_sha256(
        ikm=pin.encode("ascii"),
        salt=cert_fp_hex.encode("ascii"),
        info=b"mac2win-pair-v1",
        length=32,
    )
    message = (
        client_nonce_b64.encode("utf-8") + b"|"
        + server_nonce_b64.encode("utf-8") + b"|"
        + device_pubkey_b64.encode("utf-8")
    )
    proof = hmac.new(pin_key, message, hashlib.sha256).digest()
    return pin_key.hex(), proof.hex()


# --------------------------------------------------------------------------------------
# Deterministic test data (sha256 chain) — both sides regenerate the same bytes
# --------------------------------------------------------------------------------------

def gen_bytes(seed: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


# --------------------------------------------------------------------------------------
# Path policy (SPEC §6.2) — pinned by protocol/vectors/path_policy.json
# --------------------------------------------------------------------------------------

INVALID_CHARS = set('<>:"|?*\\')
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(10)} | {f"LPT{i}" for i in range(10)}
MAX_COMPONENT = 255  # UTF-16 code units
MAX_PATH_DEPTH = 64  # path segments (SPEC §7 resource limits)


def _utf16_len(s: str) -> int:
    return sum(2 if ord(ch) > 0xFFFF else 1 for ch in s)


def sanitize_component(comp: str) -> str:
    # 1. replace invalid characters and control chars
    out = []
    for ch in comp:
        o = ord(ch)
        if ch in INVALID_CHARS or o < 0x20 or o == 0x7F:
            out.append("_")
        else:
            out.append(ch)
    comp = "".join(out)
    # 2. trim trailing dots/spaces
    comp = comp.rstrip(". ")
    if not comp:
        return "_"
    # 3. reserved device name (with or without extension), case-insensitive
    stem, dot, rest = comp.partition(".")
    if stem.upper() in RESERVED:
        comp = stem + "_" + (dot + rest if dot else "")
    # 4. over-long component: deterministic truncation + hash suffix
    if _utf16_len(comp) > MAX_COMPONENT:
        h = hashlib.sha256(comp.encode("utf-8")).hexdigest()[:8]
        # truncate to 246 UTF-16 units, then append "-" + 8 hex
        buf = []
        used = 0
        for ch in comp:
            w = 2 if ord(ch) > 0xFFFF else 1
            if used + w > 246:
                break
            buf.append(ch)
            used += w
        comp = "".join(buf) + "-" + h
    return comp


def sanitize_path(path: str) -> tuple[str, str]:
    """Returns (verdict, final_path). verdict ∈ ACCEPT | SANITIZE | REJECT."""
    if not path:
        return "REJECT", ""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        return "REJECT", "CONTROL_CHARACTER"
    if path.startswith("\\\\"):
        return "REJECT", "UNC"
    if path.startswith("/") or path.startswith("\\") or path.startswith("//"):
        return "REJECT", "ROOTED"
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        return "REJECT", "DRIVE_LETTER"
    segments = path.split("/")
    if any(seg == ".." for seg in segments):
        return "REJECT", "PATH_TRAVERSAL"
    original = segments
    segments = [seg for seg in segments if seg != "."]
    if not segments:
        return "REJECT", "EMPTY"
    if len(segments) > MAX_PATH_DEPTH:
        return "REJECT", "PATH_TOO_DEEP"
    segments = [sanitize_component(seg) for seg in segments]
    final = "/".join(segments)
    return ("ACCEPT" if segments == original else "SANITIZE"), final


def excluded_policy_reason(path: str) -> str | None:
    """SPEC §5 EXCLUDED_BY_POLICY. Returns reason code or None."""
    parts = path.split("/")
    for i, seg in enumerate(parts):
        if seg == ".DS_Store":
            return "POLICY_DOT_DS_STORE"
        if seg.startswith("._"):
            return "POLICY_APPLEDOUBLE"
        if seg == ".Trashes":
            return "POLICY_TRASH"
        if seg == ".fseventsd":
            return "POLICY_FSEVENTSD"
        if seg == ".Spotlight-V100":
            return "POLICY_SPOTLIGHT"
        if seg == ".TemporaryItems":
            return "POLICY_TEMPITEMS"
        if seg == "__MACOSX" and i == 0:
            return "POLICY_MACOSX"
    return None


# --------------------------------------------------------------------------------------
# Vector builders
# --------------------------------------------------------------------------------------

def canonical_manifest_bytes(entries: list[dict]) -> bytes:
    out = bytearray()
    for e in entries:
        out += e["path"].encode("utf-8") + b"\x00"
        out += e["type"].encode("ascii") + b"\x00"
        out += str(e["size"]).encode("ascii") + b"\x00"
        out += str(e["mtimeUtcNs"]).encode("ascii") + b"\x00"
        out += str(e["mode"]).encode("ascii") + b"\x0a"
    return bytes(out)


def build_chunk_hashes() -> dict:
    sizes = [0, 1, 5, 1048576, 4194303, 4194304, 4194305]
    cases = []
    for n in sizes:
        data = gen_bytes(b"mac2win-chunk-v1", n)
        cases.append({
            "size": n,
            "sha256": hashlib.sha256(data).hexdigest(),
            "recipe": "sha256-chain: block_i = SHA256(seed || uint64be(i)), seed='mac2win-chunk-v1', concatenated, truncated to size",
        })
    hello = b"hello"
    return {
        "_comment": "Data-plane hashing vectors. Whole-file SHA-256 = SHA-256 of the concatenation of chunks in index order.",
        "seed": "mac2win-chunk-v1",
        "cases": cases,
        "hello": {"bytesHex": hello.hex(), "sha256": hashlib.sha256(hello).hexdigest()},
        "emptyFileSha256": hashlib.sha256(b"").hexdigest(),
        "chunkBoundaries": {
            "chunkSize": 4194304,
            "fileSize": 8388609,
            "expectedChunkCount": 3,
            "chunkSizes": [4194304, 4194304, 1],
            "note": "chunk i covers [i*chunkSize, min((i+1)*chunkSize, size)); last chunk may be short; size 0 => no chunks",
        },
    }


def build_manifest_digest() -> dict:
    entries = [
        {"path": "Vacation", "type": "dir", "size": 0, "mtimeUtcNs": "1712345678123456789", "mode": 493},
        {"path": "Vacation/IMG_0001.HEIC", "type": "file", "size": 3145728,
         "mtimeUtcNs": "1712345678123456789", "mode": 420},
        {"path": "café/naïve.txt", "type": "file", "size": 11, "mtimeUtcNs": "1700000000000000001", "mode": 420},
        {"path": "こんにちは/世界.txt", "type": "file", "size": 7, "mtimeUtcNs": "1700000000000000002", "mode": 420},
        {"path": "מכתב/שלום.txt", "type": "file", "size": 12, "mtimeUtcNs": "1700000000000000003", "mode": 420},
        {"path": "emoji/🎉.txt", "type": "file", "size": 3, "mtimeUtcNs": "1700000000000000004", "mode": 420},
        {"path": "empty.bin", "type": "file", "size": 0, "mtimeUtcNs": "1700000000000000005", "mode": 420},
        {"path": "Vacation/link", "type": "symlink", "size": 0, "mtimeUtcNs": "1700000000000000006",
         "mode": 120000, "symlinkTarget": "../IMG_0001.HEIC"},
    ]
    raw = canonical_manifest_bytes(entries)
    return {
        "_comment": "Canonical digest per protocol/PROTOCOL.md §2.7.1. Paths are NFC (the 'café' above is NFC).",
        "entries": entries,
        "canonicalBytesHex": raw.hex(),
        "manifestDigest": hashlib.sha256(raw).hexdigest(),
    }


def build_nfc_and_paths() -> dict:
    nfd_cafe = "cafe\u0301"          # e + combining acute
    nfc_cafe = "caf\u00e9"              # café
    nfd_name = "volu\u0308me"        # e + diaeresis
    nfc_name = "vol\u00fcme"         # ü
    cases = [
        # --- ACCEPT ---
        {"input": "Photos/2024/IMG_1234.jpg", "verdict": "ACCEPT", "finalPath": "Photos/2024/IMG_1234.jpg"},
        {"input": "empty-dir", "verdict": "ACCEPT", "finalPath": "empty-dir"},
        {"input": "a" * 251 + ".txt", "verdict": "ACCEPT", "finalPath": "a" * 251 + ".txt",
         "note": "component exactly at the 255 UTF-16 limit"},
        {"input": "deep/" * 40 + "file.bin", "verdict": "ACCEPT", "finalPath": "deep/" * 40 + "file.bin",
         "note": "path > 260 chars: ACCEPT, receiver uses \\\\?\\ long-path support"},
        # --- SANITIZE ---
        {"input": "a<b>c.txt", "verdict": "SANITIZE", "finalPath": "a_b_c.txt"},
        {"input": "what?.txt", "verdict": "SANITIZE", "finalPath": "what_.txt"},
        {"input": "name with trailing. ", "verdict": "SANITIZE", "finalPath": "name with trailing"},
        {"input": "trailing dot.", "verdict": "SANITIZE", "finalPath": "trailing dot"},
        {"input": "CON", "verdict": "SANITIZE", "finalPath": "CON_"},
        {"input": "con.txt", "verdict": "SANITIZE", "finalPath": "con_.txt"},
        {"input": "COM1/report.txt", "verdict": "SANITIZE", "finalPath": "COM1_/report.txt"},
        {"input": "lpt9.dat", "verdict": "SANITIZE", "finalPath": "lpt9_.dat"},
        {"input": "auxfile", "verdict": "ACCEPT", "finalPath": "auxfile",
         "note": "reserved check is on the exact stem before first dot; 'auxfile' != AUX"},
        {"input": "colon:name.txt", "verdict": "SANITIZE", "finalPath": "colon_name.txt",
         "note": "colon would create an NTFS alternate data stream"},
        {"input": "./rel/./path.txt", "verdict": "SANITIZE", "finalPath": "rel/path.txt"},
        {"input": "dot..txt", "verdict": "ACCEPT", "finalPath": "dot..txt",
         "note": "interior dots are legal; only trailing dots are trimmed"},
        {"input": "b" * 300 + ".dat", "verdict": "SANITIZE",
         "finalPath": None,  # filled below: truncation + hash suffix
         "note": "over-long component: truncate to 246 UTF-16 units + '-' + sha256(component)[:8]"},
        # --- backslash: a filename character on the wire, an invalid Windows char ---
        {"input": "folder\\name.txt", "verdict": "SANITIZE", "finalPath": "folder_name.txt",
         "note": "'\\' is never a wire separator; replaced like other invalid Windows chars"},
        {"input": "..\\..\\evil.dll", "verdict": "SANITIZE", "finalPath": ".._.._evil.dll",
         "note": "backslash-style traversal cannot escape the destination"},
        {"input": "deep/..\\..\\evil", "verdict": "SANITIZE", "finalPath": "deep/.._.._evil"},
        # --- depth limit (SPEC §7) ---
        {"input": "/".join(["seg"] * 64), "verdict": "ACCEPT",
         "finalPath": "/".join(["seg"] * 64), "note": "exactly MAX_PATH_DEPTH segments is allowed"},
        {"input": "/".join(["seg"] * 65), "verdict": "REJECT", "reason": "PATH_TOO_DEEP"},
        {"input": "/".join(["d"] * 70), "verdict": "REJECT", "reason": "PATH_TOO_DEEP"},
        # --- REJECT (hostile) ---
        {"input": "../../etc/passwd", "verdict": "REJECT", "reason": "PATH_TRAVERSAL"},
        {"input": "/etc/passwd", "verdict": "REJECT", "reason": "ROOTED"},
        {"input": "\\\\server\\share\\x", "verdict": "REJECT", "reason": "UNC"},
        {"input": "C:/Windows/System32/evil.dll", "verdict": "REJECT", "reason": "DRIVE_LETTER"},
        {"input": "c:relative.txt", "verdict": "REJECT", "reason": "DRIVE_LETTER"},
        {"input": "bad\x00name.txt", "verdict": "REJECT", "reason": "CONTROL_CHARACTER"},
        {"input": "bell\x07.txt", "verdict": "REJECT", "reason": "CONTROL_CHARACTER"},
    ]
    # fill the over-long expectation
    seg = "b" * 300 + ".dat"
    verdict, final = sanitize_path(seg)
    for c in cases:
        if c.get("finalPath") is None:
            c["finalPath"] = final
            assert verdict == "SANITIZE", verdict

    # verify every case matches the implementation (self-test of the generator)
    for c in cases:
        v, r = sanitize_path(c["input"])
        assert v == c["verdict"], (c["input"], v, c["verdict"])
        if v == "SANITIZE":
            assert r == c["finalPath"], (c["input"], r, c["finalPath"])
        if v == "REJECT":
            assert r == c["reason"], (c["input"], r, c["reason"])

    exclusions = [
        {"input": ".DS_Store", "excluded": True, "reason": "POLICY_DOT_DS_STORE"},
        {"input": "Vacation/.DS_Store", "excluded": True, "reason": "POLICY_DOT_DS_STORE"},
        {"input": "._IMG_0001.HEIC", "excluded": True, "reason": "POLICY_APPLEDOUBLE"},
        {"input": "Vacation/._notes", "excluded": True, "reason": "POLICY_APPLEDOUBLE"},
        {"input": "__MACOSX/resource.txt", "excluded": True, "reason": "POLICY_MACOSX"},
        {"input": "deep/__MACOSX/x", "excluded": False, "reason": None,
         "note": "__MACOSX only excluded at top level"},
        {"input": "image._final.jpg", "excluded": False, "reason": None,
         "note": "AppleDouble prefix must start the component"},
        {"input": "notes.txt", "excluded": False, "reason": None},
        {"input": "Vacation/.Trashes/old", "excluded": True, "reason": "POLICY_TRASH"},
        {"input": ".fseventsd/ticket", "excluded": True, "reason": "POLICY_FSEVENTSD"},
        {"input": ".Spotlight-V100/index", "excluded": True, "reason": "POLICY_SPOTLIGHT"},
        {"input": ".TemporaryItems/x", "excluded": True, "reason": "POLICY_TEMPITEMS"},
    ]
    for c in exclusions:
        got = excluded_policy_reason(c["input"])
        assert got == c["reason"], (c["input"], got, c["reason"])

    nfc_cases = [
        {"input": nfd_cafe, "nfc": nfc_cafe},
        {"input": nfd_name, "nfc": nfc_name},
        {"input": nfc_cafe, "nfc": nfc_cafe},
        {"input": "Å", "nfc": "Å"},
        {"input": "Å", "nfc": "Å"},
        {"input": "🎉", "nfc": "🎉"},
    ]
    for c in nfc_cases:
        assert unicodedata.normalize("NFC", c["input"]) == c["nfc"], c

    collision_pairs = [
        {"a": "readme.txt", "b": "README.txt", "collide": True},
        {"a": nfd_cafe + ".txt", "b": nfc_cafe + ".txt", "collide": True,
         "note": "collide only after NFC normalization"},
        {"a": "photo.jpg", "b": "photo.jpg", "collide": True, "note": "identical"},
        {"a": "photo.jpg", "b": "photo.png", "collide": False},
        {"a": "\u00c5.txt", "b": "A\u030a.txt", "collide": True,
         "note": "A-ring: NFC U+00C5 vs NFD A+U+030A - collide after NFC"},
        {"a": "\u00c1.txt", "b": "\u00c5.txt", "collide": False,
         "note": "A-acute U+00C1 vs A-ring U+00C5 - distinct"},
    ]
    for c in collision_pairs:
        got = unicodedata.normalize("NFC", c["a"]).casefold() == unicodedata.normalize("NFC", c["b"]).casefold()
        assert got == c["collide"], c

    return {
        "_comment": "SPEC §6.1/§6.2 path policy: NFC normalization, sanitization, rejection, Apple policy exclusions, case-fold collisions.",
        "sanitize": cases,
        "exclusions": exclusions,
        "nfc": nfc_cases,
        "caseCollisions": collision_pairs,
        "caseCollisionRename": {
            "note": "second+ colliding entry gets deterministic ' (n)' before the extension, n starting at 2",
            "example": {"inputOrder": ["readme.txt", "README.txt"], "finalPaths": ["readme.txt", "README (2).txt"]},
        },
    }


def build_error_responses() -> dict:
    table = [
        ("E_BAD_REQUEST", 400, False, "malformed request"),
        ("E_UNSUPPORTED_VERSION", 400, False, "protocol version 2 is not supported"),
        ("E_UNAUTHORIZED", 401, True, "token expired"),
        ("E_NOT_PAIRED", 403, False, "device is not paired"),
        ("E_PIN_INVALID", 403, True, "PIN proof does not match"),
        ("E_PIN_EXPIRED", 403, False, "PIN expired"),
        ("E_PIN_LOCKED", 429, True, "too many failed attempts"),
        ("E_APPROVAL_DENIED", 403, False, "user declined the transfer"),
        ("E_SESSION_NOT_FOUND", 404, False, "unknown session"),
        ("E_SESSION_EXPIRED", 410, False, "session expired"),
        ("E_SESSION_STATE", 409, True, "session is paused"),
        ("E_MANIFEST_TOO_LARGE", 413, False, "manifest batch too large"),
        ("E_LIMIT_EXCEEDED", 413, False, "manifest depth limit exceeded"),
        ("E_PATH_REJECTED", 400, False, "path traversal rejected"),
        ("E_CONFLICT_UNRESOLVED", 409, False, "3 conflicts unresolved"),
        ("E_CHUNK_HASH_MISMATCH", 422, True, "chunk 17 hash mismatch"),
        ("E_FILE_HASH_MISMATCH", 422, False, "final verification failed"),
        ("E_SOURCE_CHANGED", 409, True, "source file changed during transfer"),
        ("E_INSUFFICIENT_STORAGE", 507, True, "destination needs 1048576 more bytes"),
        ("E_DESTINATION_ERROR", 500, False, "destination is not writable"),
        ("E_RATE_LIMITED", 429, True, "too many requests"),
        ("E_IDLE_TIMEOUT", 408, True, "idle for 300s"),
        ("E_INTERNAL", 500, True, "unexpected error"),
    ]
    cases = []
    for code, status, retryable, msg in table:
        body = {"error": {"code": code, "message": msg, "retryable": retryable}}
        cases.append({"code": code, "httpStatus": status, "body": body})
    return {
        "_comment": "Every non-2xx response body must match this shape; code<->HTTP<->retryable mapping is normative (protocol/PROTOCOL.md §5).",
        "cases": cases,
    }


def build_pairing_transcript() -> dict:
    pin_key, proof = pin_proof(TEST_PIN, TEST_CERT_FP, CLIENT_NONCE_B64, SERVER_NONCE_B64, DEVICE_PUBKEY_B64)
    return {
        "_comment": "HKDF/HMAC binding per protocol/PROTOCOL.md §2.3. TEST PIN only — runtime PINs are CSPRNG, single-use, never logged.",
        "pin": TEST_PIN,
        "certFingerprintSha256": TEST_CERT_FP,
        "serverNonceB64": SERVER_NONCE_B64,
        "clientNonceB64": CLIENT_NONCE_B64,
        "devicePublicKeyB64": DEVICE_PUBKEY_B64,
        "hkdf": {"ikm": "ASCII(pin)", "salt": "ASCII(certFingerprintHex)", "info": "mac2win-pair-v1", "length": 32},
        "pinKeyHex": pin_key,
        "hmacMessageUtf8": f"{CLIENT_NONCE_B64}|{SERVER_NONCE_B64}|{DEVICE_PUBKEY_B64}",
        "pinProofHex": proof,
        "deviceAuth": {
            "_comment": "ECDSA P-256/SHA-256 signature input for /v1/auth/hello (server verifies; vector covers the message bytes only).",
            "signedMessageUtf8": f"{CLIENT_NONCE_B64}|{SERVER_NONCE_B64}",
        },
    }


# --------------------------------------------------------------------------------------
# Output / check
# --------------------------------------------------------------------------------------

BUILDERS = {
    "chunk_hashes.json": build_chunk_hashes,
    "manifest_digest.json": build_manifest_digest,
    "path_policy.json": build_nfc_and_paths,
    "error_responses.json": build_error_responses,
    "pairing_transcript.json": build_pairing_transcript,
}


def serialize(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="verify committed vectors and doc mirror instead of writing")
    args = ap.parse_args()

    generated = {name: serialize(builder()) for name, builder in BUILDERS.items()}

    # doc mirror check (docs/TRANSFER_PROTOCOL.md must equal protocol/PROTOCOL.md)
    mirror_ok = PROTOCOL_MD.read_bytes() == DOCS_MIRROR.read_bytes()

    if args.check:
        drift = []
        for name, content in generated.items():
            path = VECTORS / name
            if not path.exists():
                drift.append(f"MISSING {path}")
            elif path.read_text(encoding="utf-8") != content:
                drift.append(f"STALE   {path}")
        if not mirror_ok:
            drift.append(f"STALE   {DOCS_MIRROR} (mirror of {PROTOCOL_MD})")
        if drift:
            print("Vector/doc drift detected:", file=sys.stderr)
            for d in drift:
                print("  " + d, file=sys.stderr)
            print("Run: python tools/gen_vectors.py  &&  copy protocol\\PROTOCOL.md docs\\TRANSFER_PROTOCOL.md",
                  file=sys.stderr)
            return 1
        print(f"OK: {len(generated)} vector files current; docs mirror in sync.")
        return 0

    VECTORS.mkdir(parents=True, exist_ok=True)
    for name, content in generated.items():
        (VECTORS / name).write_text(content, encoding="utf-8", newline="\n")
        print(f"wrote protocol/vectors/{name}")
    if not mirror_ok:
        DOCS_MIRROR.write_bytes(PROTOCOL_MD.read_bytes())
        print(f"re-mirrored {DOCS_MIRROR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
