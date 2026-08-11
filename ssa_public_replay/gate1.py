#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "SSA_FETCH_RECEIPT_v0.1"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_if_absent(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_bytes()
        if existing != data:
            raise RuntimeError(f"MUTATION_PROHIBITED: existing object differs: {path}")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o644)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


def fetch(url: str, root: Path) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "ReceiptOS-SSA-Public-Replay/0.1"})
    fetched_at = utc_now()
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
        status = getattr(resp, "status", 200)
        content_type = resp.headers.get("Content-Type", "")
    digest = sha256_bytes(data)
    raw_rel = f"raw/{digest}"
    write_if_absent(root / raw_rel, data)
    return {
        "schema": SCHEMA,
        "url": url,
        "fetched_at": fetched_at,
        "http_status": status,
        "content_type": content_type,
        "byte_length": len(data),
        "sha256": digest,
        "raw_object": raw_rel,
    }


def append_manifest(root: Path, row: dict) -> None:
    manifest = root / "manifest.jsonl"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def verify(root: Path) -> dict:
    manifest = root / "manifest.jsonl"
    errors = []
    rows = []
    if not manifest.exists():
        errors.append("V07 malformed manifest row: manifest.jsonl missing")
        manifest_bytes = b""
    else:
        manifest_bytes = manifest.read_bytes()
        for i, line in enumerate(manifest_bytes.splitlines(), 1):
            try:
                row = json.loads(line)
                required = {"schema", "url", "fetched_at", "http_status", "content_type", "byte_length", "sha256", "raw_object"}
                if not required.issubset(row) or row.get("schema") != SCHEMA:
                    raise ValueError("missing/invalid required fields")
                rows.append(row)
            except Exception as e:
                errors.append(f"V07 malformed manifest row {i}: {e}")

    seen_paths = {}
    hash_failures = 0
    length_failures = 0
    missing_objects = 0
    for i, row in enumerate(rows, 1):
        raw_rel = row["raw_object"]
        raw_path = root / raw_rel
        if not raw_path.exists():
            missing_objects += 1
            errors.append(f"V01/V08 row {i}: missing {raw_rel}")
            continue
        actual = raw_path.read_bytes()
        actual_hash = sha256_bytes(actual)
        filename = raw_path.name
        if filename != actual_hash or actual_hash != row["sha256"]:
            hash_failures += 1
            errors.append(f"V02 row {i}: hash mismatch")
        if len(actual) != row["byte_length"]:
            length_failures += 1
            errors.append(f"V03 row {i}: byte_length mismatch")
        prior = seen_paths.get(row["sha256"])
        if prior is None:
            seen_paths[row["sha256"]] = raw_rel
        elif prior != raw_rel:
            errors.append(f"V04 row {i}: sha256 resolves to multiple raw paths")

    receipt = {
        "schema": "SSA_GATE1_RECEIPT_v0.1",
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "manifest_rows_checked": len(rows),
        "unique_raw_objects": len(seen_paths),
        "duplicate_observations": max(0, len(rows) - len(seen_paths)),
        "missing_objects": missing_objects,
        "hash_failures": hash_failures,
        "length_failures": length_failures,
        "malformed_rows": sum(1 for e in errors if e.startswith("V07")),
        "gate1_status": "PASS" if not errors else "FAIL",
        "verified_at": utc_now(),
        "verifier_version": "0.1",
        "errors": errors,
    }
    return receipt


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--root", default="ssa_public_replay/store")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("url", nargs="+")
    sub.add_parser("verify")
    args = p.parse_args()
    root = Path(args.root)

    if args.cmd == "fetch":
        for url in args.url:
            row = fetch(url, root)
            append_manifest(root, row)
            print(json.dumps(row, sort_keys=True))
        return 0

    receipt = verify(root)
    out = root / "SSA_GATE1_RECEIPT_v0.1.json"
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt_hash = sha256_bytes(out.read_bytes())
    print(json.dumps({"receipt": str(out), "receipt_sha256": receipt_hash, **receipt}, indent=2, sort_keys=True))
    return 0 if receipt["gate1_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
