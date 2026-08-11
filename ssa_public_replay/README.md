# SSA_PUBLIC_REPLAY_CORPUS_v0.1 — Gate 1

Status: specification frozen; execution is not verified until live SSA bytes are fetched and the verifier emits PASS.

## Evidence law

`APPEND + HASH + REFERENCE + VERSION + REPLAY`

Gate 1 enforces raw evidence integrity before L2 extraction or any claims/policy/JHMA layer may be created.

### Core invariants

- `path(raw) = raw/SHA256(B_a)`
- `SHA256(read(path(raw))) = filename`
- existing raw bytes are never replaced
- multiple observation receipts may reference one identical content-addressed object
- `GATE1_PASS=false => L2+ creation prohibited`

### V01–V08

- V01 raw object exists
- V02 filename and manifest hash equal recomputed SHA-256
- V03 declared byte length equals actual bytes
- V04 one hash resolves to one raw path
- V05 duplicate observations may reference the same raw object
- V06 existing object bytes are never replaced
- V07 malformed manifest row fails verification
- V08 missing referenced object fails verification

## Run

```bash
python ssa_public_replay/gate1.py fetch \
  https://www.ssa.gov/robots.txt \
  https://www.ssa.gov/myaccount/create.html \
  https://www.ssa.gov/ssi/text-report-ussi.htm \
  https://www.ssa.gov/ssi/reporting/wages \
  https://www.ssa.gov/forms/ssa-561.html \
  https://www.ssa.gov/forms/ssa-632.html

python ssa_public_replay/gate1.py verify
```

The fetch command stores exact response bodies under `ssa_public_replay/store/raw/<sha256>` and appends one `SSA_FETCH_RECEIPT_v0.1` row per observation to `manifest.jsonl`.

The verify command recomputes every raw SHA-256 and byte length, hashes the exact manifest bytes, and emits `SSA_GATE1_RECEIPT_v0.1.json`.

A PASS receipt is the only promotion authority for L2+.

## Important scope boundary

`robots.txt` is treated as a crawl directive, not legal permission. Do not fetch authenticated/private claimant surfaces. This module contains no claimant data logic and no JHMA interpretation layer.
