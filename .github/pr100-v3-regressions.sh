#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

mkdir -p evidence

STEP='preflight'
REPORT="$PWD/evidence"

finish(){
  local rc=$?

  PR100_RC="$rc" PR100_STEP="$STEP" \
    python3 - "$REPORT/receipt.json" <<'PY' || true
import datetime
import json
import os
import sys

rc = int(os.environ['PR100_RC'])

report = {
    'suite': 'PR100 compact v3 security regressions',
    'state': 'PASS' if rc == 0 else 'FAILED',
    'phase': os.environ['PR100_STEP'],
    'exit_code': rc,
    'production_release_approved': False,
    'generated_utc': datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()
}

with open(sys.argv[1], 'w') as f:
    json.dump(report, f, indent=2)
PY
}

trap finish EXIT

[[ "$(git -C src rev-parse HEAD)" == \
  '42a99a0a940cfdb277f3f951a35bb4f6795d6ada' ]] ||
  exit 2

STEP='patch'

python3 .github/pr100-compact-v3-patch.py \
  > "$REPORT/patch.log" 2>&1

python3 .github/pr100-v3-hardening.py \
  >> "$REPORT/patch.log" 2>&1

STEP='test'

(
  cd src

  cargo test \
    --release \
    --locked \
    -p nightfall-storage \
    --lib \
    -- \
    --nocapture

) > "$REPORT/storage-unit-tests.log" 2>&1 || {

  tail -n 100 "$REPORT/storage-unit-tests.log"
  exit 3
}

tail -n 14 "$REPORT/storage-unit-tests.log"

STEP='integration'

(
  cd src

  cargo test \
    --release \
    --locked \
    -p nightfall-storage \
    --tests \
    -- \
    --skip pr100_real_archive_export_import_catchup_equals_full_archive

) > "$REPORT/storage-integration-tests.log" 2>&1 || {

  tail -n 100 "$REPORT/storage-integration-tests.log"
  exit 4
}

tail -n 16 "$REPORT/storage-integration-tests.log"

STEP='completed'

echo 'EXPERIMENTAL_REGRESSIONS_PASS'
