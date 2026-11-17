#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

STEP=preflight
TEST_RC=125
AFTER_SHA=NO
SOURCE_OK=NO

REPORT="$PWD/evidence"

ASSET='nightfall-chain-514834-2026-11-14.bin'
EXPECTED_BYTES=757199858
EXPECTED_SHA='0520f7f2e793ac89d81b2aeafb3810728c08276988b19520dfc4e91865401ff2'
EXPECTED_PR_HEAD='42a99a0a940cfdb277f3f951a35bb4f6795d6ada'

mkdir -p "$REPORT"

cleanup_report(){
  local ec=$?

  export PR100_FINAL_RC="$ec"
  export PR100_STAGE="$STEP"
  export PR100_TEST_RC="$TEST_RC"
  export PR100_AFTER_SHA="$AFTER_SHA"
  export PR100_SOURCE_OK="$SOURCE_OK"
  export PR100_EXPECTED_PR_HEAD="$EXPECTED_PR_HEAD"
  export PR100_EXPECTED_SHA="$EXPECTED_SHA"
  export PR100_ASSET="$ASSET"

  python3 - \
    "$REPORT/receipt.json" \
    "$REPORT/mainnet-test.log" <<'PY' || true
import datetime
import importlib.util
import json
import os
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
log = pathlib.Path(sys.argv[2])

text = (
    log.read_text(errors='replace')
    if log.is_file()
    else ''
)

spec = importlib.util.spec_from_file_location(
    'gate',
    'src/scripts/pr100_production_gate.py'
)

measure = None

try:
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    measure = mod.parse_mainnet_pass(text)

except Exception:
    pass

rc = int(os.environ['PR100_FINAL_RC'])
test_rc = int(os.environ['PR100_TEST_RC'])

passed = (
    rc == 0
    and test_rc == 0
    and os.environ['PR100_AFTER_SHA'] == 'YES'
    and os.environ['PR100_SOURCE_OK'] == 'YES'
    and measure is not None
    and 'test result: ok. 1 passed;' in text
)

state = (
    'EXPERIMENTAL_PASS_HARDENED'
    if passed
    else (
        'BLOCKED'
        if os.environ['PR100_STAGE']
        in ('preflight', 'download')
        else 'FAILED'
    )
)

r = {
    'status': state,
    'stage': os.environ['PR100_STAGE'],
    'process_exit_code': rc,
    'rust_test_exit_code': test_rc,

    'expected_pr_head': (
        os.environ['PR100_EXPECTED_PR_HEAD']
    ),

    'verified_source_sha256': (
        os.environ['PR100_EXPECTED_SHA']
        if os.environ['PR100_SOURCE_OK'] == 'YES'
        else None
    ),

    'source_preserved': (
        os.environ['PR100_AFTER_SHA'] == 'YES'
    ),

    'archive_asset': os.environ['PR100_ASSET'],

    'measurements': (
        measure if passed else None
    ),

    'generated_utc': datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat(),

    'nonclaims': [
        'Independent checkpoint certification',
        'Legacy v1.1.2 operator migration',
        'Real-data crash rehearsal',
        'Desktop Core GUI recovery',
        'Independent security approval',
        'Production readiness'
    ]
}

tmp = out.with_suffix('.tmp')

tmp.write_text(
    json.dumps(r, indent=2) + '\n'
)

os.replace(tmp, out)

print('Acceptance receipt:', state)
PY
}

trap cleanup_report EXIT

cd "${GITHUB_WORKSPACE:?}"

[[ "$(git -C src rev-parse HEAD)" == "$EXPECTED_PR_HEAD" ]] || {
  echo 'PR source SHA mismatch' >&2
  exit 2
}

[[ -f src/crates/nightfall-storage/tests/pr100_real_checkpoint_acceptance.rs ]] ||
  exit 2

printf 'Runner memory and disk:\n'

free -h
df -h "$RUNNER_TEMP"

STEP=download

ARCHIVE="$RUNNER_TEMP/pr100-archive"
mkdir -p "$ARCHIVE"

URL="https://github.com/Instinctes/nightfall/releases/download/chain-bootstrap/$ASSET"

echo "Downloading pinned real mainnet archive: $ASSET"

curl \
  --fail \
  --location \
  --retry 5 \
  --retry-all-errors \
  --connect-timeout 30 \
  --speed-time 60 \
  --speed-limit 1024 \
  --output "$ARCHIVE/blocks.bin.part" \
  "$URL"

[[ "$(stat -c %s "$ARCHIVE/blocks.bin.part")" == "$EXPECTED_BYTES" ]] || {
  echo 'Invalid mainnet archive size' >&2
  exit 2
}

printf '%s  %s\n' \
  "$EXPECTED_SHA" \
  "$ARCHIVE/blocks.bin.part" |
  sha256sum -c -

mv \
  "$ARCHIVE/blocks.bin.part" \
  "$ARCHIVE/blocks.bin"

SOURCE_OK=YES

printf '%s\n' \
  "source_sha256=$EXPECTED_SHA" \
  > "$REPORT/asset.txt"

STEP=policy

echo 'Running PR100 policy tests'

python3 -m unittest discover \
  -s src/scripts \
  -p test_pr100_production_gate.py \
  -v \
  > "$REPORT/policy-tests.log" 2>&1 || {
    cat "$REPORT/policy-tests.log"
    exit 3
  }

tail -n 8 "$REPORT/policy-tests.log"

STEP=rust-mainnet
python3 .github/pr100-compact-v3-patch.py
python3 .github/pr100-v3-hardening.py
# Exact bytes to be promoted, before test-only instrumentation.
sha256sum \
  src/crates/nightfall-storage/src/checkpoint.rs \
  src/crates/nightfall-storage/src/lib.rs \
  src/crates/nightfall-storage/tests/pr100_real_checkpoint_acceptance.rs \
  > "$REPORT/patched-source.sha256"
(
  cd src
  cargo test --release --locked -p nightfall-storage --lib -- --nocapture
) > "$REPORT/compact-unit-tests.log" 2>&1 || {
  tail -n 120 "$REPORT/compact-unit-tests.log"
  exit 3
}
tail -n 15 "$REPORT/compact-unit-tests.log"
python3 - <<'DIAGPY'
from pathlib import Path

p = Path(
    'src/crates/nightfall-storage/tests/'
    'pr100_real_checkpoint_acceptance.rs'
)

s = p.read_text(encoding='utf-8')

helper_marker = 'struct Cleanup(PathBuf);'

helper = '''
fn measure_json<T: serde::Serialize>(value: &T) -> usize {
    struct Count(usize);

    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(b.len());
            Ok(b.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut count = Count(0);

    serde_json::to_writer(
        &mut count,
        value
    ).unwrap();

    count.0
}
'''

assert s.count(helper_marker) == 1

s = s.replace(
    helper_marker,
    helper + '\n' + helper_marker,
    1
)

counts_marker = '    drop(snapshot);'

counts = '''
    eprintln!(
        "PR100_DIAG_COMPONENTS headers_count={} recent_bodies_count={} utxos_count={} headers_json_bytes={} recent_bodies_json_bytes={} utxos_json_bytes={}",
        snapshot.headers.len(),
        snapshot.recent_bodies.len(),
        snapshot.utxos.len(),
        measure_json(&snapshot.headers),
        measure_json(&snapshot.recent_bodies),
        measure_json(&snapshot.utxos),
    );

    let binary_total =
        bincode::serialized_size(&snapshot).unwrap();

    let binary_headers =
        bincode::serialized_size(&snapshot.headers).unwrap();

    let binary_bodies =
        bincode::serialized_size(&snapshot.recent_bodies).unwrap();

    let binary_utxos =
        bincode::serialized_size(&snapshot.utxos).unwrap();

    let metadata_bytes: u64 = snapshot.utxos.iter().map(|u|
        bincode::serialized_size(
            &(&u.commit, &u.output_pk, u.height)
        ).unwrap()
    ).sum();

    let minimal_dedup_estimate = binary_total
        .saturating_sub(binary_utxos)
        .saturating_add(metadata_bytes + 8);

    eprintln!(
        "PR100_DIAG_BINARY total_bytes={} headers_bytes={} bodies_bytes={} utxos_bytes={} utxo_metadata_bytes={} dedup_estimated_bytes={}",
        binary_total,
        binary_headers,
        binary_bodies,
        binary_utxos,
        metadata_bytes,
        minimal_dedup_estimate,
    );

    let binary_file =
        scratch.join("checkpoint-diagnostic-bincode.bin");

    {
        let writer = std::io::BufWriter::new(
            std::fs::File::create(&binary_file).unwrap()
        );

        bincode::serialize_into(
            writer,
            &snapshot
        ).unwrap();
    }

    let binary_disk_bytes =
        std::fs::metadata(&binary_file).unwrap().len();

    assert_eq!(binary_disk_bytes, binary_total);

    let gzip_file =
        scratch.join("checkpoint-diagnostic-bincode.gz");

    let gzip_result = std::process::Command::new("gzip")
        .arg("-1")
        .arg("-c")
        .arg(&binary_file)
        .stdout(std::process::Stdio::from(
            std::fs::File::create(&gzip_file).unwrap()
        ))
        .status();

    if let Ok(status) = gzip_result {
        if status.success() {
            let gz =
                std::fs::metadata(&gzip_file).unwrap().len();

            eprintln!(
                "PR100_DIAG_BINARY_GZIP bytes={}",
                gz
            );
        } else {
            eprintln!(
                "PR100_DIAG_BINARY_GZIP unavailable_status"
            );
        }
    } else {
        eprintln!(
            "PR100_DIAG_BINARY_GZIP unavailable_command"
        );
    }
'''

assert s.count(counts_marker) == 1

s = s.replace(
    counts_marker,
    counts + '\n' + counts_marker,
    1
)

assert_marker = (
    '    assert!(\n'
    '        snapshot_bytes > 0 && '
    'snapshot_bytes <= 512 * 1024 * 1024,'
)

assert s.count(assert_marker) == 1

s = s.replace(
    assert_marker,
    '    eprintln!("PR100_DIAG_SNAPSHOT_SIZE bytes={} cap_bytes=536870912", snapshot_bytes);\n'
    + assert_marker,
    1
)

p.write_text(s, encoding='utf-8')

print(
    'Temporärer Runner-Test instrumentiert; '
    'Importgrenze unveraendert.'
)
DIAGPY

export NF_PR100_ARCHIVE_COPY="$ARCHIVE"

echo 'Running actual Rust Mainnet checkpoint export/import/catch-up comparison'

cd src

if timeout -k 30s 9600s \
  cargo test \
    --release \
    --locked \
    -p nightfall-storage \
    --test pr100_real_checkpoint_acceptance \
    -- \
    --ignored \
    --nocapture \
  > "$REPORT/mainnet-test.log" 2>&1; then

  TEST_RC=0

else

  TEST_RC=$?

fi

cd ..

tail -n 45 "$REPORT/mainnet-test.log"

[[ "$TEST_RC" -eq 0 ]] || {
  echo "Rust acceptance FAILED rc=$TEST_RC" >&2
  exit 4
}

STEP=verify-receipt

python3 - "$REPORT/mainnet-test.log" <<'PY'
import importlib.util
import pathlib
import sys

s = importlib.util.spec_from_file_location(
    'gate',
    'src/scripts/pr100_production_gate.py'
)

m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)

log = pathlib.Path(
    sys.argv[1]
).read_text(errors='replace')

assert 'test result: ok. 1 passed;' in log

metrics = m.parse_mainnet_pass(log)

assert metrics, (
    'Real Mainnet marker missing, '
    'duplicated, or contradictory'
)

print(
    'REAL MAINNET RUST RECEIPT VALID:',
    metrics
)
PY

STEP=source-preservation

printf '%s  %s\n' \
  "$EXPECTED_SHA" \
  "$ARCHIVE/blocks.bin" |
  sha256sum -c -

AFTER_SHA=YES

STEP=completed

printf 'EXPERIMENTAL_PASS_HARDENED: modified v3 prototype on disposable runner, not original PR code.\n'
