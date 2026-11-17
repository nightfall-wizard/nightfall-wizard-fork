#!/usr/bin/env bash
set -Eeuo pipefail

mkdir -p evidence

[[ "$(git -C source rev-parse HEAD)" == \
  '739b0163b0db6caec672a0bb0aca60fda668dfaf' ]] ||
  exit 2

[[ -z "$(git -C source status --porcelain)" ]] ||
  exit 2

(
  cd source

  cargo fmt --all

  cargo fmt --all -- --check

  git diff --check
)

python3 - <<'PY'
import hashlib
import pathlib
import subprocess
import json

root = pathlib.Path('source')

allowed = {
    'crates/nightfall-storage/src/checkpoint.rs',
    'crates/nightfall-storage/src/lib.rs',
    'crates/nightfall-storage/tests/pr100_real_checkpoint_acceptance.rs',
}

changed = subprocess.check_output([
    'git', '-C', 'source',
    'diff', '--name-only', '-z'
]).decode().strip('\0').split('\0')

assert changed != ['']
assert set(changed).issubset(allowed), (
    f'unexpected files: {changed!r}'
)

patch = subprocess.check_output([
    'git', '-C', 'source',
    'diff', '--binary',
    '--', *sorted(changed)
])

assert patch.startswith(b'diff --git a/')

pathlib.Path(
    'evidence/format.patch'
).write_bytes(patch)

sums = {
    k: hashlib.sha256(
        (root / k).read_bytes()
    ).hexdigest()
    for k in sorted(changed)
}

pathlib.Path(
    'evidence/manifest.json'
).write_text(
    json.dumps({
        'pr_head': '739b0163b0db6caec672a0bb0aca60fda668dfaf',
        'changed': sorted(changed),
        'sha256': sums,
        'patch_sha256': hashlib.sha256(
            patch
        ).hexdigest(),
        'format_only': True,
    }, indent=2) + '\n'
)

print('Formatted Rust files:', changed)

print(
    'Patch SHA256:',
    hashlib.sha256(patch).hexdigest()
)
PY
