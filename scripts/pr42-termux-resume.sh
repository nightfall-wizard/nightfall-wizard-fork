#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
WORK="$HOME/nightfall-pr42-review-20261019-203332-16069"
test -d "$WORK" || { echo "STOP: PR-Arbeitskopie fehlt."; exit 1; }
cd "$WORK"
test "$(git rev-parse --abbrev-ref HEAD)" = "pr42-safe-16069" || { echo "STOP: Nicht auf der erwarteten PR-Branch."; exit 1; }
test "$(git rev-parse HEAD)" = "$(git rev-parse refs/remotes/pr42-upstream/main)" || { echo "STOP: PR-Branch weicht vom getesteten Ausgangspunkt ab."; exit 1; }
python3 - <<'PY'
from pathlib import Path
p=Path("crates/nightfall-node/src/recovery.rs")
s=p.read_text()
import re
pattern = re.compile(
    r'for\s*\(\s*name\s*,\s*_\s*\)\s*in\s*&original\s*\{\s*'
    r'fs::remove_file\(\s*tmp\.0\.join\(\s*name\s*\)\s*\)\.unwrap\(\);\s*\}'
)
replacement = """for (name, _) in &original {
                    let path = tmp.0.join(name);
                    if path.exists() {
                        fs::remove_file(path).unwrap();
                    }
                }"""
matches = list(pattern.finditer(s))
if len(matches) == 1:
    s = pattern.sub(replacement, s, count=1)
    p.write_text(s)
    print("Recovery-Restore-Test korrigiert.")
elif "let path = tmp.0.join(name);" in s and "if path.exists()" in s:
    print("Testkorrektur bereits vorhanden.")
else:
    raise SystemExit("STOP: Restore-Test passt nicht zum erwarteten Code; kein Push.")
PY
echo "[1/4] Formatierung"
cargo fmt --all
cargo fmt --all -- --check
git diff --check
echo "[2/4] Alle 7 Recovery-Tests"
cargo test -p nightfall-node --bin nightfalld recovery::tests -j 1 -- --test-threads=1
echo "[3/4] Reale CLI-/Sperr-Tests und Clippy"
cargo test -p nightfall-node --test recovery_cli -j 1 -- --test-threads=1
cargo clippy -p nightfall-node --bin nightfalld --tests -j 1 -- -D warnings
git diff --check
echo "[4/4] Gepruefte Aenderungen sichern und PR aktualisieren"
git add crates/nightfall-node/src/main.rs crates/nightfall-node/src/recovery.rs crates/nightfall-node/tests/recovery_cli.rs docs/RECOVER-STALLED-FORK.md
git diff --cached --check
CHANGED="$(git diff --cached --name-only)"
test "$(printf '%s\n' "$CHANGED" | grep -Ec '^(crates/nightfall-node/src/(main|recovery)\.rs|crates/nightfall-node/tests/recovery_cli\.rs|docs/RECOVER-STALLED-FORK\.md)$')" = 4 || { echo "STOP: Unerwartete PR-Dateien"; exit 1; }
test "$(printf '%s\n' "$CHANGED" | wc -l | tr -d ' ')" = 4 || { echo "STOP: Unerwartete PR-Dateien"; exit 1; }
OLD="$(git rev-parse refs/remotes/pr42-fork/old)"
git -c user.name=nightfall-wizard -c user.email=nightfall-wizard@users.noreply.github.com commit -m "node: rebase and harden offline stalled-fork recovery"
git push --force-with-lease="refs/heads/wvp/stalled-fork-recovery-escape-hatch:$OLD" https://github.com/nightfall-wizard/nightfall-wizard-fork.git HEAD:refs/heads/wvp/stalled-fork-recovery-escape-hatch
echo "OK: PR #42 aktualisiert (Draft)."
echo "https://github.com/Instinctes/nightfall/pull/42"
