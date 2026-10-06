#!/usr/bin/env sh
# scripts/check-secrets.sh
# Scannt den Repo-Baum nach echten Secrets.
# Ausgenommen sind Dateien, deren Zweck es ist, verbotene Muster zu nennen.

set -eu

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

EXCLUDES='
scripts/check-secrets.sh
scripts/check-docs-version.sh
SECURITY.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
.github/
'

is_excluded() {
  for pat in $EXCLUDES; do
    case "$1" in
      $pat|$pat*) return 0 ;;
      */$pat|*/$pat*) return 0 ;;
    esac
  done
  return 1
}

files=$(git ls-files)

fail=0
note() { printf 'FEHLER: %s\n' "$1" >&2; fail=1; }

for f in $files; do
  is_excluded "$f" && continue
  [ -f "$f" ] || continue

  # 1) Echte PEM-Bloecke: BEGIN und END in derselben Datei.
  if grep -q -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$f" 2>/dev/null \
     && grep -q -- '-----END [A-Z ]*PRIVATE KEY-----'   "$f" 2>/dev/null; then
    note "$f enthaelt einen PEM Private-Key-Block"
  fi

  # 2) Klassische Token-Formen mit festen Praefixen (hohe Zuverlaessigkeit).
  if grep -nE '(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,}|sk-[A-Za-z0-9]{40,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})' "$f" 2>/dev/null >/dev/null; then
    note "$f enthaelt ein Token mit bekanntem Praefix"
  fi

  # 3) BIP-39-Mnemonic nur in Nicht-Prosa-Dateien pruefen.
  #    Prosa (Markdown/Text) beschreibt Seeds, enthaelt aber keine;
  #    eine Regex kann 12 englische Woerter nicht von einem Satz trennen.
  case "$f" in
    *.md|*.txt|*.rst|*.adoc) ;;
    *)
      if grep -nE '^([a-z]{3,8} ){11}[a-z]{3,8}$|^([a-z]{3,8} ){14}[a-z]{3,8}$|^([a-z]{3,8} ){17}[a-z]{3,8}$|^([a-z]{3,8} ){20}[a-z]{3,8}$|^([a-z]{3,8} ){23}[a-z]{3,8}$' "$f" 2>/dev/null >/dev/null; then
        note "$f koennte eine Seed-Phrase im Klartext enthalten"
      fi
      ;;
  esac
done

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "FEHLER: Moegliche Secrets gefunden. Abbruch." >&2
  exit 1
fi

echo "Secret-Scan OK: keine echten Secrets gefunden."
