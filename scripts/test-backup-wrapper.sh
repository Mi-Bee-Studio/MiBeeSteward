#!/usr/bin/env bash
# Contract test for backup.sh: it must delegate to the built-in backup command
# with the legacy positional arguments mapped to flags, and never call sqlite3.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/fake-mibee" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$BACKUP_TEST_ARGS"
SH
chmod +x "$tmp/fake-mibee"
printf 'auth:\n  jwt_secret: test-secret-at-least-32-characters\n' > "$tmp/config.yaml"

BACKUP_TEST_ARGS="$tmp/args" MIBEE_BIN="$tmp/fake-mibee" MIBEE_CONFIG="$tmp/config.yaml" \
  bash scripts/backup.sh "$tmp/data/mibee.db" "$tmp/backups" 30

expected=$'backup\n-config\n'"$tmp/config.yaml"$'\n-db\n'"$tmp/data/mibee.db"$'\n-output\n'"$tmp/backups"$'\n-retention-days\n30'
actual="$(cat "$tmp/args")"
[ "$actual" = "$expected" ] || {
  echo "backup wrapper argument mismatch" >&2
  printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
  exit 1
}

echo "backup.sh wrapper: built-in command mapping OK"
