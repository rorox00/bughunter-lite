#!/usr/bin/env bash
# scripts/install.sh
# Copy-install bughunter-lite skills into harness skill paths, backing up any
# existing same-named skill first. Default target is Claude Code only.
#   (default)       ~/.claude/skills
#   --agents        + ~/.agents/skills        (Codex + OpenCode)
#   --hermes        + ~/.hermes/skills
#   --antigravity   + ~/.gemini/config/skills
#   --all           all of the above
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$REPO/skills"

[ -d "$SRC" ] || { echo "no skills directory at $SRC" >&2; exit 1; }

declare -a TARGETS=("$HOME/.claude/skills")
add_target() { TARGETS+=("$1"); }

for arg in "$@"; do
  case "$arg" in
    --agents)      add_target "$HOME/.agents/skills" ;;
    --hermes)      add_target "$HOME/.hermes/skills" ;;
    --antigravity) add_target "$HOME/.gemini/config/skills" ;;
    --all)
      add_target "$HOME/.agents/skills"
      add_target "$HOME/.hermes/skills"
      add_target "$HOME/.gemini/config/skills"
      ;;
    -h|--help)
      echo "usage: install.sh [--agents] [--hermes] [--antigravity] [--all]"
      exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

# Dedup targets (e.g. --all --agents).
declare -A seen
declare -a UNIQ=()
for t in "${TARGETS[@]}"; do
  if [ -z "${seen[$t]:-}" ]; then
    seen[$t]=1
    UNIQ+=("$t")
  fi
done

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_ROOT="$REPO/.skill-backups/$TS"
installed=0

for target in "${UNIQ[@]}"; do
  mkdir -p "$target"
  label="$(printf '%s' "$target" | sed 's#/#_#g; s#^_##')"
  for sdir in "$SRC"/*/; do
    [ -d "$sdir" ] || continue
    name="$(basename "$sdir")"
    dest="$target/$name"
    if [ -e "$dest" ]; then
      mkdir -p "$BACKUP_ROOT/$label"
      mv "$dest" "$BACKUP_ROOT/$label/$name"
      echo "[backup]  $dest -> $BACKUP_ROOT/$label/$name"
    fi
    cp -r "$SRC/$name" "$dest"
    echo "[install] $name -> $dest"
    installed=$((installed + 1))
  done
done

echo "installed $installed skill(s) into ${#UNIQ[@]} path(s)"
[ -d "$BACKUP_ROOT" ] && echo "backups saved in $BACKUP_ROOT" || true
