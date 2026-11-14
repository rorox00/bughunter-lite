#!/usr/bin/env bash
# scripts/jsdiscover.sh
# jsdiscover.sh — bughunter-lite JS DISCOVER + DOWNLOAD (separate from analysis).
# Finds JS via inline + files + spider + lazy(headless) + historical, fetches
# each with an anti-automation fallback chain, and stores by content hash
# (sha1) for dedup + resume. Scope is enforced later in Python (deny-wins).
# Usage: jsdiscover.sh <jsfiles.txt> <live.txt> <outdir>
set -euo pipefail

UA="bughunter-lite/0.2 (+authorized-testing)"

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <jsfiles.txt> <live.txt> <outdir>" >&2
  exit 2
fi

JSFILES="$1"
LIVE="$2"
OUT="$3"
mkdir -p "$OUT/js" "$OUT/maps"
touch "$JSFILES"

# Gate every tool: a missing one is skipped, not fatal.
have() { command -v "$1" >/dev/null 2>&1; }

# Append stdin to a file with dedup: prefer anew, else sort -u in place.
append_to() {
  local f="$1"
  touch "$f"
  if have anew; then
    anew "$f"
  else
    local tmp
    tmp="$(mktemp)"
    cat - "$f" | sort -u > "$tmp"
    mv "$tmp" "$f"
  fi
}

# sha1 of a file: prefer sha1sum, else shasum.
sha1_of() {
  if have sha1sum; then
    sha1sum "$1" | cut -d' ' -f1
  else
    shasum "$1" | cut -d' ' -f1
  fi
}

# Count files matching a glob pattern (e.g. "$OUT/js/*.js"), 0 if none.
count_pat() { local c; c=$(ls -1 $1 2>/dev/null | wc -l | tr -d ' '); echo "${c:-0}"; }
count_lines() { if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }

echo "[*] jsdiscover.sh jsfiles=$JSFILES live=$LIVE out=$OUT"

# find MORE js (spider + runtime) ----------------------------------------
if have subjs; then
  cat "$LIVE" | subjs 2>/dev/null | append_to "$JSFILES" || true
else
  echo "[skip] subjs not found"
fi
if have getJS; then
  cat "$LIVE" | getJS --complete 2>/dev/null | append_to "$JSFILES" || true
else
  echo "[skip] getJS not found"
fi
if have katana; then
  katana -list "$LIVE" -headless -jc -rlm 80 -silent ${BH_PROXY:+-proxy "$BH_PROXY"} 2>/dev/null | grep -iE '\.js(\?|$)' | append_to "$JSFILES" || true
else
  echo "[skip] katana not found"
fi

# inline js: pull <script> blocks from each live page -------------------
if have curl; then
  n=0
  while read -r purl; do
    [ -z "$purl" ] && continue
    n=$((n + 1))
    curl -s -k -A "$UA" -m 20 ${BH_PROXY:+-x "$BH_PROXY"} "$purl" 2>/dev/null \
      | grep -oE '<script[^>]*>.*</script>' > "$OUT/js/inline_$n.js" 2>/dev/null || true
    [ -s "$OUT/js/inline_$n.js" ] || rm -f "$OUT/js/inline_$n.js"
    sleep 0.8  # compliance: ~75 req/min ceiling for target fetches
  done < "$LIVE"
else
  echo "[skip] curl not found — no inline extraction"
fi

# fetch each JS with a fallback chain, store by sha1 (resume-safe) --------
if have curl; then
  while read -r url; do
    [ -z "$url" ] && continue
    tmp="$(mktemp)"
    sleep 0.8  # compliance: ~75 req/min ceiling for target fetches
    curl -s -k -A "$UA" -m 20 ${BH_PROXY:+-x "$BH_PROXY"} "$url" -o "$tmp" || true
    if [ ! -s "$tmp" ] || grep -qiE 'captcha|just a moment|cf-browser-verification' "$tmp"; then
      if have katana; then
        katana -u "$url" -headless -rlm 80 -silent ${BH_PROXY:+-proxy "$BH_PROXY"} 2>/dev/null > "$tmp" || echo "$url" >> "$OUT/blocked.txt"
      else
        echo "$url" >> "$OUT/blocked.txt"
      fi
    fi
    [ -s "$tmp" ] || { rm -f "$tmp"; continue; }
    sha1="$(sha1_of "$tmp")"
    [ -f "$OUT/js/$sha1.js" ] && { rm -f "$tmp"; continue; }   # resume: already have it
    mv "$tmp" "$OUT/js/$sha1.js"
    echo "$sha1 $url" >> "$OUT/urlmap.txt"
    # sourcemaps: inline pointer + guessed .map
    grep -oE 'sourceMappingURL=[^ ]+' "$OUT/js/$sha1.js" >> "$OUT/maps/pointers.txt" 2>/dev/null || true
    curl -s -k -A "$UA" -m 20 ${BH_PROXY:+-x "$BH_PROXY"} "${url}.map" -o "$OUT/maps/$sha1.js.map" 2>/dev/null || true
    [ -s "$OUT/maps/$sha1.js.map" ] || rm -f "$OUT/maps/$sha1.js.map"
  done < "$JSFILES"
else
  echo "[skip] curl not found — no JS download"
fi

# counts -----------------------------------------------------------------
echo
echo "[*] jsdiscover.sh summary"
printf '    %-12s %s\n' "js"         "$(count_pat "$OUT/js/*.js")"
printf '    %-12s %s\n' "sourcemaps" "$(count_pat "$OUT/maps/*.map")"
printf '    %-12s %s\n' "blocked"    "$(count_lines "$OUT/blocked.txt")"
echo "[*] done."
