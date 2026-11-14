#!/usr/bin/env bash
# scripts/recon.sh
# recon.sh — bughunter-lite COLLECTION-ONLY recon for ONE authorized domain.
# Scope is enforced later in Python (deny-wins); this script only collects.
# Usage: recon.sh <domain> <outdir>
set -euo pipefail

UA="${BH_UA:-bughunter-lite/0.2 (+authorized-testing)}"
case "$UA" in *"YWH- tester"*) ;; *) UA="$UA YWH- tester " ;; esac

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <domain> <outdir>" >&2
  exit 2
fi

DOMAIN="$1"
OUT="$2"
mkdir -p "$OUT"

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

count() { if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }

echo "[*] recon.sh target=$DOMAIN out=$OUT"

# 1 subdomains ------------------------------------------------------------
if have subfinder; then
  subfinder -d "$DOMAIN" -all -silent -o "$OUT/subs.txt" || true
else
  echo "[skip] subfinder not found"; touch "$OUT/subs.txt"
fi

# 2 live hosts + fingerprint ---------------------------------------------
# Build the candidate list on disk first: a pipe into httpx can SIGPIPE under
# set -o pipefail, whereas feeding a file with -list is deterministic.
{ cat "$OUT/subs.txt" 2>/dev/null || true; echo "$DOMAIN"; } | sort -u > "$OUT/candidates.txt"
if have httpx; then
  # Compliance: -rlm 80 caps requests/MINUTE; route target traffic via Burp.
  httpx -list "$OUT/candidates.txt" -silent -json -sc -title -td -ip -cdn -rlm 80 \
    ${BH_PROXY:+-proxy "$BH_PROXY"} -H "User-Agent: $UA" -o "$OUT/live.jsonl" || true
  if have jq; then
    jq -r '.url' "$OUT/live.jsonl" 2>/dev/null | sort -u > "$OUT/live.txt" || true
  else
    echo "[skip] jq not found — deriving live.txt without it"
    grep -oE '"url":"[^"]+"' "$OUT/live.jsonl" 2>/dev/null | cut -d'"' -f4 | sort -u > "$OUT/live.txt" || true
  fi
else
  echo "[skip] httpx not found"; touch "$OUT/live.jsonl"
  cp "$OUT/candidates.txt" "$OUT/live.txt"
fi

# 3 URL collection (merge all into urls.txt) ------------------------------
touch "$OUT/urls.txt"
if have curl; then
  curl -sS -m 120 --retry 2 -A "$UA" \
    "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" \
    | append_to "$OUT/urls.txt" || true
else
  echo "[skip] curl not found"
fi

if have gau; then
  gau --subs "$DOMAIN" --threads 5 | append_to "$OUT/urls.txt" || true
else
  echo "[skip] gau not found"
fi

if have waymore; then
  waymore -i "$DOMAIN" -mode U -oU "$OUT/urls_waymore.txt" \
    && cat "$OUT/urls_waymore.txt" | append_to "$OUT/urls.txt" || true
else
  echo "[skip] waymore not found"
fi

if have katana; then
  # Compliance: -rlm 80 caps requests/MINUTE; route target traffic via Burp.
  katana -list "$OUT/live.txt" -jc -kf all -d 3 -c 5 -rlm 80 -silent \
    ${BH_PROXY:+-proxy "$BH_PROXY"} -H "User-Agent: $UA" \
    | append_to "$OUT/urls.txt" || true
else
  echo "[skip] katana not found"
fi

# static-noise trim (KEEP .js) — drop binary/font/media/style noise early so
# gf, unfurl and the JS hand-off below work on a cleaner URL set.
if [ -s "$OUT/urls.txt" ]; then
  grep -viE '\.(png|jpe?g|gif|svg|woff2?|ttf|ico|css|mp4|webm|avi|webp)(\?|$)' "$OUT/urls.txt" > "$OUT/urls.clean" || true
  mv "$OUT/urls.clean" "$OUT/urls.txt"
fi

# 4 gf "statistically vulnerable" sorting ---------------------------------
if have gf; then
  for p in redirect ssrf sqli xss lfi idor rce ; do
    gf "$p" < "$OUT/urls.txt" > "$OUT/gf_$p.txt" 2>/dev/null || true
  done
else
  echo "[skip] gf not found"
fi

# 5 parameters ------------------------------------------------------------
if have unfurl; then
  cat "$OUT/urls.txt" | unfurl --unique keys | append_to "$OUT/params.txt" || true
else
  echo "[skip] unfurl not found"; touch "$OUT/params.txt"
fi
# optional active param brute (opt-in via a --active flag):
#   arjun -u "https://$DOMAIN/" -m GET -oJ "$OUT/arjun.json"

# 6 JS discovery hand-off -------------------------------------------------
touch "$OUT/jsfiles.txt"
grep -iE '\.js(\?|$)' "$OUT/urls.txt" | append_to "$OUT/jsfiles.txt" || true
if have subjs; then
  cat "$OUT/live.txt" | subjs | append_to "$OUT/jsfiles.txt" || true
else
  echo "[skip] subjs not found"
fi

# counts summary ----------------------------------------------------------
echo
echo "[*] recon.sh summary for $DOMAIN"
printf '    %-12s %s\n' "subs"    "$(count "$OUT/subs.txt")"
printf '    %-12s %s\n' "live"    "$(count "$OUT/live.txt")"
printf '    %-12s %s\n' "urls"    "$(count "$OUT/urls.txt")"
printf '    %-12s %s\n' "params"  "$(count "$OUT/params.txt")"
printf '    %-12s %s\n' "jsfiles" "$(count "$OUT/jsfiles.txt")"
for p in redirect ssrf sqli xss lfi idor rce ; do
  [ -f "$OUT/gf_$p.txt" ] && printf '    %-12s %s\n' "gf_$p" "$(count "$OUT/gf_$p.txt")"
done
echo "[*] done."
