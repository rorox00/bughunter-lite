#!/usr/bin/env bash
# scripts/jsanalyze.sh
# jsanalyze.sh — bughunter-lite DETERMINISTIC extraction from downloaded JS.
# Reads JSDIR (js/*.js, maps/*, urlmap.txt) and emits one file per data point:
# endpoints, params, apis, secrets, libs, sinks, routes, flags, comments, tech,
# plus deobfuscated bundles and sourcemap-recovered source. No judgement here;
# scope-filtering and secret redaction happen later in Python.
# Usage: jsanalyze.sh <jsdir> <outdir>
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <jsdir> <outdir>" >&2
  exit 2
fi

JSDIR="$1"
OUT="$2"
mkdir -p "$OUT/deob" "$OUT/src"

# Gate every tool: a missing one is skipped, not fatal.
have() { command -v "$1" >/dev/null 2>&1; }

# Ensure all outputs exist so the summary is stable even when a stage skips.
for o in endpoints params apis secrets sinks routes flags comments tech ; do
  touch "$OUT/$o.txt"
done

echo "[*] jsanalyze.sh jsdir=$JSDIR out=$OUT"

# deobfuscate / unminify each bundle (webcrack unpacks webpack + deobfuscates)
for f in "$JSDIR"/js/*.js ; do
  [ -e "$f" ] || continue
  n="$(basename "$f" .js)"
  npx -y webcrack "$f" -o "$OUT/deob/$n" 2>/dev/null || js-beautify "$f" > "$OUT/deob/$n.js" 2>/dev/null || cp "$f" "$OUT/deob/$n.js"
done

# recover ORIGINAL source from sourcemaps (huge signal boost)
if have sourcemapper && [ -f "$JSDIR/urlmap.txt" ]; then
  while read -r sha1 url ; do
    [ -z "${url:-}" ] && continue
    sourcemapper -url "${url}.map" -output "$OUT/src/$sha1" 2>/dev/null || true
  done < "$JSDIR/urlmap.txt"
else
  echo "[skip] sourcemapper or urlmap.txt missing"
fi

# ENDPOINTS (jsluice primary, xnLinkFinder fallback)
if have jsluice && have jq; then
  for f in "$JSDIR"/js/*.js ; do
    [ -e "$f" ] || continue
    origin="$(grep " ${f##*/}$" "$JSDIR/urlmap.txt" 2>/dev/null | awk '{print $2}' | head -1 || true)"
    jsluice urls -R "${origin:-https://example}" "$f" 2>/dev/null | jq -r '.url' >> "$OUT/endpoints.txt" || true
  done
else
  echo "[skip] jsluice/jq missing — no jsluice endpoints"
fi
command -v xnLinkFinder >/dev/null && xnLinkFinder -i "$JSDIR/js/" -o cli 2>/dev/null >> "$OUT/endpoints.txt" || true
sort -u -o "$OUT/endpoints.txt" "$OUT/endpoints.txt" || true

# PARAMS
grep -rhoE '[?&][A-Za-z0-9_-]{2,40}=' "$JSDIR/js" 2>/dev/null | tr -d '?&=' | sort -u > "$OUT/params.txt" || true

# APIS (group + flag old versions)
grep -rhoE '/(api|v[0-9]+|internal|graphql)[A-Za-z0-9_/.-]*' "$JSDIR/js" 2>/dev/null | sort -u > "$OUT/apis.txt" || true

# SECRETS (known regex + high entropy)
if have jsluice; then
  for f in "$JSDIR"/js/*.js ; do
    [ -e "$f" ] || continue
    jsluice secrets "$f" 2>/dev/null >> "$OUT/secrets.txt" || true
  done
else
  echo "[skip] jsluice missing — no jsluice secrets"
fi
if have trufflehog; then
  trufflehog filesystem "$JSDIR/js" --json 2>/dev/null >> "$OUT/secrets.txt" || true
else
  echo "[skip] trufflehog missing"
fi

# LIBRARIES + known CVEs
if have retire; then
  retire --path "$JSDIR/js" --outputformat json --outputpath "$OUT/libs.json" 2>/dev/null || true
else
  echo "[skip] retire missing"; : > "$OUT/libs.json"
fi

# DANGEROUS FUNCTIONS / GADGETS (DOM-XSS, redirect, postMessage, prototype pollution, RCE sinks)
# Minified bundles are often one line; cut -c 1-300 keeps the match without
# dumping megabytes of surrounding bundle code into the output files.
grep -rnE 'eval\(|new Function\(|innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|insertAdjacentHTML|\.html\(|setTimeout\(["'"'"'\x60]|postMessage|addEventListener\(["'"'"'\x60]message|localStorage|sessionStorage|location\s*=|\.src\s*=|child_process|exec\(' "$JSDIR/js" 2>/dev/null | cut -c 1-300 > "$OUT/sinks.txt" || true

# ROUTES / FEATURE FLAGS / INTERESTING COMMENTS
grep -rinE '/(admin|internal|debug|actuator|console|manage)[A-Za-z0-9_/.-]*' "$JSDIR/js" 2>/dev/null | cut -c 1-300 | sort -u > "$OUT/routes.txt" || true
grep -rinE '(feature|flag|toggle|isEnabled|experiment)[A-Za-z0-9_]*' "$JSDIR/js" 2>/dev/null | cut -c 1-300 | sort -u > "$OUT/flags.txt" || true
grep -rnE '(//|/\*).*(TODO|FIXME|HACK|password|secret|internal|deprecated|apikey|token)' "$JSDIR/js" 2>/dev/null | cut -c 1-300 > "$OUT/comments.txt" || true

# TECH / FRAMEWORK
grep -rinoE 'react|angular|vue|next|nuxt|webpack|graphql|apollo|svelte|jquery' "$JSDIR/js" 2>/dev/null | sort -u > "$OUT/tech.txt" || true

# summary ----------------------------------------------------------------
count_lines() { if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }
{
  echo "jsanalyze summary ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  for o in endpoints params apis secrets libs.json sinks routes flags comments tech ; do
    name="$o"; file="$OUT/$o"
    case "$o" in libs.json) : ;; *) file="$OUT/$o.txt" ;; esac
    printf '    %-12s %s\n' "$name" "$(count_lines "$file")"
  done
} | tee "$OUT/jsanalyze_summary.txt"
echo "[*] done."
