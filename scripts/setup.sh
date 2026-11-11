#!/usr/bin/env bash
# setup.sh — one-time installer for the bughunter-lite recon toolchain (WSL/Linux).
# Run once: bash scripts/setup.sh  (then: source ~/.bashrc)
# Idempotent: skips anything already on PATH. One failure won't abort the rest.
set -uo pipefail
echo "[*] bughunter-lite toolchain setup"

# ---------- prereqs ----------
for p in go npm pip3 git curl; do
  command -v "$p" >/dev/null || echo "[!] MISSING PREREQ: $p — install it first (go / nodejs+npm / python3-pip)"
done
command -v jq >/dev/null || { echo "[+] apt: jq"; sudo apt-get install -y jq >/dev/null 2>&1 || echo "[x] install jq manually"; }

export GOBIN="${GOBIN:-$HOME/go/bin}"; mkdir -p "$GOBIN" "$HOME/.local/bin"

goget () {  # goget <bin-name> <module@version>
  command -v "$1" >/dev/null && { echo "[=] $1 present"; return; }
  echo "[+] go: $1"; go install "$2" >/dev/null 2>&1 && echo "[ok] $1" || echo "[x] $1 FAILED"
}

# ---------- Go tools ----------
goget subfinder         github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
goget httpx             github.com/projectdiscovery/httpx/cmd/httpx@latest
goget katana            github.com/projectdiscovery/katana/cmd/katana@latest
goget nuclei            github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
goget interactsh-client github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
goget gau               github.com/lc/gau/v2/cmd/gau@latest
goget gf                github.com/tomnomnom/gf@latest
goget subjs             github.com/lc/subjs@latest
goget unfurl            github.com/tomnomnom/unfurl@latest
goget anew              github.com/tomnomnom/anew@latest
goget qsreplace         github.com/tomnomnom/qsreplace@latest
goget jsluice           github.com/BishopFox/jsluice/cmd/jsluice@latest
goget sourcemapper      github.com/denandz/sourcemapper@latest
goget ffuf              github.com/ffuf/ffuf/v2@latest

# ---------- pip tools ----------
for t in waymore arjun xnLinkFinder; do
  command -v "$t" >/dev/null && { echo "[=] $t present"; continue; }
  echo "[+] pip: $t"; pip3 install --user -q "$t" >/dev/null 2>&1 && echo "[ok] $t" || echo "[x] $t FAILED"
done

# ---------- npm tools ----------
command -v retire >/dev/null && echo "[=] retire present" || {
  echo "[+] npm: retire"; npm i -g retire >/dev/null 2>&1 && echo "[ok] retire" || echo "[x] retire FAILED"; }
# webcrack is used via `npx -y webcrack` — no global install needed (needs Node).

# ---------- trufflehog (official installer) ----------
command -v trufflehog >/dev/null && echo "[=] trufflehog present" || {
  echo "[+] trufflehog";
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b "$HOME/.local/bin" >/dev/null 2>&1 && echo "[ok] trufflehog" || echo "[x] trufflehog FAILED"; }

# ---------- gf patterns ----------
[ -d "$HOME/.gf" ] && echo "[=] gf patterns present" || {
  echo "[+] gf patterns"; git clone -q https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf" \
    && echo "[ok] gf patterns" || echo "[x] gf patterns FAILED"; }

# ---------- PATH ----------
for d in "$HOME/go/bin" "$HOME/.local/bin"; do
  grep -q "$d" "$HOME/.bashrc" 2>/dev/null || echo "export PATH=\"\$PATH:$d\"" >> "$HOME/.bashrc"
done
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"

# ---------- verify ----------
echo ""; echo "[*] verification:"
miss=0
for t in subfinder httpx katana nuclei interactsh-client gau gf subjs unfurl anew qsreplace \
         jsluice sourcemapper ffuf waymore arjun xnLinkFinder retire trufflehog jq; do
  if command -v "$t" >/dev/null; then echo "  OK   $t"; else echo "  MISS $t"; miss=$((miss+1)); fi
done
echo ""
[ "$miss" -eq 0 ] && echo "[*] ALL TOOLS INSTALLED." || echo "[*] $miss missing — see notes above."
echo "[*] Run:  source ~/.bashrc   (or open a new shell) so PATH takes effect."
