#!/usr/bin/env bash
#
# scan-npm-shai-hulud.sh -- scan a tree for Shai-Hulud npm supply-chain indicators.
#
# Standalone and read-only. Download this one file, or copy-paste it into a local
# .sh -- it needs nothing else from this repo and installs nothing.
#
# Six checks:
#   1. Malicious payload files by name (SHA-256 printed alongside each hit)
#   2. package.json with a preinstall hook that runs a payload
#   3. Compromised package versions under node_modules (scoped included)
#   4. GitHub Actions workflows that dump the whole secrets context
#   5. IDE persistence written into .vscode/tasks.json or .claude/settings.json
#   6. Exfiltration strings -- fallback domain, campaign marker, wallet address
#
# A payload filename is reported whether or not its hash matches a known variant.
# A matching hash confirms the exact published sample; a non-matching hash means an
# unknown variant, not a clean file. Triage every hit by hand.
#
# Usage:
#   ./scan-npm-shai-hulud.sh [PATH]     # defaults to .
#   ./scan-npm-shai-hulud.sh --quiet    # findings and summary only
#
# Exit codes: 0 = nothing found, 1 = findings, 2 = bad usage.
#
# Covers two waves of the same campaign:
#   Aug 2026 -- https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack
#   Nov 2025 -- earlier Shai-Hulud wave (bun payload filenames)

set -uo pipefail

# ------------------------------------------------------------------ IoC data
# Everything the scan knows lives here. Update these tables when new indicators
# are published; nothing below needs to change.

# Aug 2026 wave
PAYLOAD_FILES=(setup.mjs math_init.js Math_Symbol.js)
# Nov 2025 wave -- carried forward, not listed in the Aug 2026 writeup
PAYLOAD_FILES+=(setup_bun.js bun_environment.js)

declare -A KNOWN_HASHES=(
  [54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668]="setup.mjs (Aug 2026)"
  [fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb]="setup.mjs community variant (Aug 2026)"
  [9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc]="Math_Symbol.js / math_init.js (Aug 2026)"
)

declare -A COMPROMISED=(
  [keyv]="6.0.0"
  [flat-cache]="6.1.24"
  [file-entry-cache]="11.1.6"
  [cacheable-request]="13.0.20"
  [cacheable]="2.5.1"
  ["@cacheable/memory"]="2.2.1"
  [cache-manager]="7.2.10"
  ["@cacheable/node-cache"]="3.1.2"
  ["@cacheable/utils"]="2.5.1"
  ["@cacheable/net"]="2.1.1"
  [ecto]="5.0.1"
)

EXFIL_STRINGS=(
  "npm-cache.com"
  "Shai-Hulud: Here We Go Again"
  "0xE1f2395ee43e45A1556EC6438a88c31B83493103"
)

# --------------------------------------------------------------------- setup

target="."
quiet=0

while [ $# -gt 0 ]; do
  case "$1" in
    --quiet|-q) quiet=1 ;;
    --help|-h)  sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)         echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    *)          target="$1" ;;
  esac
  shift
done

[ -d "$target" ] || { echo "not a directory: $target" >&2; exit 2; }

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; OFF=$'\033[0m'
[ -t 1 ] || { RED=""; GREEN=""; YELLOW=""; CYAN=""; OFF=""; }

# A plain counter in the current shell. Every loop below reads from process
# substitution, never a pipeline -- a `find ... | while read` body runs in a
# subshell and its increments are silently discarded on exit, which would print
# "Clear" directly under a FATAL line.
findings=0

finding() { findings=$((findings + 1)); printf '  %sFINDING: %s%s\n' "$RED" "$1" "$OFF"; }
clear_msg() { [ "$quiet" -eq 1 ] || printf '  %sClear: %s%s\n' "$GREEN" "$1" "$OFF"; }
check() { [ "$quiet" -eq 1 ] || printf '\n%s%s%s\n' "$YELLOW" "$1" "$OFF"; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else echo "unavailable"; fi
}

printf '%sScanning %s for Shai-Hulud IoCs...%s\n' "$CYAN" "$target" "$OFF"

# ---------------------------------------------------- 1. payload files by name

check "1. Malicious payload files"
before=$findings
find_args=()
for name in "${PAYLOAD_FILES[@]}"; do find_args+=(-o -name "$name"); done
while IFS= read -r file; do
  hash="$(sha256 "$file")"
  if [ -n "${KNOWN_HASHES[$hash]:-}" ]; then note="matches ${KNOWN_HASHES[$hash]}"
  else note="unknown variant -- hash not in the published set"; fi
  finding "$file"
  printf '           sha256 %s (%s)\n' "$hash" "$note"
done < <(find "$target" -type f \( "${find_args[@]:1}" \) 2>/dev/null)
[ "$findings" -eq "$before" ] && clear_msg "no known payload filenames"

# ------------------------------------------- 2. preinstall hook in a manifest

check "2. package.json preinstall hooks running a payload"
before=$findings
payload_alt="$(IFS='|'; echo "${PAYLOAD_FILES[*]}")"
while IFS= read -r hit; do
  finding "$hit"
done < <(find "$target" -type f -name package.json 2>/dev/null \
         | xargs -r grep -HnE "\"preinstall\"[[:space:]]*:[[:space:]]*\".*(${payload_alt})" 2>/dev/null)
[ "$findings" -eq "$before" ] && clear_msg "no payload preinstall hooks"

# -------------------------------------- 3. compromised versions in node_modules

check "3. Compromised package versions under node_modules"
before=$findings
while IFS= read -r pkg_json; do
  # Everything after the LAST node_modules/, minus /package.json, is the package
  # key. Handles nesting and @scope/name alike.
  key="${pkg_json##*/node_modules/}"
  key="${key%/package.json}"
  want="${COMPROMISED[$key]:-}"
  [ -n "$want" ] || continue

  if command -v jq >/dev/null 2>&1; then
    version="$(jq -r '.version // empty' "$pkg_json" 2>/dev/null)"
  else
    version="$(grep -m1 '"version"' "$pkg_json" | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"
  fi

  [ "$version" = "$want" ] && finding "${key}@${version} installed at $(dirname "$pkg_json")"
done < <(find "$target" -type f -path "*/node_modules/*" -name package.json 2>/dev/null)
[ "$findings" -eq "$before" ] && clear_msg "no compromised versions installed"

# ------------------------------------------- 4. workflow secret exfiltration

check "4. GitHub Actions workflows dumping secrets"
before=$findings
while IFS= read -r hit; do
  finding "$hit"
done < <(find "$target" -type f \( -name '*.yml' -o -name '*.yaml' \) -path "*/.github/workflows/*" 2>/dev/null \
         | xargs -r grep -HnE 'toJSON\([[:space:]]*secrets[[:space:]]*\)' 2>/dev/null)
[ "$findings" -eq "$before" ] && clear_msg "no secrets-context dumps in workflows"

# ---------------------------------------------------- 5. IDE persistence files

check "5. IDE persistence (.vscode / .claude)"
before=$findings
while IFS= read -r hit; do
  finding "references a payload -- $hit"
done < <(find "$target" -type f \( -path "*/.vscode/tasks.json" -o -path "*/.claude/settings.json" \) 2>/dev/null \
         | xargs -r grep -HnE "${payload_alt}" 2>/dev/null)
[ "$findings" -eq "$before" ] && clear_msg "no payload references in IDE config"

# ------------------------------------------------------ 6. exfiltration strings

check "6. Exfiltration infrastructure strings"
before=$findings
while IFS= read -r hit; do
  finding "$hit"
done < <(grep -rnIF --exclude-dir=.git \
           -e "${EXFIL_STRINGS[0]}" -e "${EXFIL_STRINGS[1]}" -e "${EXFIL_STRINGS[2]}" \
           "$target" 2>/dev/null)
[ "$findings" -eq "$before" ] && clear_msg "no exfiltration strings"

# ------------------------------------------------------------------- summary

echo
if [ "$findings" -gt 0 ]; then
  printf '%s%d finding(s) -- triage every one by hand.%s\n' "$RED" "$findings" "$OFF"
  printf '%sRotate npm/GitHub/cloud tokens before assuming this was a false positive.%s\n' "$RED" "$OFF"
  exit 1
fi

printf '%sNo indicators found in %s%s\n' "$GREEN" "$target" "$OFF"
exit 0
