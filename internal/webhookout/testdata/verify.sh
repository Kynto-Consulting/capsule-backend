#!/usr/bin/env bash
# Verifies a Git Capsule webhook delivery with openssl. The RAW body is read from stdin.
#
#   CAPSULE_SECRET=whsec_... CAPSULE_TIMESTAMP=... CAPSULE_SIGNATURE=sha256=... ./verify.sh < body.json
#
# Optional: CAPSULE_SECRET_PREVIOUS / CAPSULE_SIGNATURE_PREVIOUS (24 h after a rotation) and
# CAPSULE_NOW (unix seconds, for tests). Exit 0 = authentic and fresh, 1 = reject.
set -u
now="${CAPSULE_NOW:-$(date +%s)}"
ts="${CAPSULE_TIMESTAMP:-}"
case "$ts" in ''|*[!0-9]*) exit 1 ;; esac
diff=$(( now - ts )); [ "$diff" -lt 0 ] && diff=$(( -diff ))
[ "$diff" -gt 300 ] && exit 1 # replay window

body="$(mktemp)"; trap 'rm -f "$body"' EXIT
cat > "$body"

ok=1
for secret in "${CAPSULE_SECRET:-}" "${CAPSULE_SECRET_PREVIOUS:-}"; do
  [ -z "$secret" ] && continue
  want="sha256=$( { printf '%s.' "$ts"; cat "$body"; } | openssl dgst -sha256 -hmac "$secret" -hex | sed 's/^.*= //')"
  for got in "${CAPSULE_SIGNATURE:-}" "${CAPSULE_SIGNATURE_PREVIOUS:-}"; do
    [ -z "$got" ] && continue
    # bash cannot compare in constant time: compare the digests of both strings instead, so the
    # comparison does not leak how many leading characters matched
    a="$(printf '%s' "$got" | openssl dgst -sha256 -hex | sed 's/^.*= //')"
    b="$(printf '%s' "$want" | openssl dgst -sha256 -hex | sed 's/^.*= //')"
    [ "$a" = "$b" ] && ok=0
  done
done
exit $ok
