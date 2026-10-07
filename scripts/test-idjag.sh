#!/usr/bin/env bash
#
# Exercises the ID-JAG token exchange end to end against a WSO2 IS.
#
#   ./test-idjag.sh <client_id> <client_secret> <username> <password> [audience] [scope] [resource]
#
# Step 1 uses the password grant purely because it is scriptable; any OIDC flow that yields an
# id_token works the same. Enable "Password" alongside "Token Exchange" on the application, or
# substitute an id_token you already have via ID_TOKEN=... in the environment.
#
# Point IS_BASE at a non-local server, e.g. IS_BASE=https://wso2-iam-poc.dev:8443.
set -euo pipefail

CLIENT_ID=${1:?client_id required}
CLIENT_SECRET=${2:?client_secret required}
USERNAME=${3:-}
PASSWORD=${4:-}
AUDIENCE=${5:-https://acme.chat.example}
SCOPE=${6:-chat.read chat.history}
RESOURCE=${7:-}

IS_BASE=${IS_BASE:-https://localhost:9443}
TOKEN_EP="$IS_BASE/oauth2/token"

# Decodes a JWT's header and payload. base64url needs padding restored before base64 -d.
decode_jwt() {
  local jwt=$1 part
  for part in 1 2; do
    local seg
    seg=$(cut -d. -f"$part" <<<"$jwt" | tr '_-' '/+')
    while (( ${#seg} % 4 )); do seg+="="; done
    printf '%s\n' "$seg" | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "  (undecodable)"
  done
}

claim() {                                  # claim <jwt> <part:1|2> <claim-name>
  local seg
  seg=$(cut -d. -f"$2" <<<"$1" | tr '_-' '/+')
  while (( ${#seg} % 4 )); do seg+="="; done
  printf '%s' "$seg" | base64 -d 2>/dev/null \
    | python3 -c "import json,sys; v=json.load(sys.stdin).get('$3',''); print(v if not isinstance(v,list) else ' '.join(v))"
}

echo "==> 1. Obtaining an ID token from $TOKEN_EP"
ACCESS_TOKEN=
if [[ -n "${ID_TOKEN:-}" ]]; then
  echo "    using ID_TOKEN from the environment"
else
  LOGIN_RESPONSE=$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_EP" \
    -d grant_type=password \
    --data-urlencode "username=$USERNAME" \
    --data-urlencode "password=$PASSWORD" \
    -d scope=openid)
  ID_TOKEN=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("id_token",""))' <<<"$LOGIN_RESPONSE")
  ACCESS_TOKEN=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' <<<"$LOGIN_RESPONSE")
  if [[ -z "$ID_TOKEN" ]]; then
    echo "    FAILED to get an id_token:" >&2
    python3 -m json.tool <<<"$LOGIN_RESPONSE" >&2 || echo "$LOGIN_RESPONSE" >&2
    exit 1
  fi
fi
echo "--- subject token (the IS id_token) ---"
decode_jwt "$ID_TOKEN"

echo
echo "==> 2. Exchanging it for an ID-JAG (audience=$AUDIENCE${RESOURCE:+, resource=$RESOURCE})"
EXCHANGE_ARGS=(-d grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token
  --data-urlencode "subject_token=$ID_TOKEN"
  --data-urlencode "audience=$AUDIENCE"
  --data-urlencode "scope=$SCOPE")
[[ -n "$RESOURCE" ]] && EXCHANGE_ARGS+=(--data-urlencode "resource=$RESOURCE")
EXCHANGE_RESPONSE=$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_EP" "${EXCHANGE_ARGS[@]}")

echo "--- token endpoint response ---"
python3 -m json.tool <<<"$EXCHANGE_RESPONSE" || { echo "$EXCHANGE_RESPONSE"; exit 1; }

ID_JAG=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' <<<"$EXCHANGE_RESPONSE")
if [[ -z "$ID_JAG" ]]; then
  echo "No ID-JAG was issued." >&2
  exit 1
fi

echo
echo "--- the ID-JAG (expect typ=oauth-id-jag+jwt and sub=<email>) ---"
decode_jwt "$ID_JAG"

echo
echo "==> 3. Checks"
fail=0
HEADER_TYP=$(claim "$ID_JAG" 1 typ)
SUB=$(claim "$ID_JAG" 2 sub)

[[ "$HEADER_TYP" == "oauth-id-jag+jwt" ]] \
  && echo "    OK   typ is oauth-id-jag+jwt" \
  || { echo "    FAIL typ is '$HEADER_TYP', expected oauth-id-jag+jwt"; fail=1; }
[[ "$SUB" == *@* ]] \
  && echo "    OK   sub is an email address: $SUB" \
  || { echo "    FAIL sub is '$SUB', expected an email address"; fail=1; }
for c in iss aud client_id jti iat exp; do
  [[ -n "$(claim "$ID_JAG" 2 "$c")" ]] \
    && echo "    OK   $c present" \
    || { echo "    FAIL $c missing (REQUIRED by the draft)"; fail=1; }
done
RES_CLAIM=$(claim "$ID_JAG" 2 resource)
if [[ -n "$RESOURCE" ]]; then
  [[ -n "$RES_CLAIM" ]] && echo "    OK   resource claim present: $RES_CLAIM" \
    || { echo "    FAIL resource claim missing although 'resource' was requested"; fail=1; }
else
  echo "    --   resource claim: ${RES_CLAIM:-(omitted, nothing requested or configured)}"
fi

echo
echo "==> 4. Subject token type enforcement"
echo "       The draft allows only id_token, saml2 or refresh_token as the subject token."
if [[ -n "$ACCESS_TOKEN" ]]; then
  LEGACY_RESPONSE=$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_EP" \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
    --data-urlencode "subject_token=$ACCESS_TOKEN" \
    --data-urlencode "audience=$AUDIENCE")
  if python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if "access_token" in d else 1)' <<<"$LEGACY_RESPONSE"; then
    echo "    --   access_token as subject token was ACCEPTED."
    echo "         That is only correct if oauth.idjag.allow_access_token_subject_token = true (legacy mode)."
  else
    ERR=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("error",""))' <<<"$LEGACY_RESPONSE")
    echo "    OK   access_token as subject token was rejected ($ERR), as the draft requires."
  fi
else
  echo "    --   skipped (no access token at hand; ID_TOKEN came from the environment)"
fi
SAML_RESPONSE=$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_EP" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag \
  -d subject_token_type=urn:ietf:params:oauth:token-type:saml2 \
  --data-urlencode "subject_token=$ID_TOKEN" \
  --data-urlencode "audience=$AUDIENCE")
if python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if "access_token" in d else 1)' <<<"$SAML_RESPONSE"; then
  echo "    FAIL saml2 subject_token_type was accepted; it is not implemented and must be rejected"; fail=1
else
  echo "    OK   saml2 subject_token_type rejected (not implemented)"
fi

echo
echo "==> 5. Refresh token as subject token (draft: allowed when the IdP supports it)"
REFRESH_TOKEN=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("refresh_token",""))' <<<"${LOGIN_RESPONSE:-{\}}")
if [[ -z "$REFRESH_TOKEN" ]]; then
  echo "    --   skipped: the login response carried no refresh_token (enable the Refresh Token grant on the app)"
else
  RT_RESPONSE=$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_EP" \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag \
    -d subject_token_type=urn:ietf:params:oauth:token-type:refresh_token \
    --data-urlencode "subject_token=$REFRESH_TOKEN" \
    --data-urlencode "audience=$AUDIENCE")
  RT_JAG=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' <<<"$RT_RESPONSE")
  if [[ -n "$RT_JAG" ]]; then
    RT_SUB=$(claim "$RT_JAG" 2 sub)
    [[ "$RT_SUB" == "$SUB" ]] \
      && echo "    OK   ID-JAG issued from the refresh token for the same subject: $RT_SUB" \
      || { echo "    FAIL ID-JAG from refresh token has sub '$RT_SUB', expected '$SUB'"; fail=1; }
    [[ "$(claim "$RT_JAG" 1 typ)" == "oauth-id-jag+jwt" ]] \
      && echo "    OK   typ is oauth-id-jag+jwt" || { echo "    FAIL typ"; fail=1; }
  else
    ERR=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("error",""), "-", d.get("error_description",""))' <<<"$RT_RESPONSE")
    echo "    --   rejected: $ERR"
    echo "         (correct only if oauth.idjag.allow_refresh_token_subject_token = false)"
  fi
  SCOPE_RESPONSE=$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_EP" \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag \
    -d subject_token_type=urn:ietf:params:oauth:token-type:refresh_token \
    --data-urlencode "subject_token=$REFRESH_TOKEN" \
    --data-urlencode "audience=$AUDIENCE" \
    -d scope=idjag.test.not.granted)
  [[ "$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("error",""))' <<<"$SCOPE_RESPONSE")" == "invalid_scope" ]] \
    && echo "    OK   a scope outside the refresh token's grant is rejected with invalid_scope" \
    || { echo "    FAIL scope outside the refresh token's grant was not rejected with invalid_scope: $SCOPE_RESPONSE"; fail=1; }
  AFTER=$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_EP" -d grant_type=refresh_token \
    --data-urlencode "refresh_token=$REFRESH_TOKEN")
  python3 -c 'import json,sys; sys.exit(0 if "access_token" in json.load(sys.stdin) else 1)' <<<"$AFTER" \
    && echo "    OK   the refresh token is still usable afterwards (the exchange does not consume it)" \
    || { echo "    FAIL the refresh token no longer works after the exchange"; fail=1; }
  BAD=$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_EP" \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag \
    -d subject_token_type=urn:ietf:params:oauth:token-type:refresh_token \
    -d subject_token=not-a-real-refresh-token \
    --data-urlencode "audience=$AUDIENCE")
  [[ "$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("error",""))' <<<"$BAD")" == "invalid_grant" ]] \
    && echo "    OK   an unknown refresh token is rejected with invalid_grant" \
    || { echo "    FAIL unknown refresh token: $BAD"; fail=1; }
fi

echo
(( fail == 0 )) || { echo "Some checks FAILED."; exit 1; }
echo "The client would now POST this to the resource AS as grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<ID-JAG>."
