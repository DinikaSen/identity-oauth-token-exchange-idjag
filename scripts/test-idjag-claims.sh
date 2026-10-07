#!/usr/bin/env bash
#
# Exercises the configurable ID-JAG "iss", "aud" and "resource" claims, and the subject token type switch.
#
#   ./test-idjag-claims.sh <client_id> <client_secret> <username> <password> [IS_HOME]
#
# Reads the effective ID-JAG configuration out of the running server's generated identity.xml, states
# what each request should produce, then makes the requests and checks. Run it once with
# `audience`/`issuer` set, and again after turning `force_audience` on.
#
# IS_HOME must be a path on the machine this script runs on. For a remote server, copy the script
# there and run it with IS_BASE pointing at the local listener, e.g.
#   IS_BASE=https://localhost:9443 ./test-idjag-claims.sh ... /home/ubuntu/wso2is-7.4.0-SNAPSHOT
set -euo pipefail

CLIENT_ID=${1:?client_id required}
CLIENT_SECRET=${2:?client_secret required}
USERNAME=${3:?username required}
PASSWORD=${4:?password required}
IS_HOME=${5:-${IS_HOME:-/Users/dinika/WSO2/PoC/Hilton/PoC2/wso2is-7.4.0-SNAPSHOT}}

IS_BASE=${IS_BASE:-https://localhost:9443}
TOKEN_EP="$IS_BASE/oauth2/token"
IDENTITY_XML=$IS_HOME/repository/conf/identity/identity.xml

OTHER_AUDIENCE=${OTHER_AUDIENCE:-https://other.example}
TEST_RESOURCE=${TEST_RESOURCE:-https://api.other.example/v1}

claim() {                                  # claim <jwt> <part:1|2> <claim-name>
  local seg
  seg=$(cut -d. -f"$2" <<<"$1" | tr '_-' '/+')
  while (( ${#seg} % 4 )); do seg+="="; done
  printf '%s' "$seg" | base64 -d 2>/dev/null \
    | python3 -c "import json,sys; v=json.load(sys.stdin).get('$3',''); print(v if not isinstance(v,list) else ' '.join(v))"
}

cfg() {                                    # cfg <element-name> -> configured value or empty
  [[ -f "$IDENTITY_XML" ]] || return 0
  sed -n '/<IDJAG>/,/<\/IDJAG>/p' "$IDENTITY_XML" \
    | sed -n "s@.*<$1>\(.*\)</$1>.*@\1@p" | head -1
}

CFG_ISSUER=$(cfg Issuer)
CFG_AUDIENCE=$(cfg Audience)
CFG_FORCE=$(cfg ForceAudience);           [[ -n "$CFG_FORCE" ]] || CFG_FORCE=false
CFG_RESOURCE=$(cfg Resource)
CFG_LEGACY=$(cfg AllowAccessTokenSubjectToken); [[ -n "$CFG_LEGACY" ]] || CFG_LEGACY=false

echo "==> Effective ID-JAG configuration (from $IDENTITY_XML)"
[[ -f "$IDENTITY_XML" ]] || echo "    WARNING: file not found; assuming everything is unset" >&2
printf '    %-30s %s\n' "Issuer"        "${CFG_ISSUER:-(unset - server OIDC issuer)}"
printf '    %-30s %s\n' "Audience"      "${CFG_AUDIENCE:-(unset - from the request)}"
printf '    %-30s %s\n' "ForceAudience" "$CFG_FORCE"
printf '    %-30s %s\n' "Resource"      "${CFG_RESOURCE:-(unset - from the request, or omitted)}"
printf '    %-30s %s\n' "AllowAccessTokenSubjectToken" "$CFG_LEGACY"
echo

echo "==> Obtaining an ID token (and an access token, for the subject token type check)"
LOGIN=$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_EP" \
  -d grant_type=password --data-urlencode "username=$USERNAME" \
  --data-urlencode "password=$PASSWORD" -d scope=openid)
ID_TOKEN=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("id_token",""))' <<<"$LOGIN")
ACCESS_TOKEN=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' <<<"$LOGIN")
[[ -n "$ID_TOKEN" ]] || { echo "    FAILED to obtain an id_token (is the Password grant enabled?)" >&2; exit 1; }
echo "    ok"
echo

pass=0; fail=0
check() {                                  # check <label> <expected> <actual>
  if [[ "$2" == "$3" ]]; then printf '    OK   %-28s %s\n' "$1" "$3"; pass=$((pass+1))
  else printf '    FAIL %-28s got %s, expected %s\n' "$1" "${3:-<empty>}" "$2"; fail=$((fail+1)); fi
}

# exchange [audience] [resource] [subject_token_type] [subject_token] -> prints the ID-JAG, or "" on error
exchange() {
  local args=(-d grant_type=urn:ietf:params:oauth:grant-type:token-exchange
              -d requested_token_type=urn:ietf:params:oauth:token-type:id-jag
              -d "subject_token_type=${3:-urn:ietf:params:oauth:token-type:id_token}"
              --data-urlencode "subject_token=${4:-$ID_TOKEN}")
  [[ -n "${1:-}" ]] && args+=(--data-urlencode "audience=$1")
  [[ -n "${2:-}" ]] && args+=(--data-urlencode "resource=$2")
  curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_EP" "${args[@]}" \
    | python3 -c 'import json,sys
d=json.load(sys.stdin)
if "access_token" in d: print(d["access_token"])
else: print("ERROR:%s:%s" % (d.get("error"), (d.get("error_description") or "")[:90]), file=sys.stderr)'
}

# --------------------------------------------------------------------------------------------------
echo "==> 1. Request WITHOUT 'audience'"
if [[ -n "$CFG_AUDIENCE" ]]; then
  echo "       expect: succeeds, aud = configured Audience"
  JAG=$(exchange "" || true)
  if [[ -n "$JAG" ]]; then
    check "aud" "$CFG_AUDIENCE" "$(claim "$JAG" 2 aud)"
  else
    printf '    FAIL %-28s request was rejected\n' "aud"; fail=$((fail+1))
  fi
else
  echo "       expect: rejected with invalid_request (audience is REQUIRED and none is configured)"
  if JAG=$(exchange "" 2>/dev/null) && [[ -n "$JAG" ]]; then
    printf '    FAIL %-28s succeeded but should have been rejected\n' "no-audience"; fail=$((fail+1))
  else
    printf '    OK   %-28s rejected as expected\n' "no-audience"; pass=$((pass+1))
  fi
fi
echo

# --------------------------------------------------------------------------------------------------
echo "==> 2. Request WITH audience=$OTHER_AUDIENCE"
if [[ "$CFG_FORCE" == "true" && -n "$CFG_AUDIENCE" ]]; then
  echo "       expect: aud = configured Audience (client overruled; a WARN is logged)"
  EXPECT_AUD=$CFG_AUDIENCE
else
  echo "       expect: aud = the requested audience (client wins)"
  EXPECT_AUD=$OTHER_AUDIENCE
fi
JAG=$(exchange "$OTHER_AUDIENCE" || true)
if [[ -n "$JAG" ]]; then
  check "aud" "$EXPECT_AUD" "$(claim "$JAG" 2 aud)"
  if [[ -n "$CFG_ISSUER" ]]; then
    check "iss (configured)" "$CFG_ISSUER" "$(claim "$JAG" 2 iss)"
  else
    printf '    --   %-28s %s (server default)\n' "iss" "$(claim "$JAG" 2 iss)"
  fi
  check "typ" "oauth-id-jag+jwt" "$(claim "$JAG" 1 typ)"
  if [[ -n "$CFG_RESOURCE" ]]; then
    check "resource (configured)" "$CFG_RESOURCE" "$(claim "$JAG" 2 resource)"
  else
    check "resource (omitted)" "" "$(claim "$JAG" 2 resource)"
  fi
  printf '    --   %-28s %s\n' "sub" "$(claim "$JAG" 2 sub)"
else
  printf '    FAIL %-28s request was rejected\n' "aud"; fail=$((fail+1))
fi
echo

# --------------------------------------------------------------------------------------------------
echo "==> 3. Request WITH audience=$OTHER_AUDIENCE AND resource=$TEST_RESOURCE"
if [[ -n "$CFG_RESOURCE" ]]; then
  echo "       expect: resource claim = configured Resource (client's resource overruled)"
  EXPECT_RES=$CFG_RESOURCE
else
  echo "       expect: resource claim = the requested resource"
  EXPECT_RES=$TEST_RESOURCE
fi
JAG=$(exchange "$OTHER_AUDIENCE" "$TEST_RESOURCE" || true)
if [[ -n "$JAG" ]]; then
  check "resource" "$EXPECT_RES" "$(claim "$JAG" 2 resource)"
  check "aud" "$EXPECT_AUD" "$(claim "$JAG" 2 aud)"
else
  printf '    FAIL %-28s request was rejected\n' "resource"; fail=$((fail+1))
fi
echo

# --------------------------------------------------------------------------------------------------
echo "==> 4. Request with a relative 'resource' (not an RFC 8707 resource indicator)"
echo "       expect: rejected with invalid_target"
if JAG=$(exchange "$OTHER_AUDIENCE" "not/a/uri" 2>/dev/null) && [[ -n "$JAG" ]]; then
  printf '    FAIL %-28s succeeded but should have been rejected\n' "relative-resource"; fail=$((fail+1))
else
  printf '    OK   %-28s rejected as expected\n' "relative-resource"; pass=$((pass+1))
fi
echo

# --------------------------------------------------------------------------------------------------
echo "==> 5. Access token as subject_token (subject_token_type=access_token)"
if [[ -z "$ACCESS_TOKEN" ]]; then
  echo "    --   skipped: no access token in the login response"
elif [[ "$CFG_LEGACY" == "true" ]]; then
  echo "       expect: ACCEPTED (legacy switch AllowAccessTokenSubjectToken is on; a WARN is logged)"
  JAG=$(exchange "$OTHER_AUDIENCE" "" urn:ietf:params:oauth:token-type:access_token "$ACCESS_TOKEN" || true)
  if [[ -n "$JAG" ]]; then
    printf '    OK   %-28s accepted (legacy mode)\n' "access-token-subject"; pass=$((pass+1))
  else
    printf '    FAIL %-28s rejected although legacy mode is on\n' "access-token-subject"; fail=$((fail+1))
  fi
else
  echo "       expect: rejected with invalid_request (not permitted by the draft; legacy switch is off)"
  if JAG=$(exchange "$OTHER_AUDIENCE" "" urn:ietf:params:oauth:token-type:access_token "$ACCESS_TOKEN" 2>/dev/null) \
     && [[ -n "$JAG" ]]; then
    printf '    FAIL %-28s accepted but should have been rejected\n' "access-token-subject"; fail=$((fail+1))
  else
    printf '    OK   %-28s rejected as expected\n' "access-token-subject"; pass=$((pass+1))
  fi
fi

echo
echo "==> $pass passed, $fail failed"
[[ $fail -eq 0 ]]
