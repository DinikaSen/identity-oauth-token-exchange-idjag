#!/usr/bin/env bash
#
# Installs the ID-JAG token exchange grant into a WSO2 Identity Server pack.
#
#   ./scripts/install.sh /path/to/wso2is-x.y.z
#
# Auto-detects the pack's own bundle versions, builds against them, deploys the bundle, and applies
# both configuration changes. Safe to re-run: every step detects work already done and skips it.
#
# The server must be STOPPED. Restart it yourself afterwards.
set -euo pipefail

IS_HOME=${1:-}
if [[ -z "$IS_HOME" ]]; then
  echo "usage: $0 /path/to/wso2is-x.y.z" >&2
  exit 64
fi
IS_HOME=$(cd "$IS_HOME" 2>/dev/null && pwd) || { echo "No such directory: ${1}" >&2; exit 66; }
PROJECT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

PLUGINS=$IS_HOME/repository/components/plugins
DROPINS=$IS_HOME/repository/components/dropins
TOML=$IS_HOME/repository/conf/deployment.toml
TEMPLATE=$IS_HOME/repository/resources/conf/templates/repository/conf/identity/identity.xml.j2

for path in "$PLUGINS" "$DROPINS" "$TOML" "$TEMPLATE"; do
  [[ -e "$path" ]] || { echo "Not a WSO2 IS pack (missing ${path#$IS_HOME/})" >&2; exit 66; }
done

if command -v lsof >/dev/null && lsof -nP -iTCP:9443 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "WARNING: something is listening on 9443. Stop the server before installing," >&2
  echo "         otherwise the bundle will not be picked up." >&2
fi

echo "==> Target pack: $IS_HOME"

# ---------------------------------------------------------------------------------------------------
# 1. Resolve the pack's bundle versions. Bundle filenames are <symbolic-name>_<version>.jar.
# ---------------------------------------------------------------------------------------------------
resolve() {                                   # resolve <maven-property> <bundle-symbolic-name>
  local prop=$1 name=$2 match count
  # shellcheck disable=SC2206
  local matches=( $PLUGINS/${name}_*.jar )
  count=${#matches[@]}
  if (( count == 0 )) || [[ ! -e ${matches[0]} ]]; then
    echo "MISSING: no bundle matching ${name}_*.jar in the pack's plugins directory." >&2
    echo "         This pack cannot host the extension as written." >&2
    exit 65
  fi
  if (( count > 1 )); then
    echo "    note: $count bundles match ${name}_*.jar; using the highest version" >&2
    IFS=$'\n' matches=( $(printf '%s\n' "${matches[@]}" | sort -V) ); unset IFS
  fi
  match=$(basename "${matches[$((count-1))]}")
  match=${match#"${name}_"}; match=${match%.jar}
  printf '%s\n' "$match"
  printf '    %-34s %s\n' "$prop" "$match" >&2
}

echo "==> Detected bundle versions"
V_OAUTH=$(resolve identity.oauth.version              org.wso2.carbon.identity.oauth)
V_OAUTH_COMMON=$(resolve identity.oauth.common.version       org.wso2.carbon.identity.oauth.common)
V_TE=$(resolve token.exchange.version            org.wso2.carbon.identity.oauth2.grant.token.exchange)
V_FW=$(resolve identity.framework.version         org.wso2.carbon.identity.application.common)
V_FW_AUTH=$(resolve identity.framework.auth.version    org.wso2.carbon.identity.application.authentication.framework)
V_FW_CORE=$(resolve identity.framework.core.version    org.wso2.carbon.identity.core)
V_FW_BASE=$(resolve identity.framework.base.version    org.wso2.carbon.identity.base)
V_USER_CORE=$(resolve carbon.user.core.version           org.wso2.carbon.user.core)
V_USER_API=$(resolve carbon.user.api.version            org.wso2.carbon.user.api)
V_UTILS=$(resolve carbon.utils.version               org.wso2.carbon.utils)
V_NIMBUS=$(resolve nimbusds.version                   nimbus-jose-jwt)
V_LANG=$(resolve commons.lang.version               commons-lang)

# commons-logging lives in lib/ and uses a hyphen, so it is resolved separately.
CL=$(ls "$IS_HOME"/lib/commons-logging-*.jar 2>/dev/null | sort -V | tail -1 || true)
[[ -n "$CL" ]] || { echo "MISSING: lib/commons-logging-*.jar" >&2; exit 65; }
printf '    %-34s %s\n' "commons-logging" "$(basename "$CL")"

# ---------------------------------------------------------------------------------------------------
# 2. Build against those versions.
# ---------------------------------------------------------------------------------------------------
echo "==> Building"
( cd "$PROJECT" && mvn -q clean package \
    -Dis.home="$IS_HOME" \
    -Didentity.oauth.version="$V_OAUTH" \
    -Didentity.oauth.common.version="$V_OAUTH_COMMON" \
    -Dtoken.exchange.version="$V_TE" \
    -Didentity.framework.version="$V_FW" \
    -Didentity.framework.auth.version="$V_FW_AUTH" \
    -Didentity.framework.core.version="$V_FW_CORE" \
    -Didentity.framework.base.version="$V_FW_BASE" \
    -Dcarbon.user.core.version="$V_USER_CORE" \
    -Dcarbon.user.api.version="$V_USER_API" \
    -Dcarbon.utils.version="$V_UTILS" \
    -Dnimbusds.version="$V_NIMBUS" \
    -Dcommons.lang.version="$V_LANG" )

JAR=$(ls "$PROJECT"/target/org.wso2.custom.identity.oauth2.grant.tokenexchange.idjag-*.jar | head -1)
echo "    built $(basename "$JAR")"

# ---------------------------------------------------------------------------------------------------
# 3. Deploy the bundle.
# ---------------------------------------------------------------------------------------------------
echo "==> Deploying the bundle to dropins"
rm -f "$DROPINS"/org.wso2.custom.identity.oauth2.grant.tokenexchange.idjag-*.jar
cp "$JAR" "$DROPINS/"
echo "    $(basename "$JAR")"

# ---------------------------------------------------------------------------------------------------
# 4. Patch identity.xml.j2 with the <IDJAG> config block.
#
#    Backups go in the PROJECT directory, not inside the pack. Two directories in a pack destroy
#    files left in them: the config parser scans repository/resources/conf/templates and warns about
#    anything stray, and $IS_HOME/backup is owned by the config mapper, which clears it on server
#    start. A backup kept in either place is lost the first time the server comes up.
# ---------------------------------------------------------------------------------------------------
BACKUP=$PROJECT/backups/$(basename "$IS_HOME")
BLOCK=$PROJECT/docs/identity-xml-idjag-block.xml
[[ -f "$BLOCK" ]] || { echo "Missing $BLOCK" >&2; exit 70; }

echo "==> Patching identity.xml.j2"
mkdir -p "$BACKUP"
[[ -e "$BACKUP/identity.xml.j2.orig" ]] || cp "$TEMPLATE" "$BACKUP/identity.xml.j2.orig"
TEMPLATE=$TEMPLATE BLOCK=$BLOCK BACKUP=$BACKUP python3 - <<'PYBLOCK'
import os, pathlib, sys

tpl = pathlib.Path(os.environ["TEMPLATE"])
block = pathlib.Path(os.environ["BLOCK"]).read_text()
s = tpl.read_text()
OPENER = "\n        <!--\n            Configuration for the custom ID-JAG"

if "<IDJAG>" in s:
    # Replace whatever block is present, so re-running upgrades an earlier install in place.
    if OPENER not in s:
        sys.exit("identity.xml.j2 has an <IDJAG> element that this installer did not write. "
                 "Reconcile it by hand against docs/identity-xml-idjag-block.xml.")
    start = s.index(OPENER)
    end = s.index("</IDJAG>\n", start) + len("</IDJAG>\n")
    if s[start:end] == block:
        print("    already up to date, skipping")
        sys.exit(0)
    tpl.write_text(s[:start] + block + s[end:])
    print("    replaced the existing <IDJAG> block with the current one")
    sys.exit(0)

anchor = "        </SupportedGrantTypes>\n"
if s.count(anchor) != 1:
    sys.exit("Expected exactly one </SupportedGrantTypes> in identity.xml.j2, found %d. "
             "Insert docs/identity-xml-idjag-block.xml after it by hand." % s.count(anchor))
tpl.write_text(s.replace(anchor, anchor + block))
print("    inserted after </SupportedGrantTypes> (original saved to %s)" % os.environ.get("BACKUP", ""))
PYBLOCK

# ---------------------------------------------------------------------------------------------------
# 5. Configure deployment.toml.
# ---------------------------------------------------------------------------------------------------
IDJAG_CLAIM_KEYS='# Value for the ID-JAG "iss" claim. Unset means this server'"'"'s own OIDC token issuer
# (e.g. https://localhost:9443/oauth2/token), which is what a resource application validating against
# this server'"'"'s published metadata expects. Set it when the third party knows this identity provider
# by some other issuer identifier.
# issuer = "https://idp.example.com"
#
# Value for the ID-JAG "aud" claim: the identifier of the resource application'"'"'s authorization server.
# Unset means it comes from the request'"'"'s `audience` parameter, which the specification requires. When
# set, it supplies the target for requests that omit `audience`.
# audience = "https://acme.chat.example"
#
# With force_audience = true the configured `audience` also REPLACES any `audience` the client sends,
# instead of only defaulting it. Leave it off unless the server should overrule its clients.
# force_audience = false
#
# Value for the ID-JAG "client_id" claim: an identifier the resource application'"'"'s authorization server
# recognises. Unset means the requesting client'"'"'s own id, which is right only when both ends know it by
# the same name.
# client_id = "<client id registered at the resource AS>"
#
# With use_app_client_id = true the ID-JAG "client_id" claim is always the requesting IS application'"'"'s
# own client id and `client_id` above is ignored. Use it when each IS application is created with the
# client id it was given at the resource AS, so one shared override would be wrong.
# use_app_client_id = false
#
# Extra user claims to carry in the ID-JAG, as comma separated claimName=localClaimUri pairs. A claim
# the user has no value for is omitted. Values "true"/"false" are emitted as JSON booleans.
# additional_claims = "emailVerified=http://wso2.org/claims/identity/emailVerified"
#
# Value for the ID-JAG "resource" claim: the protected resource the grant is spent at, as opposed to
# "aud", which names the authorization server that redeems it. Unset means the request'"'"'s optional
# `resource` parameter is used, or the claim is omitted when the client sent none.
# resource = "<resource identifier the resource AS expects>"
#
# TEMPORARY. The specification only allows an ID token, SAML 2.0 assertion or refresh token as the
# subject token. Earlier versions of this extension also accepted access tokens; set this to true only
# while clients built against that behaviour are migrated to presenting ID tokens. Each use is logged
# at WARN.
# allow_access_token_subject_token = false
#
# Whether a refresh token issued by this server may be the subject token (the specification allows it
# "when supported"). Default true. Set false to require a live ID token for every ID-JAG.
# allow_refresh_token_subject_token = true'

echo "==> Configuring deployment.toml"
mkdir -p "$BACKUP"
[[ -e "$BACKUP/deployment.toml.orig" ]] || cp "$TOML" "$BACKUP/deployment.toml.orig"

if grep -q "idjag.IdJagGrantHandler" "$TOML"; then
  # Already installed. Back-fill the ID-JAG claim keys if this pack predates them.
  if ! grep -q "^\[oauth.idjag\]" "$TOML"; then
    echo "    WARNING: the handler is configured but there is no [oauth.idjag] block." >&2
    echo "             Add one (see the README) to configure the ID-JAG claims." >&2
  else
    # The python below decides per key, so no shortcut guard here: it would go stale every time a new
    # key is added, which is exactly how client_id and additional_claims were missed.
    TOML=$TOML KEYS=$IDJAG_CLAIM_KEYS python3 - <<'PYTOML'
import os, pathlib
import re
p = pathlib.Path(os.environ["TOML"]); s = p.read_text()
anchor = "[oauth.idjag]\n"
i = s.index(anchor) + len(anchor)

# Split the canned text into per-key chunks so only genuinely missing keys are inserted.
chunks, current = [], []
for line in os.environ["KEYS"].splitlines():
    current.append(line)
    m = re.match(r"^#? *([a-z_]+) = ", line)
    if m:
        chunks.append((m.group(1), "\n".join(current)))
        current = []
missing = [(k, c) for k, c in chunks if not re.search(r"^#? *%s = " % k, s, re.M)]
if not missing:
    print("    already configured, skipping")
else:
    p.write_text(s[:i] + "\n".join(c for _, c in missing) + "\n" + s[i:])
    print("    added to the existing [oauth.idjag] block: " + ", ".join(k for k, _ in missing))
PYTOML
  fi
elif grep -q "^\[oauth.grant_type.token_exchange\]" "$TOML"; then
  echo "    WARNING: this pack already has an [oauth.grant_type.token_exchange] block." >&2
  echo "             Not touching it. Set these two keys in it by hand:" >&2
  echo "               grant_handler = \"org.wso2.custom.identity.oauth2.grant.idjag.IdJagGrantHandler\"" >&2
  echo "               grant_validator = \"org.wso2.carbon.identity.oauth2.grant.token.exchange.TokenExchangeGrantValidator\"" >&2
  echo "             Then add an [oauth.idjag] block (see the README)." >&2
else
  cat >> "$TOML" <<'EOFTOML'

# =====================================================================================================
# ID-JAG (Identity Assertion JWT Authorization Grant) token exchange extension.
#
# Replaces the stock token exchange grant handler with one that also serves
# requested_token_type=urn:ietf:params:oauth:token-type:id-jag. All other token exchange requests keep
# their existing behaviour.
# =====================================================================================================
[oauth.grant_type.token_exchange]
enable = true
grant_handler = "org.wso2.custom.identity.oauth2.grant.idjag.IdJagGrantHandler"
grant_validator = "org.wso2.carbon.identity.oauth2.grant.token.exchange.TokenExchangeGrantValidator"
allow_refresh_tokens = false

[oauth.idjag]
EOFTOML
  printf '%s\n' "$IDJAG_CLAIM_KEYS" >> "$TOML"
  cat >> "$TOML" <<'EOFTOML'
#
# Local claim whose value becomes the ID-JAG "sub" claim, instead of the default subject UUID.
subject_claim_uri = "http://wso2.org/claims/emailaddress"
# ID-JAG lifetime in seconds.
validity_period = 300
# Reject subject tokens whose "iat" is older than this many minutes.
iat_validity_period = 60
# Fail the request when the user has no value for subject_claim_uri, rather than silently falling back
# to the subject identifier.
require_subject_claim = true
# Comma separated allowlist of resource authorization server issuers an ID-JAG may target.
# Leave unset (or commented out) to allow any audience.
# allowed_audiences = "https://acme.chat.example,https://api.figma.example"
EOFTOML
  echo "    appended (original saved to $BACKUP)"
fi

cat <<EOF

==> Done. Next:
    1. Start the pack:   cd $IS_HOME && sh bin/wso2server.sh start
    2. Check it loaded:  grep -iE "ERROR|idjag" $IS_HOME/repository/logs/wso2carbon.log
    3. In the Console, enable the "Token Exchange" grant on the application, keep it a
       confidential client, and make sure the test user has an email address claim.
    4. Smoke test:       ./scripts/test-idjag.sh <client_id> <client_secret> <user> <pass>

    Before untrusted clients use this, set oauth.idjag.allowed_audiences in deployment.toml.

    To revert, with the server stopped:
      rm $DROPINS/org.wso2.custom.identity.oauth2.grant.tokenexchange.idjag-*.jar
      cp $BACKUP/deployment.toml.orig  $TOML
      cp $BACKUP/identity.xml.j2.orig  $TEMPLATE
EOF
