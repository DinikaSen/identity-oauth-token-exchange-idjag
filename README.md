# ID-JAG token exchange grant for WSO2 Identity Server 7.x

Issues **Identity Assertion JWT Authorization Grants** (ID-JAG,
[draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/),
written against draft **-04**) from WSO2 IS, so a client can trade an IS-issued ID token for a grant
it presents to a **different** authorization server that trusts IS.

This covers the **identity provider** side only: IS mints ID-JAGs. IS does not consume ID-JAGs issued
by anyone else.

The ID-JAG `sub` claim carries the **user's email address**, not IS's default subject UUID.

## The flow

```
┌────────┐                     ┌─────────────┐                    ┌──────────────────────┐
│ Client │                     │   WSO2 IS   │                    │ Resource app's AS    │
│        │                     │    (IdP)    │                    │ (e.g. Atlassian)     │
└───┬────┘                     └──────┬──────┘                    └──────────┬───────────┘
    │  1. OIDC login                  │                                      │
    ├────────────────────────────────►│                                      │
    │◄────────── id_token ────────────┤                                      │
    │                                 │                                      │
    │  2. POST /oauth2/token          │                                      │
    │     grant_type=token-exchange   │                                      │
    │     requested_token_type=id-jag │                                      │
    │     subject_token=<id_token>    │                                      │
    │     audience=<their AS>         │                                      │
    ├────────────────────────────────►│                                      │
    │                                 │ validate assertion, resolve user,    │
    │                                 │ read email claim, sign ID-JAG        │
    │◄── 3. oauth-id-jag+jwt ─────────┤                                      │
    │                                 │                                      │
    │  4. POST /oauth2/token  grant_type=jwt-bearer  assertion=<ID-JAG>      │
    ├───────────────────────────────────────────────────────────────────────►│
    │◄──────────────────────── access_token ─────────────────────────────────┤
```

Step 4 happens entirely at the third party. IS's only job is steps 2–3.

## Request and response

```http
POST /oauth2/token HTTP/1.1
Host: localhost:9443
Authorization: Basic <client_id:client_secret>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&requested_token_type=urn:ietf:params:oauth:token-type:id-jag
&subject_token=<the IS id_token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&audience=https://acme.chat.example
&resource=https://api.acme.chat.example
&scope=chat.read chat.history
```

| Parameter | Draft | Meaning here |
|---|---|---|
| `requested_token_type` | REQUIRED | Must be the id-jag URN, otherwise the request is ordinary token exchange |
| `subject_token` | REQUIRED | The IS-issued ID token, or a refresh token IS issued to this client |
| `subject_token_type` | REQUIRED | `urn:ietf:params:oauth:token-type:id_token` or `urn:ietf:params:oauth:token-type:refresh_token`. See [Subject token types](#subject-token-types) |
| `audience` | REQUIRED | Identifier of the resource application's authorization server. Becomes `aud`. Optional only when `oauth.idjag.audience` is configured |
| `resource` | OPTIONAL | RFC 8707 resource indicator of the resource server. Becomes the `resource` claim |
| `scope` | OPTIONAL | Scopes requested at the resource server |
| `authorization_details` | OPTIONAL | Not implemented; ignored |

```json
{
  "access_token": "eyJ0eXAiOiJvYXV0aC1pZC1qYWcrand0...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "token_type": "N_A",
  "scope": "chat.read chat.history",
  "expires_in": 300
}
```

The issued JWT:

```json
// header
{ "typ": "oauth-id-jag+jwt", "alg": "RS256", "kid": "..." }
// payload
{
  "jti":       "3f1c...",
  "iss":       "https://localhost:9443/oauth2/token",  // IS issuer, or oauth.idjag.issuer
  "sub":       "alice@example.com",                    // the user's email, not the subject UUID
  "aud":       "https://acme.chat.example",            // from `audience`, or oauth.idjag.audience
  "client_id": "abc123",                               // requesting client, or oauth.idjag.client_id
  "iat":       1789551720,
  "exp":       1789552020,
  "scope":     "chat.read chat.history",               // only when scopes survived validation
  "resource":  "https://api.acme.chat.example"         // from `resource`, or oauth.idjag.resource; else omitted
}
```

`jti`, `iss`, `sub`, `aud`, `client_id`, `iat` and `exp` are always present, as the draft requires.
`scope` and `resource` are optional in the draft and are omitted when there is nothing to put in them.
Extra claims can be added with `oauth.idjag.additional_claims`.

## Subject token types

Draft -04 allows exactly three subject token types: an OpenID Connect ID token, a SAML 2.0 assertion,
or a refresh token. This extension implements the ID token and the refresh token. SAML 2.0 is rejected
with `invalid_request`.

### Refresh token as the subject token

```http
subject_token=<refresh token IS issued to this client>
&subject_token_type=urn:ietf:params:oauth:token-type:refresh_token
```

The draft's rule is that the IdP validates it "the same way it would for a standard refresh_token
grant": issued by IS, bound to the authenticated client, unexpired, not revoked, and the requested
scopes within the token's authorization. The handler hands the token to the same
`RefreshTokenGrantProcessor` the stock refresh grant uses, so persisted, hybrid and JWT refresh tokens
are all handled the way IS handles them elsewhere. On top of that it requires:

| Check | Failure |
|---|---|
| Token is known and belongs to the requesting client | `invalid_grant` |
| Token state is active (or its access token merely expired), not revoked or inactive | `invalid_grant` |
| Token is the latest in its rotation chain | `invalid_grant` |
| Token's own validity has not run out | `invalid_grant` |
| Token is not bound to a certificate, cookie, DPoP key or similar | `invalid_grant` |
| Every requested scope is one the token was issued with | `invalid_scope` |

With no `scope` in the request, the token's own scopes are seeded (minus `openid`). The user comes from
the token record and the `sub` claim is resolved from the user store as usual. **The refresh token is
not rotated or consumed**; the client keeps using it.

Bound refresh tokens are refused because a token exchange request cannot prove the binding, and an
ID-JAG minted from one would silently shed that protection.

Switch it off with `allow_refresh_token_subject_token = false` to require a live ID token for every
ID-JAG.

An **access token is not an identity assertion** and is not permitted by the draft. Earlier versions of
this extension accepted `urn:ietf:params:oauth:token-type:access_token` (and the generic `jwt` type)
whenever the value was a JWT. That is now **off by default**. For clients still built that way it can be
re-enabled temporarily:

```toml
[oauth.idjag]
allow_access_token_subject_token = true
```

Every exchange that relies on the switch is logged at WARN with the client id, so you can tell when it
is safe to turn off again. Leaving it on means any client holding a bearer access token for a user can
mint an identity assertion for that user, which is a wider capability than holding an ID token issued
to that client.

## What it validates

| Check | Failure |
|---|---|
| `audience` present (or configured) | `invalid_request` |
| Client-supplied `audience` is an absolute URI without fragment | `invalid_target` |
| Client-supplied `audience` on the configured allowlist (if set) | `invalid_target` |
| Client-supplied `resource`, when present, is an absolute URI without fragment | `invalid_target` |
| `subject_token_type` is `id_token` or `refresh_token` (or `access_token`/`jwt` with the legacy switch on) | `invalid_request` |
| For a refresh token: the checks in [Refresh token as the subject token](#refresh-token-as-the-subject-token) | `invalid_grant` / `invalid_scope` |
| For an ID token: `subject_token` is a signed JWT with `iss`, `sub`, `aud`, `exp` | `invalid_request` |
| Signature valid for the IdP resolved from `iss` | `invalid_request` |
| `exp`/`nbf`/`iat` within skew and `iat` freshness window | `invalid_request` |
| `aud` of the subject token contains the requesting `client_id` (or the federated IdP alias) | `invalid_target` |
| A local user resolves from `sub` | `invalid_grant` |
| The user has a value for the subject claim | `server_error` |

The subject token `aud` check is the draft's processing rule: "the IdP MUST validate that the audience
of the assertion matches the client_id of the client authentication of the request."

The last check fails closed on purpose: an ID-JAG whose `sub` quietly fell back to IS's UUID would be
accepted by the resource application and mapped to the wrong account, or to none.

## Design notes

- **It replaces the stock token exchange handler by subclassing it.** A request is only treated as
  ID-JAG when `requested_token_type` is the id-jag URN; everything else — ordinary token exchange,
  impersonation — is delegated to `TokenExchangeGrantHandler` untouched. This keeps the spec-mandated
  `grant_type` (`urn:ietf:params:oauth:grant-type:token-exchange`) rather than inventing a private one.
- **Per-request state lives on the message context**, never on the handler. WSO2 instantiates one grant
  handler and shares it across concurrent requests.
- **The ID-JAG is not persisted.** It is not an access token: no row in `IDN_OAUTH2_ACCESS_TOKEN`, no
  refresh token, `token_type: N_A`. It is signed directly with the tenant key, so a resource AS that
  already trusts IS's OIDC metadata validates it with the JWKS it has.
- **Scopes are validated by the framework, exactly as for an access token.** `validateGrant` seeds the
  requested scopes onto the message context; `AccessTokenIssuer` then runs its normal scope pipeline,
  which keeps only the scopes the user's roles and the application's authorised API resources permit.
  The ID-JAG `scope` claim and the response's `scope` field carry what survived. A scope the resource
  application expects therefore has to be registered on IS, typically as an API resource authorised for
  the application. `openid` is stripped from the claim because it is an OIDC request marker for IS, not
  an authority at the resource application.
- **`audience` and `resource` are different things.** `aud` names the authorization server that will
  redeem the grant; `resource` names the protected resource the resulting access token is for. One
  authorization server fronts many resources, which is why the draft keeps both.

## Build

```bash
mvn clean package
```

Compiles against the OSGi bundles in the target IS distribution, so it needs no access to the WSO2
Maven repositories (which return 403 without credentials) and cannot drift from the API the server
runs. The `is.home` default in `pom.xml` points at the pack this was developed against; see
[Deploy](#deploy) for targeting a different one.

## Deploy

### Into an IS pack

```bash
./scripts/install.sh /path/to/wso2is-x.y.z
```

Stop the target server first, then start it again afterwards. The script:

1. reads the pack's own bundle versions out of `repository/components/plugins` and builds against
   them, so it adapts to a different IS version or update level on its own;
2. drops the bundle into `repository/components/dropins`;
3. inserts the `<IDJAG>` block into `identity.xml.j2`;
4. appends the `[oauth.grant_type.token_exchange]` and `[oauth.idjag]` blocks to `deployment.toml`.

It is safe to re-run — each step detects work already done and skips it, and an existing `<IDJAG>`
block is replaced with the current one so new keys reach an older install. It saves the two original
config files to `backups/<pack-name>/` in this project. It bails out with a clear message if the path is
not an IS pack, or if the pack has no token exchange bundle to extend.

If the pack already has an `[oauth.grant_type.token_exchange]` block, the script leaves it alone and
prints the two keys to set by hand, rather than writing a duplicate block.

**Backups live in the project, not in the pack.** Two directories inside a pack destroy files left in
them: `repository/resources/conf/templates` is scanned by the config parser, which warns about
anything stray, and `$IS_HOME/backup` belongs to the config mapper, which clears it on server start.

To revert, with the server stopped:

```bash
rm $IS_HOME/repository/components/dropins/org.wso2.custom.identity.oauth2.grant.tokenexchange.idjag-*.jar
cp backups/<pack-name>/deployment.toml.orig $IS_HOME/repository/conf/deployment.toml
cp backups/<pack-name>/identity.xml.j2.orig \
   $IS_HOME/repository/resources/conf/templates/repository/conf/identity/identity.xml.j2
```

### By hand

If you would rather not run the script, or it refuses the pack:

1. Build, pointing at the target pack so the compile classpath matches it:

   ```bash
   mvn clean package -Dis.home=/path/to/wso2is-x.y.z
   ```

   If that pack's bundle versions differ from the defaults in `pom.xml`, override the ones that
   differ, e.g. `-Didentity.oauth.version=7.4.99.40`. The filenames in
   `repository/components/plugins` are `<bundle-symbolic-name>_<version>.jar`, so the version to pass
   is right there in the filename. A mismatch shows up as Maven failing to find a `systemPath` jar,
   which names the file it wanted.

2. Copy the bundle into `dropins`:

   ```bash
   cp target/org.wso2.custom.identity.oauth2.grant.tokenexchange.idjag-1.0-SNAPSHOT.jar \
      $IS_HOME/repository/components/dropins/
   ```

3. Add the `<IDJAG>` block to
   `$IS_HOME/repository/resources/conf/templates/repository/conf/identity/identity.xml.j2`,
   immediately after `</SupportedGrantTypes>` — copy it from `docs/identity-xml-idjag-block.xml`.

4. Append to `$IS_HOME/repository/conf/deployment.toml`:

   ```toml
   [oauth.grant_type.token_exchange]
   enable = true
   grant_handler = "org.wso2.custom.identity.oauth2.grant.idjag.IdJagGrantHandler"
   grant_validator = "org.wso2.carbon.identity.oauth2.grant.token.exchange.TokenExchangeGrantValidator"
   allow_refresh_tokens = false

   [oauth.idjag]
   subject_claim_uri = "http://wso2.org/claims/emailaddress"
   validity_period = 300
   iat_validity_period = 60
   require_subject_claim = true
   # allowed_audiences = "https://acme.chat.example,https://api.figma.example"
   ```

5. Restart the server, then confirm with
   `grep -iE "ERROR|idjag" $IS_HOME/repository/logs/wso2carbon.log`.

### Will it work on a different IS version?

The extension only needs the packaged token exchange grant (`org.wso2.carbon.identity.oauth2.grant.token.exchange`)
plus the OAuth and framework bundles every pack has. The OSGi imports are declared with wide ranges
(`[6.0.0, 8.0.0)` for OAuth, `[1.4.0, 2.0.0)` for token exchange), so it should tolerate update-level
bumps within IS 7.x. Across a major version the API it builds on could move — rebuild against that
pack and let the compiler tell you.

### Configuration reference

All keys live under `[oauth.idjag]` in `deployment.toml`. Every one is optional.

| Key | Default | Meaning |
|---|---|---|
| `issuer` | this server's OIDC token issuer | Value of the ID-JAG `iss` claim |
| `audience` | *(from the request)* | Value of the ID-JAG `aud` claim when the client omits `audience` |
| `force_audience` | `false` | Let the configured `audience` override a client-supplied one, not just default it |
| `client_id` | the requesting client's id | Value of the ID-JAG `client_id` claim: the client as the resource AS knows it |
| `use_app_client_id` | `false` | Always emit the requesting IS application's own client id as the `client_id` claim, ignoring `client_id` |
| `resource` | *(from the request, else omitted)* | Value of the ID-JAG `resource` claim; overrides a client-supplied `resource` |
| `additional_claims` | *(none)* | Comma separated `claimName=localClaimUri` pairs to add to the ID-JAG. `true`/`false` values become JSON booleans; a claim the user has no value for is omitted |
| `subject_claim_uri` | `http://wso2.org/claims/emailaddress` | Local claim that becomes the ID-JAG `sub` |
| `validity_period` | `300` | ID-JAG lifetime, seconds |
| `iat_validity_period` | `60` | Max age of the subject token's `iat`, minutes |
| `allowed_audiences` | *(unset — any)* | Comma separated allowlist of resource AS identifiers a client may ask for |
| `require_subject_claim` | `true` | Fail rather than fall back to the subject identifier |
| `allow_access_token_subject_token` | `false` | **Temporary.** Accept access tokens as subject tokens for clients not yet migrated to ID tokens |
| `allow_refresh_token_subject_token` | `true` | Accept refresh tokens IS issued to the client as subject tokens |

#### Issuer

`iss` defaults to this server's own OpenID Connect token issuer — `https://localhost:9443/oauth2/token`
on a stock pack — which is what a resource application validating the grant against this server's
published metadata expects. Override it when the third party knows this identity provider by a
different identifier, such as a public URL fronting a private deployment:

```toml
[oauth.idjag]
issuer = "https://idp.example.com"
```

Nothing else changes: the grant is still signed with the same tenant key and the same `kid`. If you
point `iss` somewhere the third party cannot fetch a JWKS from, it has to be told where the keys are
out of band.

#### Audience

`aud` is the identifier of the resource application's authorization server. By default the client
names it per request with `audience`, which the draft requires. Two ways to configure it instead:

```toml
[oauth.idjag]
# Supplies `aud` when the client omits `audience`; a client that sends `audience` still wins.
audience = "https://acme.chat.example"
```

```toml
[oauth.idjag]
# Pins `aud` for every ID-JAG, overriding whatever the client asks for.
audience = "https://acme.chat.example"
force_audience = true
```

With `audience` configured, the request parameter stops being mandatory, so a request can be as short
as `grant_type` + `requested_token_type` + `subject_token` + `subject_token_type`.

`force_audience` is off by default because silently retargeting a grant the client asked to have
minted for somewhere else is a surprising thing for a server to do. When it is on and a client asks
for a *different* target, the override is logged at WARN — in steady state that should not happen.

A configured `audience` is not checked against `allowed_audiences`, nor required to be a URI; an
administrator who set it has already made that call, and some authorization servers identify
themselves with an opaque id. The allowlist and the URI check exist to constrain what *clients* may
ask for.

#### Resource and client_id

Some resource applications need more than `aud`. Atlassian, for example, redeems the grant at one
authorization server but issues the access token for a specific site, and it knows the client by the
id registered on its side:

```toml
[oauth.idjag]
audience = "https://auth.atlassian.com/<app-id>"
force_audience = true
client_id = "<client id registered at Atlassian>"
resource = "https://api.atlassian.com/ex/jira/<cloud-id>"
additional_claims = "email=http://wso2.org/claims/emailaddress,emailVerified=http://wso2.org/claims/identity/emailVerified"
```

A configured `resource` wins over a client-supplied one. When neither is present the claim is omitted.

The draft defines `client_id` as "the client identifier of the OAuth 2.0 client at the Resource
Authorization Server", which "MAY be different than the client identifier of the OAuth 2.0 client
requesting an ID-JAG from the IdP" (section 3.1), and the resource AS "MUST validate that the
client_id claim in the ID-JAG matches the authenticated client making the request" (section 4.4.1).
The claim is resolved in this order:

1. with `use_app_client_id = true`, the requesting application's own IS client id;
2. otherwise the configured `client_id`;
3. otherwise the requesting application's own IS client id.

One static `client_id` fits a deployment where a single IS application talks to a single resource AS
registration. When several IS applications each have their own registration at the resource AS,
create each IS application with the client id it was given there and set `use_app_client_id = true`.

## Application setup

In the IS Console, for the application that will request ID-JAGs:

- **Protocol → Allowed grant types**: enable `Token Exchange` (and whatever it uses to log the user in).
- **Client authentication**: confidential client; ID-JAG requests must be authenticated.
- **Scopes**: any scope the ID-JAG should carry must be a scope IS knows about and the application is
  authorised for, or the framework drops it.
- Make sure the user has a value for `http://wso2.org/claims/emailaddress`.

## Testing

```bash
./scripts/test-idjag.sh <client_id> <client_secret> <username> <password> [audience] [scope] [resource]
IS_BASE=https://host:8443 ./scripts/test-idjag.sh ...     # against a non-local server
```

It fetches an ID token, exchanges it for an ID-JAG, pretty-prints both JWTs, checks the required
claims, and confirms that an access token and a SAML type are rejected as subject tokens.

```bash
./scripts/test-idjag-claims.sh <client_id> <client_secret> <username> <password> [IS_HOME]
```

Reads the effective `[oauth.idjag]` configuration from the running server's generated identity.xml,
then checks `aud`, `iss`, `resource` and the access-token switch behave as configured. It has to run on
the machine that hosts the pack, since it reads a file from it.

Verified against WSO2 IS 7.4.0-SNAPSHOT on 2026-10-07, with and without the access-token switch:

- all seven required claims present; `sub` is the email; `typ` is `oauth-id-jag+jwt`;
- configured `audience`, `issuer`, `resource`, `client_id` and `additional_claims` land in the JWT;
- client-supplied `audience`/`resource` are overruled when configured and `force_audience` is on;
- a relative `resource` is rejected with `invalid_target`;
- `access_token` and `jwt` subject token types are rejected with `invalid_request` when the switch is
  off, accepted with a WARN when it is on; `saml2` is always rejected;
- scopes not registered on IS are dropped from the claim and the response; `openid` never produces an
  `id_token` in the exchange response;
- a refresh token as subject token yields an ID-JAG for the same user, a scope outside its grant is
  rejected with `invalid_scope`, an unknown or revoked token with `invalid_grant`, and the refresh token
  remains usable afterwards.

Note on plain token exchange: a request without `requested_token_type` is delegated to the stock
handler, which for a *self-issued* subject token still requires the token's `aud` to match a
registered IdP alias — so it answers `invalid_target` unless that is configured. That is pre-existing
stock behaviour, not something this extension changes; the error text is emitted by the stock bundle,
which is itself the evidence that delegation works.

## Not implemented

- SAML 2.0 assertions as subject tokens (permitted by the draft).
- Account-lock check on the refresh token path. The stock refresh grant only performs it when
  `validate_authenticated_user_for_refresh_grant` is enabled, which is off by default; this handler
  does not perform it at all.
- `authorization_details` (RFC 9396) request parameter and claim.
- `tenant` and `aud_sub` optional claims.
- Proof-of-possession binding (`cnf`).
- Advertising `identity_chaining_requested_token_types_supported` in the IdP's authorization server
  metadata (draft section 7.1).

## Source map

| File | Role |
|---|---|
| `IdJagGrantHandler.java` | Grant lifecycle: detect ID-JAG requests, validate `audience`/`resource`/subject token, delegate the rest to the stock handler |
| `IdJagTokenBuilder.java` | Builds and signs the `oauth-id-jag+jwt`, shapes the RFC 8693 response |
| `IdJagSubjectResolver.java` | Resolves `sub` and additional claims — user attributes, then user store, then the subject token |
| `IdJagConfig.java` | Reads `OAuth.IDJAG.*` from identity.xml |
| `IdJagConstants.java` | URNs, parameter names, claim names, config paths |
