# idp-cyberos — SAML 2.0 + OpenID Connect Identity Provider (Go)

This repository contains a **minimal dual-protocol Identity Provider** for stacks that combine SAML SPs and OIDC clients:

- **SAML 2.0** — for sites that act as SAML Service Providers.
- **OpenID Connect** (OAuth 2.0 authorization code flow) — for sites that act as OIDC Relying Parties / OAuth clients (e.g. an app at `https://client.example.com`).

Both flows share the same **IdP session cookie** (`idp_session`) on the IdP origin. A user who signs in once (via Hanko on the IdP login page) can complete **SAML** and **OIDC** flows without re-entering credentials while that session is valid — useful for cross-site SSO across different protocols.

Hanko is **not** configured as a SAML SP here; this IdP bridges **Hanko (JWT + Hanko Elements UI)** to **SAML for SPs** and **OIDC tokens for OIDC clients**.

**License:** [MIT](LICENSE)

---

## Requirements

- Go **1.25+** (see `go.mod`)
- Optional: Docker / Docker Compose for containerized deployment
- A running **[Hanko](https://github.com/teamhanko/hanko)** public API (JWT + JWKS), reachable from this IdP and from the browser

---

## Endpoints (summary)

### SAML (IdP)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/metadata` | SAML IdP metadata (XML) |
| GET | `/sso` | SAML AuthnRequest (HTTP-Redirect); session or login page |
| GET | `/sso/complete` | After Hanko login: verify JWT, issue SAML Response to SP ACS |

### OpenID Connect

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/.well-known/openid-configuration` | OIDC Discovery (JSON) |
| GET | `/authorize` | Authorization endpoint (`response_type=code`); session or login page |
| POST | `/token` | Token endpoint (`grant_type=authorization_code`) |
| GET | `/userinfo` | UserInfo (Bearer access token) |
| GET | `/jwks` | JWKS for IdP-issued JWTs (RS256) |

### Login

- IdP serves a small HTML page with **Hanko Elements**; successful login redirects to `/sso/complete`, which verifies the Hanko JWT and then completes either a **pending SAML** or **pending OIDC** request (tracked via signed cookies).

---

## Configuration

### `config.yaml`

| Field | Description |
|--------|-------------|
| `entity_id` | SAML IdP Entity ID (public URL of the IdP) |
| `base_url` | Base URL used in metadata and OIDC `issuer` (must match public URL) |
| `listen_addr` | HTTP listen address (default `:5800`) |
| `hanko_api_url` | Hanko public API base URL (e.g. `https://api.cybeross.ru`) |
| `key_path` / `cert_path` | RSA private key and X.509 certificate (PEM) for SAML assertion signing and OIDC JWT signing |
| `session_key` | HMAC secret for signed cookies (override with env in production) |
| `service_providers` | SAML SPs: `entity_id`, `acs_url`, `name` |
| `oidc_clients` | OIDC/OAuth clients: `client_id`, `client_secret`, `redirect_uris`, `name` |

**OIDC client secrets:** You can put a placeholder in YAML (e.g. `${OIDC_CLIENT_SECRET_FASTYGO}`) and set the real value via environment variable `OIDC_CLIENT_SECRET_<CLIENTID>` (uppercase `client_id`), e.g. `OIDC_CLIENT_SECRET_FASTYGO` for client `fastygo`. The server applies overrides after loading YAML.

### Environment overrides

After loading `config.yaml`, these variables **override** the file if set:

| Variable | Overrides |
|----------|-----------|
| `IDP_SESSION_KEY` | `session_key` |
| `IDP_ENTITY_ID` | `entity_id` |
| `IDP_BASE_URL` | `base_url` |
| `IDP_LISTEN_ADDR` | `listen_addr` |
| `IDP_HANKO_API_URL` | `hanko_api_url` |
| `IDP_KEY_PATH` | `key_path` |
| `IDP_CERT_PATH` | `cert_path` |
| `OIDC_CLIENT_SECRET_<CLIENTID>` | `client_secret` for the matching `oidc_clients[]` entry (e.g. `OIDC_CLIENT_SECRET_FASTYGO`) |

Use these in Docker or systemd to avoid committing secrets.

---

## Build and run (local)

```bash
cd /path/to/@SSO
go build -o idp .
./idp -config config.yaml
```

Defaults: listen on `:5800`, read `config.yaml` from the current directory.

---

## Docker Compose (this repo only)

1. Copy environment template:

   ```bash
   cp .env.example .env
   ```

   Edit `.env`: set a strong `IDP_SESSION_KEY`, correct public URLs (`IDP_ENTITY_ID`, `IDP_BASE_URL`, `IDP_HANKO_API_URL`), and **OIDC client secret(s)** (e.g. `OIDC_CLIENT_SECRET_FASTYGO`) matching your registered OIDC apps.

2. Build and start:

   ```bash
   docker compose build
   docker compose up -d
   ```

3. IdP listens on **127.0.0.1:5800** (see `docker-compose.yml`). RSA keys persist in the named volume `idp_keys` at `/app/keys` inside the container.

4. **SAML SPs** need the **public certificate** `idp.crt` (e.g. copy into each SP’s `certs/idp.crt`).

5. **OIDC clients** do **not** need a static `idp.crt` file — they discover the IdP and validate `id_token` using **`GET /jwks`** (and Discovery).

---

## Production deployment

1. **TLS**: Terminate HTTPS at a reverse proxy (nginx, Caddy, Traefik) and route `https://idp.yourdomain` to this service.
2. **Secrets**: Set `IDP_SESSION_KEY` and OIDC client secrets via the orchestrator; do not commit `.env`.
3. **`base_url` / issuer**: Must exactly match the public HTTPS URL of this IdP (OIDC Discovery and JWT `iss` claim).
4. **Hanko**: Ensure `hanko_api_url` matches the URL browsers and this IdP use (CORS and cookies on the Hanko side must allow your IdP origin — and any extra app origins if you embed Hanko from other sites).
5. **Full stack**: This repo is **isolated**. Deploy Hanko from `@OIDC`, your SAML Service Provider site, and optional OIDC client apps, then point DNS and proxy rules at each service.

---

## Cross-protocol SSO (SAML + OIDC)

- The IdP sets a signed **`idp_session`** cookie on successful Hanko login (HTTPS, `Secure`, `SameSite=None` as implemented).
- **SAML**: `/sso` → login if no session → `/sso/complete` → SAML Response to ACS.
- **OIDC**: `/authorize` → if session exists, issue **authorization code** immediately; if not, same login page, then `/sso/complete` → redirect back to client with `code`.
- A user who authenticated for a **SAML** site can later open an **OIDC** client (e.g. `https://client.example.com`) and be issued a code **without logging in again**, as long as the IdP session cookie is still valid.

---

## Testing

```bash
go test ./...
```

---

## Related repositories

| Repository | Role |
|------------|------|
| `@OIDC` | Hanko Docker image + `hanko-config.yaml` (credential API) |
| (your SP repo) | Website as **SAML** Service Provider |
| (optional) | **OIDC** client app (e.g. `/auth/callback`) |

---

## Security notes

- Replace placeholder secrets before production.
- Prefer HTTPS everywhere; many cookies and WebAuthn require secure contexts.
- Keep OIDC `client_secret` values long and random; align them between IdP env and each client app’s env.
- Restrict IdP and Hanko admin interfaces to trusted networks or SSH tunnels if needed.
