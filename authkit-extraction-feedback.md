# AuthKit SDK Extraction — Post-Implementation Feedback

**Date:** 2026-04-16  
**Scope:** Verification of the "AuthKit SDK Extraction and AuthFly TypeScript Core" refactor.  
**Mode:** Local smoke test (build + run + HTTP probes), no deploy.

---

## TL;DR

The refactor **works end-to-end** on a local build. All new packages (`pkg/core`, `pkg/authkit`, `pkg/authkit-hanko`, `pkg/store/memory`, `internal/protocol/saml`) compile, tests pass, and the running server serves all endpoints correctly, with the login page injecting the provider SDK dynamically via `FlowConfig.SDKScript` as designed. The separation of concerns between the IdP core, the provider-agnostic UI (`pkg/authkit`), the Hanko adapter (`pkg/authkit-hanko`), and the shared contracts (`pkg/core`) is clean enough that `pkg/authkit` and `pkg/authkit-hanko` could be lifted out as independent Go modules without further surgery.

There are **no blockers**. There are a few **housekeeping items** and a **small architectural debt** left over from Phase 1 that should be addressed before splitting the repos.

---

## What was verified

### Toolchain

| Step | Result |
|---|---|
| `go build ./...` | OK |
| `go vet ./...` | OK (no warnings) |
| `go test ./...` | OK (`internal/auth`, `internal/oidc`, `internal/saml`, `pkg/authkit-hanko` all pass) |
| `templ generate` | OK (views regenerated in `pkg/authkit/views/`) |
| `go generate ./...` | OK (`ui8kit.js` regenerated → `pkg/authkit/static/js/ui8kit.js`) |
| `bun run build` (AuthFly TS) | OK (ESM + UMD + `.d.ts` in `dist/`) |
| `npm run build:css` | OK (`pkg/authkit/static/css/app.css` produced) |

### Runtime smoke test (local `go run ./cmd/server` on `:5800`)

| Endpoint | Expected | Got |
|---|---|---|
| `GET /jwks` | 200 | 200, 431 B |
| `GET /.well-known/openid-configuration` | 200 | 200, 596 B |
| `GET /metadata` | 200 (SAML XML) | 200, 1750 B |
| `GET /authorize?...` (login page) | 200, HTML | 200, 4100 B, correct `<title>Sign In — CyberOS SSO</title>` |
| `GET /logout?redirect=...` | 200 | 200 |
| `GET /sso` (no SAMLRequest) | 400 | 400 |
| `GET /sso?SAMLRequest=INVALID` | 400 | 400 |
| `GET /userinfo` (no token) | 401 | 401 |
| `GET /static/js/ui8kit.js` | 200 | 200, 27357 B |
| `GET /static/js/authkit-hanko.js` | 200 | 200, 46009 B |
| `GET /static/css/app.css` | 200 | 200, 37389 B |
| `GET /static/css/ui8kit/base.css` | 200 | 200 |

The merged static FS (`authkit.MergedFS(ui.StaticFS(), creds.StaticFS())`) correctly unifies assets from both `pkg/authkit` and `pkg/authkit-hanko` under a single `/static/` mount — this is exactly the intended split.

### Provider-agnostic layout is effective

Rendered login page ships the exact JSON the plan specified — **no `hankoApiUrl` leaks into the client**:

```json
{
  "apiUrl": "https://api.cybeross.ru",
  "features": {
    "allowOIDCRegistration": false,
    "allowPublicRegistration": false,
    "allowSAMLRegistration": true
  },
  "locale": "en",
  "logoutPath": "/logout",
  "successRedirect": "/sso/complete"
}
```

And the two scripts injected are:

- `/static/js/ui8kit.js` — UI primitives (from `pkg/authkit`)
- `/static/js/authkit-hanko.js` — provider bundle (from `pkg/authkit-hanko`, injected via `FlowConfig.SDKScript`)

No references to `auth-flow.js` or `hanko-frontend-sdk.js` remain in any rendered HTML. The logout page also uses only abstract `apiUrl` + `logoutPath`.

---

## Housekeeping — empty directories left on disk

Git no longer tracks these paths (content is deleted in the working tree), but the **empty folder shells still exist** on the filesystem and pollute the project tree:

```
internal/web/         (static/, views/ — all empty)
internal/i18n/        (en/, ru/ — all empty)
pkg/provider/         (hanko/, memory/ — all empty)
```

They do not affect build or runtime (Go ignores directories without `.go` files, embed patterns point elsewhere), but they are **misleading when browsing the repo**. Safe to remove:

```bash
rm -r internal/web internal/i18n pkg/provider
```

Git will not notice because it already tracks the deletions. I did not delete them in this audit run to keep the filesystem identical to what you would see.

---

## Architectural debt carried over from Phase 1

The following predate this refactor but are visible now that the new layout is clean:

### 1. `internal/protocol/{saml,oidc}` are still just aliases

`internal/protocol/saml/saml.go` and `internal/protocol/oidc/oidc.go` are **re-export shims** over the original `internal/saml` and `internal/oidc` packages:

```go
// internal/protocol/saml/saml.go
package saml
import oldsaml "idp-cyberos/internal/saml"
type AuthnRequest   = oldsaml.AuthnRequest
type ParsedRequest  = oldsaml.ParsedRequest
var (
    ParseAuthnRequest = oldsaml.ParseAuthnRequest
    BuildSAMLResponse = oldsaml.BuildSAMLResponse
    HandleMetadata    = oldsaml.HandleMetadata
)
```

This works, but **tests still live in `internal/saml` and `internal/oidc`** while callers import from `internal/protocol/...`. Two observations:

- Ambiguity for new contributors (which package is canonical?).
- Blocks a future clean split because a module extraction would need to follow both paths.

Remediation (small, low-risk): in a follow-up, move the real implementation into `internal/protocol/{saml,oidc}/` and delete the shims + the old packages. `internal/protocol/saml/postform.go` is already doing the right thing.

### 2. `config.yaml` vs `.env.example` — two sources of truth

`config.yaml` still contains:

```yaml
session_key: "CHANGE-ME-TO-A-RANDOM-32-BYTE-KEY"
```

and `.env.example` tells the operator to override it via `IDP_SESSION_KEY`. That is fine for deployment, but for a clean **"AuthKit as a distributable"** story the YAML file should not contain dummy secrets at all. The comment on line 7 already says "prefer .env" — consider just removing the `session_key` line entirely from `config.yaml` and letting `ApplyEnvOverrides` be the only path.

### 3. Docker image relies on committed JS artifacts

`Dockerfile` stage 1 builds CSS but **does not** build `ui8kit.js` or `authkit-hanko.js` — they are expected to be checked in:

- `.gitignore` intentionally ignores `pkg/authkit/static/js/ui8kit.js` → the Docker build will **fail** if the image is built from a fresh clone that has not run `go generate ./...` first.
- `pkg/authkit-hanko/static/js/authkit-hanko.js` is **not** ignored, but needs a hand-crafted `bun run build && cp` step in the `@AuthFly-authkit-ts` sibling repo.

This is a real sharp edge. Two possible fixes:

**Option A — make the Docker build self-sufficient** (recommended if `@AuthFly-authkit-ts` stays a sibling repo):

```dockerfile
# Stage 0: AuthFly TS core → authkit-hanko.js
FROM oven/bun:1-alpine AS authfly-ts
WORKDIR /build
COPY ../@AuthFly-authkit-ts/ .
RUN bun install && bun run build

# Stage 1 additions (after `COPY pkg/... .`):
RUN go generate ./...
COPY --from=authfly-ts /build/dist/authfly-authkit.umd.js \
     pkg/authkit-hanko/static/js/authkit-hanko.js
```

**Option B — commit the generated files** and drop them from `.gitignore`. Simpler but pollutes diffs.

Right now the intermediate state ("committed `authkit-hanko.js`, ignored `ui8kit.js`") is inconsistent — pick one policy.

### 4. `package.json` has `build:ui8kit-js` but Docker doesn't call it

`npm run build` does the right thing locally, but **Docker stage 1 only runs `build:css`**. Stage 2 runs `go generate ./...` which *does* regenerate `ui8kit.js` (via `cmd/gen-ui8kit`), so this accidentally works — but only because Go is a second execution environment that also happens to produce JS. A reader of the Dockerfile has no way to understand where `ui8kit.js` comes from. Either:

- add a comment in the Dockerfile explaining that `go generate` produces `ui8kit.js`, or
- move the gen step into the frontend stage (`go install` a tool there), or
- drop `build:ui8kit-js` from `package.json` to avoid a second supposed build path.

---

## Suggested follow-up priorities

In order of payoff-per-effort:

1. **Delete empty leftover directories** (`internal/web`, `internal/i18n`, `pkg/provider`) — literally one `rm -r`, improves navigability.
2. **Document the Docker build contract** — either make it self-sufficient (stage 0 pulls `@AuthFly-authkit-ts`) or add an explicit `make build-frontend` target before `docker build`. Currently the build-from-clean-clone story is fragile.
3. **Collapse `internal/protocol/{saml,oidc}` shims** — merge the old `internal/{saml,oidc}` code into `internal/protocol/...` and remove the aliases. Prepares for Phase 2 (multi-repo split of SPI).
4. **Remove the placeholder `session_key` from `config.yaml`** — `.env` is the single source of truth.
5. **Add a `README.md` in each new package** (`pkg/core`, `pkg/authkit`, `pkg/authkit-hanko`, `pkg/store/memory`) with a short "what is this / how to depend on it" paragraph. Essential before lifting them to standalone repos (`github.com/authfly/core`, `github.com/authfly/authkit`, `github.com/authfly/authkit-hanko`).
6. **Wire the `@AuthFly-authkit-ts` build into CI** so `authkit-hanko.js` is rebuilt automatically on every push and checked into the release artifact, not the source tree.

---

## What is already excellent

- **`pkg/core` is truly minimal.** Eight tiny files, no imports from anything else in the tree. That is the right shape for a future `github.com/authfly/core` module.
- **`authkit.Renderer` is a proper interface**, not a concrete type. The server depends on the interface, the constructor returns it, and the Hanko-specific bits live outside `pkg/authkit`. This is the cleanest layering the project has had so far.
- **Provider-agnostic `auth-config` JSON.** The design decision to inject a generic script via `FlowConfig.SDKScript` (instead of hard-coding `<script src="/static/js/auth-flow.js">` in the templ layout) is what made the whole thing click. Nothing in `pkg/authkit` needs to know Hanko exists.
- **`saml/postform.html` is now embedded next to the SAML code.** The previous `templates/` folder was the last place where "HTML lived at the project root" — that is gone now. SAML POST binding is fully self-contained in `internal/protocol/saml/`.
- **`MergedFS` helper** is a nice touch: it lets provider packages contribute their own assets under the same `/static/` prefix without the core server needing to know the layout. This is the extension point future providers (`authkit-supabase`, `authkit-custom`) will use.
- **TypeScript side is strictly contract-shaped.** `@authfly/core` exports `AuthProvider`, `AuthState`, `AuthFlow`, `AuthDOMController` with zero Hanko references. Hanko lives behind `HankoProvider` and the UMD bundle. A future `@authfly/authkit-supabase` drops in at the same seam.

---

## Net assessment

**Phase "AuthKit SDK Extraction" is done and verifiable.** The remaining work is cosmetic (empty folders, stale shims, documentation) and operational (Docker build pipeline for the TS artifact). None of it blocks the next phase — extracting `pkg/authkit` and `pkg/authkit-hanko` into separate repositories under `github.com/authfly/`.

The codebase is now in a state where that extraction is a **mechanical move** rather than a refactor, which is the best signal that the architectural goals of this phase were met.
