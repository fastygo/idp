# `authkit-hanko` — Hanko provider for AuthFly

Hanko-specific implementation of **`core.CredentialVerifier`**: JWT verification against Hanko’s JWKS, token extraction from cookies, and **`FlowConfig`** that points the browser to **`/static/js/authkit-hanko.js`** (UMD bundle built from the TypeScript AuthFly core + `HankoProvider`).

## Contents

- **`NewVerifier(hankoAPIURL)`** — constructs the verifier and JWKS client.
- **`StaticFS()`** — embeds `static/js/authkit-hanko.js` (and any other Hanko-only assets) for merging with `authkit` static files on the same `/static/` prefix.

## Future module

Intended to become **`github.com/authfly/authkit-hanko`**, depending on **`github.com/authfly/core`**. Rebuild `static/js/authkit-hanko.js` from `@authfly/core` + Hanko adapter in CI when publishing.
