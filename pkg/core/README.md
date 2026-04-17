# `core` — AuthFly shared contracts

Provider-agnostic types and interfaces for IdP flows. This package has **no** dependencies on UI, Hanko, or any specific storage.

## Contents

- **`FlowConfig`** — API URL, session cookie name, logout path, and path to the browser SDK script (`SDKScript`).
- **`FeatureFlags`** — registration toggles (public, OIDC, SAML).
- **`AuthCode` / `AuthCodeStore`** — OAuth2-style authorization codes for the OIDC layer.
- **`CredentialVerifier`** — verify bearer/session tokens and expose `FlowConfig()` for the UI layer.
- **`IdentityClaims`**, session helpers, and shared errors.

## Future module

Intended to become **`github.com/authfly/core`** as a standalone Go module. Consumers (IdP apps, `pkg/authkit`, provider packages) depend only on these contracts.
