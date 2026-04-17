# `authkit` — hosted login UI (Go + templ)

Embeddable **HTML/CSS** for sign-in, sign-out, and error pages: `templ` views, embedded i18n (`en` / `ru`), Tailwind-built CSS, and shared static assets (e.g. `ui8kit.js`).

## Role

- Implements **`Renderer`**: `RenderLogin`, `RenderLogout`, `RenderError`, plus `StaticFS()` for `/static/...`.
- Takes **`ViewConfig`** from the host app: branding, `core.FlowConfig` (including **`SDKScript`** — provider-specific browser bundle), and `core.FeatureFlags`.
- **Does not** import Hanko or other credential backends; it only renders what the config describes.

## Future module

Intended to become **`github.com/authfly/authkit`**. It will depend on **`github.com/authfly/core`** and remain free of IdP-specific wiring.
