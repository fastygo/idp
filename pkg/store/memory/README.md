# `store/memory` — in-memory `AuthCodeStore`

A thread-safe **in-memory** implementation of **`core.AuthCodeStore`** for OAuth2 authorization codes (save, consume, periodic cleanup). Suitable for single-process deployments and tests.

## Limitations

Data is **not** persisted across restarts and is not shared across multiple IdP instances. Replace with a shared store (Redis, SQL) when you scale horizontally or need durable codes.

## Future module

Can ship as **`github.com/authfly/store-memory`** or remain under **`github.com/authfly/core`** as a subpackage, depending on how you split repositories.
