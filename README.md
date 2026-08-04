# zeddius-api

Rust/Axum backend for Zeddius.

## Local development

```bash
# Point DATABASE_URL at a Neon instance
sqlx migrate run
cargo run
```

## sqlx offline query cache (`.sqlx/`)

`sqlx::query_as!` normally connects to a live, already-migrated Postgres at `cargo build`
time to type-check each query. The Docker build has no DB access and CI builds the image
*before* running that PR's migrations, so the build instead reads cached query metadata from
`.sqlx/*.json` via `SQLX_OFFLINE=true` (set in the [Dockerfile](./Dockerfile)).

**`.sqlx/` is checked into git.** It is compile-time metadata, not a build artifact — every
machine and CI need it to type-check without a live DB.

### TODO for every new query or schema-affecting migration

Re-run this locally (against a real, migrated `DATABASE_URL`) and commit the result:

```bash
cargo install sqlx-cli --no-default-features --features rustls,postgres  # once
cargo sqlx prepare
```

If you forget, the build fails with "no cached data for this query" rather than silently
using stale metadata — but it's easy to forget, so treat it as part of the change whenever
`src/**/repo.rs` or `migrations/` changes.

## CI/CD

Three GitHub Actions workflows in `.github/workflows/`:

- **`development.yml`** — on PR to `main`: fmt/clippy/test, build+push image, run migrations,
  deploy to the dev Cloud Run service.
- **`production.yml`** — on PR merge to `main`: build+push a version-tagged image, tag the
  release, bump the patch version. Does not deploy.
- **`deploy.yml`** — manual dispatch: run migrations and deploy a specific version to
  `development` or `production`.

Deploys to Cloud Run on GCP (`zeddiusdev` / `zeddiusprod` projects), authenticated via
Workload Identity Federation. Database is Neon Postgres.

## API endpoint flows

Every branch below is what the code actually does, not just the happy path. `AuthUser` means
the endpoint requires a valid bearer token only (identity, any verification status). `VerifiedUser`
additionally requires `email_verified_at` to be set. Endpoints with neither are unauthenticated.

### `GET /health`

```mermaid
flowchart TD
    A[Request] --> A1[200 OK<br/>status, name, version]
```

### `POST /auth/register`

```mermaid
flowchart TD
    A[Request: email, username,<br/>display_name, password] --> B{All fields present?}
    B -- no --> B1[422 Validation Failed]
    B -- yes --> C{Valid email format?}
    C -- no --> C1[422 Validation Failed]
    C -- yes --> D{Password >= 8 chars?}
    D -- no --> D1[422 Validation Failed]
    D -- yes --> E{Username reserved?}
    E -- yes --> E1[422 Validation Failed]
    E -- no --> F{Verified user already<br/>exists with this email?}
    F -- yes --> F1[409 Conflict<br/>email already registered]
    F -- no --> G[Hash password]
    G --> H[Insert user row<br/>email_verified_at = NULL]
    H --> I{Insert conflict?}
    I -- users_username_key --> I1[409 Conflict<br/>username already taken]
    I -- other db error --> I2[500 Internal]
    I -- no conflict --> J[Generate + store code<br/>send via Resend]
    J --> K[Issue tokens]
    K --> K1[201 Created]
```

### `POST /auth/login`

```mermaid
flowchart TD
    A[Request: email, password] --> B[Fetch every user row<br/>matching this email]
    B --> C{Any candidates<br/>password matches?}
    C -- no --> C1[401 Unauthorized]
    C -- yes --> D[Issue tokens]
    D --> D1[200 OK]
```

More than one unverified row can share an email, so this checks the password against every
candidate rather than trusting a single, arbitrarily-picked match.

### `POST /auth/refresh`

```mermaid
flowchart TD
    A[Request: refresh_token] --> B{Hash matches an active,<br/>unexpired refresh token?}
    B -- no --> B1[401 Unauthorized]
    B -- yes --> C[Revoke old access +<br/>refresh token pair]
    C --> D[Issue new token pair<br/>same transaction]
    D --> D1[200 OK]
```

### `POST /auth/logout` — `AuthUser`

```mermaid
flowchart TD
    A[Request: Bearer token] --> B{Token valid?}
    B -- no --> B1[401 Unauthorized]
    B -- yes --> C[Revoke this access +<br/>refresh token pair]
    C --> C1[204 No Content]
```

### `GET /auth/sessions` — `AuthUser`

```mermaid
flowchart TD
    A[Request: Bearer token] --> B{Token valid?}
    B -- no --> B1[401 Unauthorized]
    B -- yes --> C[List active sessions<br/>for this user]
    C --> C1[200 OK<br/>id, created_at, expires_at,<br/>user_agent, is_current]
```

### `DELETE /auth/sessions` — `AuthUser`

```mermaid
flowchart TD
    A[Request: Bearer token] --> B{Token valid?}
    B -- no --> B1[401 Unauthorized]
    B -- yes --> C[Revoke every other session<br/>callers own session stays live]
    C --> C1[204 No Content]
```

### `POST /auth/verify-email` — `AuthUser`

```mermaid
flowchart TD
    A[Request: Bearer token, code] --> B{Token valid?}
    B -- no --> B1[401 Unauthorized]
    B -- yes --> C{User row found<br/>for this token?}
    C -- no --> C1[500 Internal<br/>invariant violation]
    C -- yes --> D{Code hash + expiry present,<br/>match, not expired?}
    D -- no --> D1[401 Unauthorized]
    D -- yes --> E{A different row already<br/>holds this email verified?}
    E -- yes --> F[Merge: reassign oauth_accounts,<br/>backfill password if missing,<br/>delete this row]
    F --> F1[Issue tokens for<br/>the existing row<br/>200 OK]
    E -- no --> G[Promote this row:<br/>set email_verified_at,<br/>clear code fields]
    G --> G1[Issue tokens for<br/>this row<br/>200 OK]
```

### `POST /auth/resend-verification` — `AuthUser`

```mermaid
flowchart TD
    A[Request: Bearer token] --> B{Token valid?}
    B -- no --> B1[401 Unauthorized]
    B -- yes --> C{Already verified?}
    C -- yes --> C1[204 No Content<br/>no-op]
    C -- no --> D{User row found<br/>for this token?}
    D -- no --> D1[500 Internal<br/>invariant violation]
    D -- yes --> E[Generate + store new code<br/>send via Resend]
    E --> E1[204 No Content]
```

### `POST /auth/oauth/apple`

```mermaid
flowchart TD
    A[Request: identity_token] --> B{Token verifies AND<br/>has an email claim?}
    B -- no --> B1[401 Unauthorized]
    B -- yes --> C{oauth_accounts row<br/>for this sub?}
    C -- yes --> C1[Issue tokens<br/>200 OK]
    C -- no --> D{Verified user exists<br/>with this email?}
    D -- no --> D1[204 No Content<br/>go onboard via /complete]
    D -- yes --> E{User has<br/>password_hash?}
    E -- yes --> E1[409 Conflict<br/>prove password via /link]
    E -- no --> F{claims.email_verified?}
    F -- false --> F1[204 No Content<br/>treated as no match]
    F -- true --> G{has_oauth_email<br/>user.id, user.email?}
    G -- yes --> G1[Link oauth_accounts row<br/>Issue tokens<br/>200 OK]
    G -- no --> G2[log error: impossible state<br/>204 No Content]
```

### `POST /auth/oauth/apple/complete`

```mermaid
flowchart TD
    A[Request: identity_token,<br/>username, display_name] --> B{Token verifies AND<br/>has an email claim?}
    B -- no --> B1[401 Unauthorized]
    B -- yes --> C{oauth_accounts row<br/>for this sub already?}
    C -- yes --> C1[Idempotent: issue tokens<br/>200 OK]
    C -- no --> D{username / display_name<br/>empty, or username reserved?}
    D -- yes --> D1[422 Validation Failed]
    D -- no --> E[email_verified_at =<br/>claims.email_verified ? now : None]
    E --> F[create_with_oauth:<br/>insert users + oauth_accounts row]
    F --> G{Insert conflict?}
    G -- users_email_verified_unique --> G1[409 Conflict<br/>email already registered]
    G -- users_username_key --> G2[409 Conflict<br/>username already taken]
    G -- other db error --> G3[500 Internal]
    G -- no conflict --> H{email_verified_at<br/>is None?}
    H -- yes --> H1[Generate + store code<br/>send via Resend]
    H -- no --> I[Issue tokens]
    H1 --> I
    I --> I1[201 Created]
```

### `POST /auth/oauth/apple/link`

```mermaid
flowchart TD
    A[Request: identity_token,<br/>password] --> B{Token verifies AND<br/>has an email claim?}
    B -- no --> B1[401 Unauthorized]
    B -- yes --> C{oauth_accounts row<br/>for this sub already?}
    C -- yes --> C1[Idempotent: issue tokens<br/>200 OK]
    C -- no --> D{Verified user exists<br/>with this email?}
    D -- no --> D1[401 Unauthorized]
    D -- yes --> E{User has<br/>password_hash?}
    E -- no --> E1[401 Unauthorized]
    E -- yes --> F{password matches<br/>hash?}
    F -- no --> F1[401 Unauthorized]
    F -- yes --> G[link_oauth_account:<br/>insert oauth_accounts row]
    G --> G1[Issue tokens<br/>200 OK]
```

`oauth_apple_link` deliberately collapses three different failure reasons (no verified
account, no password on the account, wrong password) into the same `401` — the same
anti-enumeration reasoning as `login` never distinguishing "no such account" from "wrong
password."

### `GET /auth/username/{username}/available`

```mermaid
flowchart TD
    A[Request: username] --> B{Username reserved?}
    B -- yes --> B1[200 OK<br/>available: false]
    B -- no --> C{Username already<br/>exists in DB?}
    C -- yes --> C1[200 OK<br/>available: false]
    C -- no --> C2[200 OK<br/>available: true]
```

### `GET /users/me` — `VerifiedUser`

```mermaid
flowchart TD
    A[Request: Bearer token] --> B{Token valid?}
    B -- no --> B1[401 Unauthorized]
    B -- yes --> C{email_verified_at set?}
    C -- no --> C1[403 Forbidden]
    C -- yes --> D{User row found<br/>for this token?}
    D -- no --> D1[500 Internal<br/>invariant violation]
    D -- yes --> E[200 OK<br/>full user profile]
```
