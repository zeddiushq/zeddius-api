# zeddius-api — Agent Guide

This file describes conventions for working in this specific repository. For product decisions, the data model, the API contract, and the build sequence, **read `~/code/zeddius-docs/PLAN.md`**. That file is the source of truth.

---

## What this repo is

The Zeddius backend. System of record for all user data, and the sole auth authority. Single REST/JSON API consumed by `zeddius-ios` and `zeddius-web`.

**Stack:**
- Rust (stable)
- Axum — web framework (Tokio-native)
- Tokio — async runtime
- sqlx — async Postgres driver with compile-time query checking and built-in migrations
- serde / serde_json — serialization
- Deployed to Cloud Run on GCP, Neon (serverless Postgres) for the database
- CI/CD: GitHub Actions with Workload Identity Federation

**Auth crates (primitives only — no auth frameworks):**
- `argon2` — Argon2id password hashing
- `sha2` — SHA-256 for token hashing before storage
- `rand` — cryptographically secure random token generation
- `reqwest` — HTTP client for fetching Apple's JWKS
- `jsonwebtoken` — Apple identity token signature verification

**Supporting crates:**
- `uuid` — UUID type with sqlx + serde feature flags
- `chrono` — `DateTime<Utc>` for all timestamps
- `rust_decimal` — `Decimal` for weights and macros (no float drift)
- `anyhow` — error context propagation in internal code
- `thiserror` — derive macro for the `AppError` type
- `tower` / `tower-http` — middleware (CORS, request tracing, compression)
- `tracing` / `tracing-subscriber` — structured logging

---

## Project layout

```
zeddius-api/
├── Cargo.toml
├── Cargo.lock
├── migrations/                    -- sqlx migration files (0001_init.sql, etc.)
├── src/
│   ├── main.rs                    -- server bootstrap, router assembly
│   ├── config.rs                  -- env var loading into Config struct
│   ├── db.rs                      -- sqlx pool setup
│   ├── error.rs                   -- AppError enum + IntoResponse impl
│   ├── state.rs                   -- AppState (pool, config, shared resources)
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── extractor.rs           -- AuthUser: FromRequestParts impl (token DB lookup)
│   │   ├── service.rs             -- token issuance, refresh, revocation
│   │   └── apple.rs               -- Apple identity token verification (JWKS fetch + verify)
│   └── domain/
│       ├── mod.rs
│       ├── user/
│       │   ├── mod.rs
│       │   ├── model.rs           -- User struct, request/response types
│       │   ├── routes.rs          -- Axum handlers
│       │   └── repo.rs            -- sqlx queries
│       ├── weight/
│       ├── food/
│       ├── recipe/
│       ├── workout/
│       ├── sleep/
│       ├── checkin/
│       ├── exercise/
│       ├── measurement/
│       ├── screentime/
│       ├── healthkit/
│       ├── forecast/              -- WeightForecaster, LiftForecaster, MoodForecaster
│       ├── importing/             -- Weight Gurus CSV importer
│       └── seed/                  -- Exercise + food seed loaders
└── .github/workflows/
```

Each domain module owns its models, routes (handlers), and repo (sqlx queries). Handlers are thin — extract auth, validate input, call repo, return response.

---

## Conventions

### Rust idioms

**`use` statements**
- Functions: import the parent module, call as `module::function()`. Makes it clear the function isn't defined locally.
- Types (structs, enums): import the item directly. PascalCase already signals "this is a type."
- Traits: import the item directly. You need traits in scope for their methods to work, but you don't call `Trait::method()` explicitly.
- Macros: import directly. The `!` suffix makes them visually distinct regardless.
- Modules used as namespaces: import the module (e.g. `use tracing_subscriber::fmt`), call as `fmt::layer()`.

```rust
use axum::{Router, routing};           // routing = module (has functions inside)
use tokio::net::TcpListener;           // TcpListener = struct
use tracing::info;                     // info = macro
use tracing_subscriber::{EnvFilter, fmt, prelude::*};  // EnvFilter = struct, fmt = module
```

**Unwrap and error handling**
- Never call `.unwrap()` in handler code. Handlers return `Result<_, AppError>` and use `?`.
- In `main`: return `anyhow::Result<()>` and use `?` so startup failures print a clean error and exit non-zero. Do not `unwrap()` in main.
- When an operation is genuinely infallible by construction (invariant holds because of prior code), use `.expect("why this can't fail")` over silent `.unwrap()`. The message documents the invariant.
- Use `.context("what was being attempted")?` on startup operations for log observability — not because the error is recoverable, but because "failed to bind to 0.0.0.0:8080 / caused by: address in use" is more useful in Cloud Run logs than a raw OS error code.

```rust
// main — startup failures propagate cleanly
let listener = TcpListener::bind("0.0.0.0:8080")
    .await
    .context("failed to bind to 0.0.0.0:8080")?;
info!("listening on {}", listener.local_addr().expect("bound listener has local addr"));

// handler — errors become HTTP responses
async fn get_user(State(state): State<AppState>, auth: AuthUser) -> Result<Json<User>, AppError> {
    let user = user_repo::find(&state.db, auth.user_id).await?;
    Ok(Json(user))
}
```

**Transitive dependencies**
- Do not add a crate to `Cargo.toml` just because a dependency re-exports it. Use the re-export path instead.
- `axum` re-exports `http` as `axum::http` — use `axum::http::StatusCode`, not `http::StatusCode`, and don't add `http` to `Cargo.toml`.
- Only add a crate directly if you need something it doesn't re-export, or if you need to pin its version independently of what your dependencies expect.

**anyhow vs thiserror**
- `anyhow` is for application-level error propagation where the caller doesn't need to match on error variants — startup code, internal utilities, `main`. Use `anyhow::Result<T>` and `?` freely.
- `thiserror` is for `AppError` — the typed error enum that handlers return. It needs concrete variants so `IntoResponse` can map each one to the correct HTTP status and body.

### Data types

Use `Decimal` (from `rust_decimal`) for all weights and macros. Never `f64`. Use `Uuid` for all IDs. Use `DateTime<Utc>` (from `chrono`) for all timestamps — no naive datetimes.

```rust
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct WeightLog {
    pub id: Uuid,
    pub user_id: Uuid,
    pub recorded_at: DateTime<Utc>,
    pub weight_kg: Decimal,
    pub body_fat_pct: Option<Decimal>,
    pub muscle_mass_kg: Option<Decimal>,
    pub source: String,
    pub source_uuid: Option<String>,
    pub created_at: DateTime<Utc>,
}
```

### Multi-user scoping is enforced server-side

Never accept a `user_id` from the client. The `AuthUser` extractor resolves the authenticated user from the token and injects it into every handler. All repo functions take `user_id` as an explicit parameter.

```rust
async fn list_weight_logs(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<WeightLogQuery>,
) -> Result<Json<Vec<WeightLog>>, AppError> {
    let logs = weight_repo::list(&state.db, auth.user_id, &params).await?;
    Ok(Json(logs))
}
```

If a handler that accesses user data doesn't take `AuthUser`, that's a bug.

### Auth flow

1. Client sends `Authorization: Bearer <opaque-token>`
2. `AuthUser` extractor (implements `FromRequestParts`) reads the header
3. Computes `SHA-256(token)`
4. Queries: `SELECT user_id FROM access_tokens WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`
5. If found: returns `AuthUser { user_id }` — handler proceeds
6. If not found / expired / revoked: returns 401 immediately

No JWT verification. No external auth service. Every authenticated request costs one indexed DB read.

### Token issuance (`auth/service.rs`)

```
generate_token() → OsRng → 32 random bytes → hex-encode → raw token returned to client
store_token()    → SHA-256(raw_token) → insert into access_tokens or refresh_tokens
verify_token()   → SHA-256(presented_token) → SELECT from table → check expiry + revocation
```

Raw tokens are never stored. Only hashes. The raw token leaves the server exactly once in the response body at issuance.

### Apple identity token verification (`auth/apple.rs`)

On `POST /auth/oauth/apple`:
1. Fetch Apple's JWKS from `https://appleid.apple.com/auth/keys` (cache with short TTL)
2. Decode and verify the identity token JWT signature using the matching public key
3. Validate claims: `iss = https://appleid.apple.com`, `aud = <your bundle ID>`, `exp > now()`
4. Extract `sub` (Apple user ID) and `email`
5. Look up `oauth_accounts` by `(provider = 'apple', provider_user_id = sub)`
6. If found → issue token pair for the linked user
7. If not found → return `needs_onboarding: true` with no tokens

The identity token is verified and discarded. It never leaves the auth handler.

### Error handling

Define a single `AppError` enum. Implement `IntoResponse` on it. Handlers return `Result<_, AppError>` — never panic in a request path, never call `unwrap()`.

```rust
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("{0} not found")]
    NotFound(&'static str),
    #[error("validation failed")]
    ValidationFailed(Vec<FieldError>),
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}
```

All errors serialize to:
```json
{ "error": { "code": "NOT_FOUND", "message": "Weight log not found" } }
```

### Validation

Validate request bodies in the handler before calling the repo. Use guard clauses, not a validation framework. Return `AppError::ValidationFailed` with field-level detail for client errors.

### sqlx queries

Use `sqlx::query_as!` macro for compile-time checked queries. Queries live in `repo.rs` files within each domain module.

```rust
pub async fn list(
    db: &PgPool,
    user_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<WeightLog>, sqlx::Error> {
    sqlx::query_as!(
        WeightLog,
        "SELECT * FROM weight_logs
         WHERE user_id = $1 AND recorded_at BETWEEN $2 AND $3
         ORDER BY recorded_at DESC",
        user_id,
        from,
        to
    )
    .fetch_all(db)
    .await
}
```

### Migrations

sqlx migrations in `migrations/`. Numbered sequentially: `0001_init.sql`, `0002_seed_exercises.sql`, etc.

- One concern per migration file
- Never edit a migration that has been applied. Add a new one.
- `sqlx migrate run` applies pending migrations. In production this runs as a one-off Cloud Run job before the API rolls.

To add a migration:
```bash
sqlx migrate add <description>
# edit the generated file in migrations/
sqlx migrate run
```

### Configuration

All config from environment variables. `config.rs` loads them into a `Config` struct at startup — fail fast on missing required values, not at first use.

Required env vars:
- `DATABASE_URL` — Neon connection string (includes pooler URL for production)
- `APPLE_BUNDLE_ID` — used to validate `aud` claim in Apple identity tokens
- `GCS_BUCKET_PHOTOS` — Cloud Storage bucket for body photo uploads
- `RUST_LOG` — tracing filter (e.g., `zeddius_api=debug,sqlx=warn`)

### Shared app state

`AppState` is cloned cheaply into every handler via `State<AppState>`. It holds the `PgPool` and `Config`. Nothing else lives as a global.

```rust
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
}
```

### HealthKit sync endpoint

`POST /v1/healthkit/sync` accepts a batch of HealthKit samples. The handler:
1. Stores raw samples in `healthkit_samples` (audit log) — dedup by `sample_uuid` using `ON CONFLICT DO NOTHING`
2. Routes samples to typed handlers per `sample_type` (e.g., `HKQuantityTypeIdentifierBodyMass` → `weight_logs`)
3. Each typed handler upserts into the appropriate domain table, also using `sample_uuid` for dedup

iOS can re-send the same sample batch without creating duplicates.

### Forecasting

`domain/forecast/` owns trajectory math.

- `WeightForecaster`: linear regression on the 7-day moving average of `weight_logs`. Output: predicted weight at +30, +60, +90 days with a confidence interval based on residuals.
- `LiftForecaster`: Epley 1RM estimate per `lift_set` (best set per exercise per workout) → linear regression over recent sessions → projected 1RM at +30, +60, +90.
- `MoodForecaster`: 14-day moving average of mood/focus/energy.

Keep the math simple and explicit. No ML crates, no time-series frameworks.

### Local development

```bash
# Start local Postgres (or point DATABASE_URL at a Neon dev branch)
docker compose up -d db

# Run migrations
sqlx migrate run

# Start API (with hot reload via cargo-watch)
cargo watch -x run

# Run tests
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

Prefer pointing `DATABASE_URL` at a Neon dev branch over running local Postgres — it eliminates the Docker dependency and matches the production driver behavior exactly.

### CI/CD

Three workflow files mirroring the pattern used in `zeddius-web`.

**`development.yml`** — triggers on PR open, sync, reopen against `main`:
1. Check out code (GitHub App token)
2. Set up GCP via WIF (`zeddiushq/github-actions/setup-gcp@main`)
3. `cargo fmt --check` — fail fast on unformatted code
4. `cargo clippy -- -D warnings` — treat all warnings as errors
5. `cargo test` — run the full test suite
6. Build and push Docker image tagged with `github.sha` to Artifact Registry
7. Run migrations against the dev Neon database: `sqlx migrate run` with `DATABASE_URL` from the `development` environment secrets
8. Deploy to dev Cloud Run

Migrations run after the image build so a compilation failure stops the pipeline before touching the database. They run before the deploy so the new binary never starts against a stale schema. You do not need to run migrations manually before opening a PR.

**`production.yml`** — triggers on PR closed against `main`, only when merged:
1. Check out code (GitHub App token, `contents: write` permission for the version commit)
2. Set up GCP via WIF
3. Read version from `Cargo.toml`: `cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version'`
4. Build and push Docker image tagged with the semver version
5. Tag the git release: `git tag v<version> && git push origin v<version>`
6. Create GitHub release: `gh release create v<version> --generate-notes`
7. Bump version in `Cargo.toml`: `cargo install cargo-edit && cargo set-version --bump patch`
8. Commit and push the bumped `Cargo.toml` and `Cargo.lock`

Production deploy is intentionally NOT automatic — the image is built and tagged here, but deployment requires a manual trigger.

**`deploy.yml`** — manual `workflow_dispatch`, inputs: `version` (e.g. `0.1.0`) and `environment` (`development` or `production`):
1. Set up GCP via WIF (no checkout needed — just deploying an already-built image)
2. Run migrations: `sqlx migrate run` with `DATABASE_URL` from secrets — Neon is internet-accessible so no proxy needed
3. Deploy to Cloud Run using the versioned image

The migration step in `deploy.yml` runs before the Cloud Run revision goes live. If migrations fail, the deploy stops before the new binary is running. This prevents the API starting against a schema it doesn't match.

**Dockerfile** uses a multi-stage build: stage 1 compiles the release binary with the official `rust` image; stage 2 copies only the binary into a minimal `debian:bookworm-slim` runtime image with `ca-certificates` for TLS. The resulting image is typically 20–50 MB vs. several GB for the build stage.

**WIF setup:** org-level provider with environment-level conditions, per-repo service account impersonation bindings across separate `zeddius-dev` and `zeddius-prod` GCP projects. Mirrors the existing pattern in `zeddius-web`.

---

## What this repo does NOT do

- It does not call the Anthropic API or do any AI processing v1. Voice/photo food logging is post-MVP.
- It does not touch HealthKit (iOS only). It accepts pre-extracted samples via `/v1/healthkit/sync`.
- It does not serve any UI. Web and iOS are separate clients.
- It does not manage user credentials outside its own auth logic — no third-party auth service.

---

## When in doubt

- Product question → check `~/code/zeddius-docs/PLAN.md`, then ask Joshua.
- Stack question → use the simplest, most idiomatic Rust. Avoid clever macros and trait gymnastics for things that don't need it.
- Schema change → update `PLAN.md` first (data model section), then write the migration, then update the affected repo functions.
