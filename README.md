# zeddius-api

Rust/Axum backend for Zeddius. See [CLAUDE.md](./CLAUDE.md) for full architecture and conventions.

## Local development

```bash
# Point DATABASE_URL at a Neon instance (see .env)
sqlx migrate run
cargo watch -x run
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

Three GitHub Actions workflows in `.github/workflows/`, mirroring `zeddius-web`:

- **`development.yml`** — on PR to `main`: fmt/clippy/test, build+push image, run migrations,
  deploy to the dev Cloud Run service.
- **`production.yml`** — on PR merge to `main`: build+push a version-tagged image, tag the
  release, bump the patch version. Does not deploy.
- **`deploy.yml`** — manual dispatch: run migrations and deploy a specific version to
  `development` or `production`.

Deploys to Cloud Run on GCP (`zeddiusdev` / `zeddiusprod` projects), authenticated via
Workload Identity Federation. Database is Neon Postgres (no Cloud SQL proxy needed).
