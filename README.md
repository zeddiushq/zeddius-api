# zeddius-api

Rust/Axum backend for Zeddius.

## Local development

```bash
# Point DATABASE_URL at a local instance
sqlx migrate run
cargo run
```

```bash
# install prettier globally (one time)
npm install -g prettier prettier-plugin-sql
# format SQL files
prettier --write migrations/**/*.sql --plugin=prettier-plugin-sql --language=postgresql
```
