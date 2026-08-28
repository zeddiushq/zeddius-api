use sqlx::PgPool;

use super::model::Exercise;

pub async fn list(db: &PgPool) -> Result<Vec<Exercise>, sqlx::Error> {
    sqlx::query_as!(
        Exercise,
        r#"SELECT id, name, slug, muscle_groups, equipment, default_set_scheme, progression_type
         FROM exercises
         ORDER BY name"#,
    )
    .fetch_all(db)
    .await
}
