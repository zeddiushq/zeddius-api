use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Serialize, ToSchema)]
pub struct Exercise {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub muscle_groups: Vec<String>,
    pub equipment: Vec<String>,
    pub default_set_scheme: Option<Value>,
    pub progression_type: String,
}
