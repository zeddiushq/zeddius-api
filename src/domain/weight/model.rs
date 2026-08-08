use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct WeightLog {
    pub id: Uuid,
    pub recorded_at: DateTime<Utc>,
    pub weight_kg: Decimal,
    pub body_fat_pct: Option<Decimal>,
    pub muscle_mass_kg: Option<Decimal>,
    pub water_pct: Option<Decimal>,
    pub bone_mass_kg: Option<Decimal>,
    pub source: String,
    pub source_uuid: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateWeightLogRequest {
    pub recorded_at: DateTime<Utc>,
    pub weight_kg: Decimal,
    pub body_fat_pct: Option<Decimal>,
    pub muscle_mass_kg: Option<Decimal>,
    pub water_pct: Option<Decimal>,
    pub bone_mass_kg: Option<Decimal>,
}

#[derive(Debug, Deserialize)]
pub struct WeightLogQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}
