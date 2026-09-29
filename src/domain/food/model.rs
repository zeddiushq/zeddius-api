use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Debug, Serialize, ToSchema)]
pub struct FoodEntry {
    pub id: Uuid,
    pub consumed_at: DateTime<Utc>,
    pub name: String,
    pub kcal: Option<Decimal>,
    pub protein_g: Option<Decimal>,
    pub carbs_g: Option<Decimal>,
    pub fat_g: Option<Decimal>,
    pub source: String,
    pub portion_count: Option<Decimal>,
    pub meal_slot: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateFoodEntryRequest {
    pub consumed_at: DateTime<Utc>,
    pub name: String,
    pub kcal: Option<Decimal>,
    pub protein_g: Option<Decimal>,
    pub carbs_g: Option<Decimal>,
    pub fat_g: Option<Decimal>,
    pub portion_count: Option<Decimal>,
    pub meal_slot: Option<String>,
}

// SQL COALESCE means omitted = unchanged; there's no way to clear a field to null via PATCH.
// Delete and re-create the entry if a field needs clearing.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateFoodEntryRequest {
    pub consumed_at: Option<DateTime<Utc>>,
    pub name: Option<String>,
    pub kcal: Option<Decimal>,
    pub protein_g: Option<Decimal>,
    pub carbs_g: Option<Decimal>,
    pub fat_g: Option<Decimal>,
    pub portion_count: Option<Decimal>,
    pub meal_slot: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct FoodEntryQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

pub const MEAL_SLOTS: [&str; 4] = ["breakfast", "lunch", "dinner", "snack"];
