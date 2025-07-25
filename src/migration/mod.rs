// ABOUTME: SeaORM migration module for database schema management
// ABOUTME: Handles initial schema creation and future migrations

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20241201_000001_create_initial_tables::Migration),
        ]
    }
}

pub mod m20241201_000001_create_initial_tables;