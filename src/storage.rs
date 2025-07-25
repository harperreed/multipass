// ABOUTME: SeaORM database storage layer for users, credentials, files, and versions
// ABOUTME: Handles all database operations using SeaORM entities and migrations

use anyhow::Result;
use sea_orm::{Database, DatabaseConnection, EntityTrait, ActiveModelTrait, Set, ColumnTrait, QueryFilter, PaginatorTrait};
use sea_orm_migration::MigratorTrait;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::types::*;
use crate::entities::{user, credential, file, file_version};
use crate::migration::Migrator;

pub struct Storage {
    pub db: DatabaseConnection,
}

impl Storage {
    pub async fn new() -> Result<Self> {
        // Connect to SQLite database
        let db = Database::connect("sqlite:multipass.db?mode=rwc").await?;
        
        // Run migrations
        Migrator::up(&db, None).await?;
        
        Ok(Self { db })
    }

    // User operations
    pub async fn store_user(&self, user_data: &User) -> Result<()> {
        let user = user::ActiveModel {
            id: Set(user_data.id),
            username: Set(user_data.username.clone()),
            display_name: Set(user_data.display_name.clone()),
            created_at: Set(chrono::Utc::now().timestamp()),
        };
        
        user.insert(&self.db).await?;
        Ok(())
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User> {
        let user_model = user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .one(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        Ok(User {
            id: user_model.id,
            username: user_model.username,
            display_name: user_model.display_name,
        })
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<User> {
        let user_model = user::Entity::find_by_id(user_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        Ok(User {
            id: user_model.id,
            username: user_model.username,
            display_name: user_model.display_name,
        })
    }

    // Credential operations
    pub async fn store_credential(&self, credential_id: &str, user_id: Uuid, passkey: &Passkey) -> Result<()> {
        let credential_data = bincode::serialize(passkey)?;
        
        let credential = credential::ActiveModel {
            id: Set(credential_id.to_string()),
            user_id: Set(user_id),
            credential_data: Set(credential_data),
            counter: Set(0),
            created_at: Set(chrono::Utc::now().timestamp()),
        };

        credential.insert(&self.db).await?;
        Ok(())
    }

    pub async fn get_credential(&self, credential_id: &str) -> Result<StoredCredential> {
        let credential_model = credential::Entity::find_by_id(credential_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Credential not found"))?;

        Ok(StoredCredential {
            id: credential_model.id,
            user_id: credential_model.user_id,
            credential_data: credential_model.credential_data,
            counter: credential_model.counter as u32,
        })
    }

    pub async fn get_user_credentials(&self, user_id: Uuid) -> Result<Vec<StoredCredential>> {
        let credentials = credential::Entity::find()
            .filter(credential::Column::UserId.eq(user_id))
            .all(&self.db)
            .await?;

        Ok(credentials.into_iter().map(|c| StoredCredential {
            id: c.id,
            user_id: c.user_id,
            credential_data: c.credential_data,
            counter: c.counter as u32,
        }).collect())
    }

    pub async fn update_credential_counter(&self, credential_id: &str, counter: u32) -> Result<()> {
        let credential = credential::Entity::find_by_id(credential_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Credential not found"))?;

        let mut credential: credential::ActiveModel = credential.into();
        credential.counter = Set(counter as i64);
        credential.update(&self.db).await?;

        Ok(())
    }

    // File operations - TODO: Implement after updating crypto module
    pub async fn create_file(&self, _req: &CreateFileRequest, _user_id: Uuid) -> Result<CreateFileResponse> {
        // TODO: Implement file creation with new crypto integration
        Err(anyhow::anyhow!("File creation not yet implemented with SeaORM"))
    }

    pub async fn get_files_for_user(&self, passkey_id: &str) -> Result<Vec<FileInfo>> {
        let files = file::Entity::find()
            .filter(file::Column::PasskeyId.eq(passkey_id))
            .all(&self.db)
            .await?;

        let mut file_infos = Vec::new();
        for f in files {
            // Count versions for this file
            let version_count = file_version::Entity::find()
                .filter(file_version::Column::FileId.eq(f.id))
                .count(&self.db)
                .await? as i32;

            file_infos.push(FileInfo {
                id: f.id,
                filename: f.filename,
                tags: f.tags,
                version_count,
                created_at: f.created_at,
                updated_at: f.updated_at,
            });
        }

        Ok(file_infos)
    }

    // Legacy methods for compatibility - will be removed after migration
    pub async fn store_encrypted_data(&self, _data: &EncryptedData) -> Result<()> {
        // This is a temporary bridge method
        // In the new system, this will be handled by create_file and save_version
        Ok(())
    }

    pub async fn get_encrypted_data(&self, _passkey_id: &str) -> Result<Vec<EncryptedData>> {
        // Legacy compatibility - return empty for now
        Ok(vec![])
    }

    pub async fn get_encrypted_data_by_id(&self, _data_id: &str) -> Result<EncryptedData> {
        // Legacy compatibility - this method will be phased out
        Err(anyhow::anyhow!("Legacy method - use file operations instead"))
    }

    pub async fn delete_encrypted_data(&self, _data_id: &str) -> Result<()> {
        // Legacy compatibility - this will become delete_file
        Ok(())
    }
}