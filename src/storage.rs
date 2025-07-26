// ABOUTME: SeaORM database storage layer for users, credentials, files, and versions
// ABOUTME: Handles all database operations using SeaORM entities and migrations

use anyhow::Result;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Set, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::entities::{credential, file, file_version, user};
use crate::migration::Migrator;
use crate::types::*;

#[derive(Debug, sea_orm::FromQueryResult)]
struct FileWithCount {
    pub id: Uuid,
    pub filename: String,
    pub tags: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub version_count: i32,
}

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
    pub async fn store_credential(
        &self,
        credential_id: &str,
        user_id: Uuid,
        passkey: &Passkey,
    ) -> Result<()> {
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

        Ok(credentials
            .into_iter()
            .map(|c| StoredCredential {
                id: c.id,
                user_id: c.user_id,
                credential_data: c.credential_data,
                counter: c.counter as u32,
            })
            .collect())
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

    // File operations
    pub async fn create_file(
        &self,
        req: &CreateFileRequest,
        user_id: Uuid,
        passkey_id: &str,
    ) -> Result<CreateFileResponse> {
        // Generate encryption materials
        let (salt, nonce_bytes) = crate::crypto::generate_encryption_materials()?;

        // Encrypt content using common utility
        let encrypted_content =
            crate::crypto::encrypt_with_materials(&req.content, passkey_id, &salt, &nonce_bytes)?;

        // Generate content hash for change detection using SHA-256
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(req.content.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        // Create file record
        let file_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        let file = file::ActiveModel {
            id: Set(file_id),
            user_id: Set(user_id),
            passkey_id: Set(passkey_id.to_string()),
            filename: Set(req.filename.clone()),
            tags: Set(req.tags.clone()),
            current_version_id: Set(Some(version_id)),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let file_version = file_version::ActiveModel {
            id: Set(version_id),
            file_id: Set(file_id),
            user_id: Set(user_id),
            version_number: Set(1),
            encrypted_content: Set(encrypted_content),
            nonce: Set(nonce_bytes.to_vec()),
            salt: Set(salt.to_vec()),
            content_hash: Set(content_hash),
            change_summary: Set(Some("Initial version".to_string())),
            created_at: Set(now),
        };

        // Insert both records in a transaction-like fashion
        file.insert(&self.db).await?;
        file_version.insert(&self.db).await?;

        Ok(CreateFileResponse {
            file_id,
            version_id,
        })
    }

    pub async fn get_files_for_user(&self, passkey_id: &str) -> Result<Vec<FileInfo>> {
        use sea_orm::{JoinType, QuerySelect, RelationTrait};

        // Use a more efficient query that joins files with version counts
        let files_with_counts = file::Entity::find()
            .filter(file::Column::PasskeyId.eq(passkey_id))
            .join(JoinType::LeftJoin, file::Relation::Versions.def())
            .column_as(file_version::Column::Id.count(), "version_count")
            .group_by(file::Column::Id)
            .group_by(file::Column::Filename)
            .group_by(file::Column::Tags)
            .group_by(file::Column::CreatedAt)
            .group_by(file::Column::UpdatedAt)
            .into_model::<FileWithCount>()
            .all(&self.db)
            .await?;

        let file_infos = files_with_counts
            .into_iter()
            .map(|f| FileInfo {
                id: f.id,
                filename: f.filename,
                tags: f.tags,
                version_count: f.version_count,
                created_at: f.created_at,
                updated_at: f.updated_at,
            })
            .collect();

        Ok(file_infos)
    }

    pub async fn get_file_content(
        &self,
        file_id: Uuid,
        version_id: Option<Uuid>,
        passkey_id: &str,
    ) -> Result<GetFileContentResponse> {
        // Get the file to verify ownership
        let file = file::Entity::find_by_id(file_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("File not found"))?;

        // Verify the user owns this file via passkey_id
        if file.passkey_id != passkey_id {
            return Err(anyhow::anyhow!("Access denied"));
        }

        // Get the version (latest if not specified)
        let version = if let Some(vid) = version_id {
            file_version::Entity::find_by_id(vid)
                .one(&self.db)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Version not found"))?
        } else {
            // Get the latest version
            file_version::Entity::find()
                .filter(file_version::Column::FileId.eq(file_id))
                .order_by_desc(file_version::Column::VersionNumber)
                .one(&self.db)
                .await?
                .ok_or_else(|| anyhow::anyhow!("No versions found"))?
        };

        // Decrypt the content using common utility
        let content = crate::crypto::decrypt_with_materials(
            &version.encrypted_content,
            passkey_id,
            &version.salt,
            &version.nonce,
        )
        .map_err(|_| anyhow::anyhow!("Invalid UTF-8 content"))?;

        Ok(GetFileContentResponse {
            content,
            version_id: version.id,
            version_number: version.version_number,
        })
    }

    pub async fn save_file_version(
        &self,
        file_id: Uuid,
        content: &str,
        change_summary: Option<&str>,
        passkey_id: &str,
    ) -> Result<SaveVersionResponse> {
        // Get the file to verify ownership
        let file = file::Entity::find_by_id(file_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("File not found"))?;

        // Verify the user owns this file via passkey_id
        if file.passkey_id != passkey_id {
            return Err(anyhow::anyhow!("Access denied"));
        }

        // Get the current highest version number
        let current_max_version = file_version::Entity::find()
            .filter(file_version::Column::FileId.eq(file_id))
            .order_by_desc(file_version::Column::VersionNumber)
            .one(&self.db)
            .await?
            .map(|v| v.version_number)
            .unwrap_or(0);

        let new_version_number = current_max_version + 1;

        // Generate encryption materials
        let (salt, nonce_bytes) = crate::crypto::generate_encryption_materials()?;

        // Encrypt content using common utility
        let encrypted_content =
            crate::crypto::encrypt_with_materials(content, passkey_id, &salt, &nonce_bytes)?;

        // Generate content hash for change detection using SHA-256
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        // Create new version
        let version_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        let file_version_record = file_version::ActiveModel {
            id: Set(version_id),
            file_id: Set(file_id),
            user_id: Set(file.user_id),
            version_number: Set(new_version_number),
            encrypted_content: Set(encrypted_content),
            nonce: Set(nonce_bytes.to_vec()),
            salt: Set(salt.to_vec()),
            content_hash: Set(content_hash),
            change_summary: Set(change_summary.map(|s| s.to_string())),
            created_at: Set(now),
        };

        // Insert the new version
        file_version_record.insert(&self.db).await?;

        // Update the file's current_version_id and updated_at
        let mut file_update: file::ActiveModel = file.into();
        file_update.current_version_id = Set(Some(version_id));
        file_update.updated_at = Set(now);
        file_update.update(&self.db).await?;

        Ok(SaveVersionResponse {
            version_id,
            version_number: new_version_number,
        })
    }

    // Secure file operations using WebAuthn signature-based encryption
    pub async fn create_file_secure(
        &self,
        req: &CreateFileRequest,
        user_id: Uuid,
        passkey_id: &str,
        encrypted_content: Vec<u8>,
        nonce: Vec<u8>,
        salt: Vec<u8>,
    ) -> Result<CreateFileResponse> {
        let now = chrono::Utc::now().timestamp();
        let file_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();

        // Compute content hash for change detection (on encrypted content)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&encrypted_content);
        let content_hash = format!("{:x}", hasher.finalize());

        // Create file record
        let file = file::ActiveModel {
            id: Set(file_id),
            user_id: Set(user_id),
            passkey_id: Set(passkey_id.to_string()),
            filename: Set(req.filename.clone()),
            tags: Set(req.tags.clone()),
            current_version_id: Set(Some(version_id)),
            created_at: Set(now),
            updated_at: Set(now),
        };
        file::Entity::insert(file).exec(&self.db).await?;

        // Create initial version with secure encryption
        let version = file_version::ActiveModel {
            id: Set(version_id),
            file_id: Set(file_id),
            user_id: Set(user_id),
            version_number: Set(1),
            encrypted_content: Set(encrypted_content),
            nonce: Set(nonce),
            salt: Set(salt),
            content_hash: Set(content_hash),
            change_summary: Set(Some("Initial version".to_string())),
            created_at: Set(now),
        };
        file_version::Entity::insert(version).exec(&self.db).await?;

        Ok(CreateFileResponse {
            file_id,
            version_id,
        })
    }

    pub async fn get_file_content_secure(
        &self,
        file_id: Uuid,
        version_id: Option<Uuid>,
        passkey_id: &str,
        webauthn_signature: &[u8],
        _challenge: &crate::challenge::Challenge,
    ) -> Result<String> {
        println!("🔍 get_file_content_secure called for file_id: {}", file_id);
        println!("📋 passkey_id: {}", passkey_id);
        println!("🔢 signature length: {}", webauthn_signature.len());

        // Get the file to verify ownership
        println!("📁 Looking up file in database...");
        let file = file::Entity::find_by_id(file_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("File not found"))?;

        println!(
            "✅ Found file: {} (owner: {})",
            file.filename, file.passkey_id
        );

        // Verify ownership
        if file.passkey_id != passkey_id {
            println!(
                "❌ Access denied - passkey mismatch. File owner: {}, Request passkey: {}",
                file.passkey_id, passkey_id
            );
            return Err(anyhow::anyhow!("Access denied"));
        }
        println!("✅ Ownership verified");

        // Get the requested version or latest
        println!("📝 Looking up file version...");
        let version = if let Some(vid) = version_id {
            println!("🔍 Looking for specific version: {}", vid);
            file_version::Entity::find_by_id(vid)
                .filter(file_version::Column::FileId.eq(file_id))
                .one(&self.db)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Version not found"))?
        } else {
            println!("🔍 Looking for latest version");
            file_version::Entity::find()
                .filter(file_version::Column::FileId.eq(file_id))
                .order_by_desc(file_version::Column::VersionNumber)
                .one(&self.db)
                .await?
                .ok_or_else(|| anyhow::anyhow!("No versions found"))?
        };

        println!(
            "✅ Found version {} with encrypted content length: {}",
            version.version_number,
            version.encrypted_content.len()
        );

        // Decrypt content using passkey-based key derivation (temporary workaround)
        // TODO: Implement proper key management for WebAuthn signature-based encryption
        println!("🔓 Starting decryption...");
        println!(
            "🔐 Salt length: {}, Nonce length: {}",
            version.salt.len(),
            version.nonce.len()
        );
        let decrypted_content = crate::crypto::decrypt_with_materials(
            &version.encrypted_content,
            passkey_id,
            &version.salt,
            &version.nonce,
        )
        .map_err(|e| {
            println!("❌ Decryption failed: {}", e);
            e
        })?;

        println!(
            "✅ Decryption successful, content length: {}",
            decrypted_content.len()
        );

        Ok(decrypted_content)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn save_file_version_secure(
        &self,
        file_id: Uuid,
        content: &str,
        change_summary: Option<&str>,
        passkey_id: &str,
        encrypted_content: Vec<u8>,
        nonce: Vec<u8>,
        salt: Vec<u8>,
    ) -> Result<SaveVersionResponse> {
        println!(
            "💾 save_file_version_secure called for file_id: {}",
            file_id
        );
        println!("📋 passkey_id: {}", passkey_id);
        println!(
            "📝 content length: {}, encrypted length: {}",
            content.len(),
            encrypted_content.len()
        );

        // Get and verify file ownership
        println!("📁 Looking up file for ownership verification...");
        let file = file::Entity::find_by_id(file_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("File not found"))?;

        println!(
            "✅ Found file: {} (owner: {})",
            file.filename, file.passkey_id
        );

        if file.passkey_id != passkey_id {
            println!(
                "❌ Access denied - passkey mismatch for save. File owner: {}, Request passkey: {}",
                file.passkey_id, passkey_id
            );
            return Err(anyhow::anyhow!("Access denied"));
        }
        println!("✅ Save ownership verified");

        // Compute content hash for change detection (on decrypted content)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        let version_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        // Use a transaction to ensure atomicity
        println!("🔄 Starting database transaction for save...");
        let txn = TransactionTrait::begin(&self.db).await?;

        // Get the current highest version number INSIDE the transaction to prevent race conditions
        println!("📊 Looking up current max version number within transaction...");
        let current_max_version = file_version::Entity::find()
            .filter(file_version::Column::FileId.eq(file_id))
            .order_by_desc(file_version::Column::VersionNumber)
            .one(&txn)
            .await?
            .map(|v| v.version_number)
            .unwrap_or(0);

        let new_version_number = current_max_version + 1;
        println!("🔢 Calculated new version number: {}", new_version_number);

        // Create new version with secure encryption
        let version = file_version::ActiveModel {
            id: Set(version_id),
            file_id: Set(file_id),
            user_id: Set(file.user_id),
            version_number: Set(new_version_number),
            encrypted_content: Set(encrypted_content),
            nonce: Set(nonce),
            salt: Set(salt),
            content_hash: Set(content_hash),
            change_summary: Set(change_summary.map(|s| s.to_string())),
            created_at: Set(now),
        };

        println!("💾 Inserting new file version...");
        let insert_result = file_version::Entity::insert(version).exec(&txn).await;
        match &insert_result {
            Ok(_) => println!("✅ Version insert successful"),
            Err(e) => println!("❌ Version insert failed: {}", e),
        }
        insert_result?;

        // Update file's current_version_id and updated_at
        println!("📝 Updating file record...");
        let mut file_update: file::ActiveModel = file.into();
        file_update.current_version_id = Set(Some(version_id));
        file_update.updated_at = Set(now);
        let update_result = file_update.update(&txn).await;
        match &update_result {
            Ok(_) => println!("✅ File update successful"),
            Err(e) => println!("❌ File update failed: {}", e),
        }
        update_result?;

        // Commit the transaction
        println!("✅ Committing transaction...");
        let commit_result = txn.commit().await;
        match &commit_result {
            Ok(_) => println!("✅ Transaction commit successful"),
            Err(e) => println!("❌ Transaction commit failed: {}", e),
        }
        commit_result?;

        println!("🎉 Save completed successfully!");

        Ok(SaveVersionResponse {
            version_id,
            version_number: new_version_number,
        })
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
        Err(anyhow::anyhow!(
            "Legacy method - use file operations instead"
        ))
    }

    pub async fn delete_encrypted_data(&self, _data_id: &str) -> Result<()> {
        // Legacy compatibility - this will become delete_file
        Ok(())
    }
}
