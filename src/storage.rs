// ABOUTME: SQLite database storage layer for users, credentials, and encrypted data
// ABOUTME: Handles all database operations including schema creation and data persistence

use anyhow::Result;
use sqlx::{sqlite::SqlitePool, Row};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::types::*;

pub struct Storage {
    pub pool: SqlitePool,
}

impl Storage {
    pub async fn new() -> Result<Self> {
        // Create database file if it doesn't exist
        let pool = SqlitePool::connect("sqlite:multipass.db?mode=rwc").await?;
        
        let storage = Self { pool };
        storage.initialize_schema().await?;
        
        Ok(storage)
    }

    async fn initialize_schema(&self) -> Result<()> {
        // Users table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Credentials table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                credential_data BLOB NOT NULL,
                counter INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Encrypted data table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS encrypted_data (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                passkey_id TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT 'Untitled Secret',
                encrypted_content BLOB NOT NULL,
                nonce BLOB NOT NULL,
                salt BLOB NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (passkey_id) REFERENCES credentials (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn store_user(&self, user: &User) -> Result<()> {
        sqlx::query(
            "INSERT INTO users (id, username, display_name) VALUES (?, ?, ?)"
        )
        .bind(user.id.to_string())
        .bind(&user.username)
        .bind(&user.display_name)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User> {
        let row = sqlx::query("SELECT id, username, display_name FROM users WHERE username = ?")
            .bind(username)
            .fetch_one(&self.pool)
            .await?;

        Ok(User {
            id: Uuid::parse_str(row.get("id"))?,
            username: row.get("username"),
            display_name: row.get("display_name"),
        })
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<User> {
        let row = sqlx::query("SELECT id, username, display_name FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .fetch_one(&self.pool)
            .await?;

        Ok(User {
            id: Uuid::parse_str(row.get("id"))?,
            username: row.get("username"),
            display_name: row.get("display_name"),
        })
    }

    pub async fn store_credential(&self, credential_id: &str, user_id: Uuid, passkey: &Passkey) -> Result<()> {
        let credential_data = bincode::serialize(passkey)?;
        
        sqlx::query(
            "INSERT INTO credentials (id, user_id, credential_data, counter) VALUES (?, ?, ?, ?)"
        )
        .bind(credential_id)
        .bind(user_id.to_string())
        .bind(credential_data)
        .bind(0i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_credential(&self, credential_id: &str) -> Result<StoredCredential> {
        let row = sqlx::query("SELECT id, user_id, credential_data, counter FROM credentials WHERE id = ?")
            .bind(credential_id)
            .fetch_one(&self.pool)
            .await?;

        Ok(StoredCredential {
            id: row.get("id"),
            user_id: Uuid::parse_str(row.get("user_id"))?,
            credential_data: row.get("credential_data"),
            counter: row.get::<i64, _>("counter") as u32,
        })
    }

    pub async fn get_user_credentials(&self, user_id: Uuid) -> Result<Vec<StoredCredential>> {
        let rows = sqlx::query("SELECT id, user_id, credential_data, counter FROM credentials WHERE user_id = ?")
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        let mut credentials = Vec::new();
        for row in rows {
            credentials.push(StoredCredential {
                id: row.get("id"),
                user_id: Uuid::parse_str(row.get("user_id"))?,
                credential_data: row.get("credential_data"),
                counter: row.get::<i64, _>("counter") as u32,
            });
        }

        Ok(credentials)
    }

    pub async fn update_credential_counter(&self, credential_id: &str, counter: u32) -> Result<()> {
        sqlx::query("UPDATE credentials SET counter = ? WHERE id = ?")
            .bind(counter as i64)
            .bind(credential_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn store_encrypted_data(&self, data: &EncryptedData) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO encrypted_data (id, user_id, passkey_id, title, encrypted_content, nonce, salt, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(data.id.to_string())
        .bind(data.user_id.to_string())
        .bind(&data.passkey_id)
        .bind(&data.title)
        .bind(&data.encrypted_content)
        .bind(&data.nonce)
        .bind(&data.salt)
        .bind(data.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_encrypted_data(&self, passkey_id: &str) -> Result<Vec<EncryptedData>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, passkey_id, title, encrypted_content, nonce, salt, created_at 
            FROM encrypted_data WHERE passkey_id = ?
            "#
        )
        .bind(passkey_id)
        .fetch_all(&self.pool)
        .await?;

        let mut data = Vec::new();
        for row in rows {
            data.push(EncryptedData {
                id: Uuid::parse_str(row.get("id"))?,
                user_id: Uuid::parse_str(row.get("user_id"))?,
                passkey_id: row.get("passkey_id"),
                title: row.get("title"),
                encrypted_content: row.get("encrypted_content"),
                nonce: row.get("nonce"),
                salt: row.get("salt"),
                created_at: row.get("created_at"),
            });
        }

        Ok(data)
    }

    pub async fn get_encrypted_data_by_id(&self, data_id: &str) -> Result<EncryptedData> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, passkey_id, title, encrypted_content, nonce, salt, created_at 
            FROM encrypted_data WHERE id = ?
            "#
        )
        .bind(data_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(EncryptedData {
            id: Uuid::parse_str(row.get("id"))?,
            user_id: Uuid::parse_str(row.get("user_id"))?,
            passkey_id: row.get("passkey_id"),
            title: row.get("title"),
            encrypted_content: row.get("encrypted_content"),
            nonce: row.get("nonce"),
            salt: row.get("salt"),
            created_at: row.get("created_at"),
        })
    }

    pub async fn delete_encrypted_data(&self, data_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM encrypted_data WHERE id = ?")
            .bind(data_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}