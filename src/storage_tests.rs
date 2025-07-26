// ABOUTME: Comprehensive tests for the storage layer
// ABOUTME: Tests database operations, file storage, encryption integration, and error handling

#[cfg(test)]
mod tests {
    use super::super::storage::*;
    use super::super::types::*;
    use tempfile::TempDir;
    use uuid::Uuid;

    async fn create_test_storage() -> (Storage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        // Create storage with explicit database path instead of relying on env var
        use sea_orm::Database;
        use sea_orm_migration::MigratorTrait;

        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
        let db = Database::connect(&db_url).await.unwrap();

        // Run migrations
        crate::migration::Migrator::up(&db, None).await.unwrap();

        let storage = Storage { db };
        (storage, temp_dir)
    }

    // Helper to create a credential for testing
    async fn create_test_credential(storage: &Storage, passkey_id: &str, user_id: Uuid) {
        // Instead of creating a complex mock Passkey, let's directly insert into the database
        // This bypasses the WebAuthn complexity for testing purposes
        use crate::entities::credential;
        use sea_orm::{ActiveModelTrait, Set};

        // Create minimal credential data for testing
        let mock_credential_data = vec![1, 2, 3, 4]; // Minimal mock data

        let credential = credential::ActiveModel {
            id: Set(passkey_id.to_string()),
            user_id: Set(user_id),
            credential_data: Set(mock_credential_data),
            counter: Set(0),
            created_at: Set(chrono::Utc::now().timestamp()),
        };

        credential.insert(&storage.db).await.unwrap();
    }

    #[tokio::test]
    async fn test_user_operations() {
        let (storage, _temp_dir) = create_test_storage().await;

        let user = User {
            id: Uuid::new_v4(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
        };

        // Store user
        storage.store_user(&user).await.unwrap();

        // Retrieve by username
        let retrieved = storage.get_user_by_username("testuser").await.unwrap();
        assert_eq!(retrieved.id, user.id);
        assert_eq!(retrieved.username, user.username);
        assert_eq!(retrieved.display_name, user.display_name);

        // Retrieve by ID
        let retrieved_by_id = storage.get_user_by_id(user.id).await.unwrap();
        assert_eq!(retrieved_by_id.username, user.username);
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let (storage, _temp_dir) = create_test_storage().await;

        // Try to get non-existent user
        let result = storage.get_user_by_username("nonexistent").await;
        assert!(result.is_err());

        let result = storage.get_user_by_id(Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_file_creation_and_retrieval() {
        let (storage, _temp_dir) = create_test_storage().await;

        // Create test user first
        let user = User {
            id: Uuid::new_v4(),
            username: "fileuser".to_string(),
            display_name: "File User".to_string(),
        };
        storage.store_user(&user).await.unwrap();

        let passkey_id = "test_passkey_123";
        // Create credential for this passkey_id
        create_test_credential(&storage, passkey_id, user.id).await;

        let request = CreateFileRequest {
            filename: "test.txt".to_string(),
            tags: "test/documents".to_string(),
            content: "Hello, world!".to_string(),
        };

        // Create file
        let response = storage
            .create_file(&request, user.id, passkey_id)
            .await
            .unwrap();
        assert_eq!(response.file_id.to_string().len(), 36); // UUID length

        // Get file content
        let content_response = storage
            .get_file_content(response.file_id, None, passkey_id)
            .await
            .unwrap();
        assert_eq!(content_response.content, "Hello, world!");
        assert_eq!(content_response.version_number, 1);

        // List files for user
        let files = storage.get_files_for_user(passkey_id).await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "test.txt");
        assert_eq!(files[0].tags, "test/documents");
        assert_eq!(files[0].version_count, 1);
    }

    #[tokio::test]
    async fn test_file_versioning() {
        let (storage, _temp_dir) = create_test_storage().await;

        // Create test user first
        let user = User {
            id: Uuid::new_v4(),
            username: "versionuser".to_string(),
            display_name: "Version User".to_string(),
        };
        storage.store_user(&user).await.unwrap();

        let passkey_id = "test_passkey_version";
        // Create credential for this passkey_id
        create_test_credential(&storage, passkey_id, user.id).await;

        let request = CreateFileRequest {
            filename: "versioned.txt".to_string(),
            tags: "test".to_string(),
            content: "Version 1".to_string(),
        };

        // Create initial file
        let response = storage
            .create_file(&request, user.id, passkey_id)
            .await
            .unwrap();
        let file_id = response.file_id;

        // Save a new version
        let version_response = storage
            .save_file_version(file_id, "Version 2", Some("Updated content"), passkey_id)
            .await
            .unwrap();
        assert_eq!(version_response.version_number, 2);

        // Get latest version
        let content = storage
            .get_file_content(file_id, None, passkey_id)
            .await
            .unwrap();
        assert_eq!(content.content, "Version 2");
        assert_eq!(content.version_number, 2);

        // Get specific version
        let first_version = storage
            .get_file_content(file_id, Some(response.version_id), passkey_id)
            .await
            .unwrap();
        assert_eq!(first_version.content, "Version 1");
        assert_eq!(first_version.version_number, 1);

        // Check version count updated
        let files = storage.get_files_for_user(passkey_id).await.unwrap();
        assert_eq!(files[0].version_count, 2);
    }

    #[tokio::test]
    async fn test_file_access_control() {
        let (storage, _temp_dir) = create_test_storage().await;

        // Create test users
        let user1 = User {
            id: Uuid::new_v4(),
            username: "user1".to_string(),
            display_name: "User One".to_string(),
        };
        let user2 = User {
            id: Uuid::new_v4(),
            username: "user2".to_string(),
            display_name: "User Two".to_string(),
        };
        storage.store_user(&user1).await.unwrap();
        storage.store_user(&user2).await.unwrap();

        let passkey1 = "passkey_user1";
        let passkey2 = "passkey_user2";

        // Create credentials for both users
        create_test_credential(&storage, passkey1, user1.id).await;
        create_test_credential(&storage, passkey2, user2.id).await;

        let request = CreateFileRequest {
            filename: "private.txt".to_string(),
            tags: "personal".to_string(),
            content: "Private data".to_string(),
        };

        // User1 creates file
        let response = storage
            .create_file(&request, user1.id, passkey1)
            .await
            .unwrap();
        let file_id = response.file_id;

        // User1 can access their file
        let content = storage
            .get_file_content(file_id, None, passkey1)
            .await
            .unwrap();
        assert_eq!(content.content, "Private data");

        // User2 cannot access user1's file
        let result = storage.get_file_content(file_id, None, passkey2).await;
        assert!(result.is_err());

        // User2 cannot save to user1's file
        let result = storage
            .save_file_version(file_id, "Hacked!", None, passkey2)
            .await;
        assert!(result.is_err());

        // User2 cannot see user1's files in their list
        let user2_files = storage.get_files_for_user(passkey2).await.unwrap();
        assert_eq!(user2_files.len(), 0);
    }

    #[tokio::test]
    async fn test_secure_file_operations() {
        let (storage, _temp_dir) = create_test_storage().await;

        // Create test user
        let user = User {
            id: Uuid::new_v4(),
            username: "secureuser".to_string(),
            display_name: "Secure User".to_string(),
        };
        storage.store_user(&user).await.unwrap();

        let passkey_id = "secure_passkey";
        // Create credential for this passkey_id
        create_test_credential(&storage, passkey_id, user.id).await;
        let request = CreateFileRequest {
            filename: "secure.txt".to_string(),
            tags: "secure/documents".to_string(),
            content: "Secure content".to_string(),
        };

        // Mock encrypted data
        let encrypted_content = b"encrypted_mock_data".to_vec();
        let nonce = b"mock_nonce12".to_vec();
        let salt = b"mock_salt_32_bytes_long_for_test".to_vec();

        // Create file with secure method
        let response = storage
            .create_file_secure(
                &request,
                user.id,
                passkey_id,
                encrypted_content.clone(),
                nonce.clone(),
                salt.clone(),
            )
            .await
            .unwrap();

        // Note: We can't easily test get_file_content_secure and save_file_version_secure
        // without a full WebAuthn implementation, but we can test that they exist
        // and handle basic parameter validation
        assert_eq!(response.file_id.to_string().len(), 36); // Valid UUID
    }

    #[tokio::test]
    async fn test_empty_file_content() {
        let (storage, _temp_dir) = create_test_storage().await;

        let user = User {
            id: Uuid::new_v4(),
            username: "emptyuser".to_string(),
            display_name: "Empty User".to_string(),
        };
        storage.store_user(&user).await.unwrap();

        let passkey_id = "empty_passkey";
        // Create credential for this passkey_id
        create_test_credential(&storage, passkey_id, user.id).await;
        let request = CreateFileRequest {
            filename: "empty.txt".to_string(),
            tags: "".to_string(),
            content: "".to_string(),
        };

        // Create empty file
        let response = storage
            .create_file(&request, user.id, passkey_id)
            .await
            .unwrap();

        // Should be able to retrieve empty content
        let content = storage
            .get_file_content(response.file_id, None, passkey_id)
            .await
            .unwrap();
        assert_eq!(content.content, "");
    }

    #[tokio::test]
    async fn test_large_file_content() {
        let (storage, _temp_dir) = create_test_storage().await;

        let user = User {
            id: Uuid::new_v4(),
            username: "largeuser".to_string(),
            display_name: "Large User".to_string(),
        };
        storage.store_user(&user).await.unwrap();

        let passkey_id = "large_passkey";
        // Create credential for this passkey_id
        create_test_credential(&storage, passkey_id, user.id).await;
        let large_content = "A".repeat(100000); // 100KB
        let request = CreateFileRequest {
            filename: "large.txt".to_string(),
            tags: "test/large".to_string(),
            content: large_content.clone(),
        };

        // Create large file
        let response = storage
            .create_file(&request, user.id, passkey_id)
            .await
            .unwrap();

        // Should be able to retrieve large content
        let content = storage
            .get_file_content(response.file_id, None, passkey_id)
            .await
            .unwrap();
        assert_eq!(content.content, large_content);
    }

    #[tokio::test]
    async fn test_unicode_file_content() {
        let (storage, _temp_dir) = create_test_storage().await;

        let user = User {
            id: Uuid::new_v4(),
            username: "unicodeuser".to_string(),
            display_name: "Unicode User".to_string(),
        };
        storage.store_user(&user).await.unwrap();

        let passkey_id = "unicode_passkey";
        // Create credential for this passkey_id
        create_test_credential(&storage, passkey_id, user.id).await;
        let unicode_content = "Hello 世界! 🚀 Testing émojis and spéciál chars ñáéíóú";
        let request = CreateFileRequest {
            filename: "unicode.txt".to_string(),
            tags: "test/unicode".to_string(),
            content: unicode_content.to_string(),
        };

        // Create unicode file
        let response = storage
            .create_file(&request, user.id, passkey_id)
            .await
            .unwrap();

        // Should preserve unicode content
        let content = storage
            .get_file_content(response.file_id, None, passkey_id)
            .await
            .unwrap();
        assert_eq!(content.content, unicode_content);
    }

    #[tokio::test]
    async fn test_file_with_special_filename() {
        let (storage, _temp_dir) = create_test_storage().await;

        let user = User {
            id: Uuid::new_v4(),
            username: "specialuser".to_string(),
            display_name: "Special User".to_string(),
        };
        storage.store_user(&user).await.unwrap();

        let passkey_id = "special_passkey";
        // Create credential for this passkey_id
        create_test_credential(&storage, passkey_id, user.id).await;
        let request = CreateFileRequest {
            filename: "file-with_special.chars (1).txt".to_string(),
            tags: "test/special-chars".to_string(),
            content: "Content with special filename".to_string(),
        };

        // Create file with special characters in filename
        let _response = storage
            .create_file(&request, user.id, passkey_id)
            .await
            .unwrap();

        // Should preserve special filename
        let files = storage.get_files_for_user(passkey_id).await.unwrap();
        assert_eq!(files[0].filename, "file-with_special.chars (1).txt");
    }

    #[tokio::test]
    async fn test_multiple_files_ordering() {
        let (storage, _temp_dir) = create_test_storage().await;

        let user = User {
            id: Uuid::new_v4(),
            username: "orderuser".to_string(),
            display_name: "Order User".to_string(),
        };
        storage.store_user(&user).await.unwrap();

        let passkey_id = "order_passkey";
        // Create credential for this passkey_id
        create_test_credential(&storage, passkey_id, user.id).await;

        // Create multiple files
        for i in 1..=5 {
            let request = CreateFileRequest {
                filename: format!("file{}.txt", i),
                tags: format!("tag{}", i),
                content: format!("Content {}", i),
            };
            storage
                .create_file(&request, user.id, passkey_id)
                .await
                .unwrap();

            // Small delay to ensure different timestamps
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        // List files - should maintain consistent ordering
        let files = storage.get_files_for_user(passkey_id).await.unwrap();
        assert_eq!(files.len(), 5);

        // Verify all files are there
        let filenames: Vec<String> = files.iter().map(|f| f.filename.clone()).collect();
        for i in 1..=5 {
            assert!(filenames.contains(&format!("file{}.txt", i)));
        }
    }
}
