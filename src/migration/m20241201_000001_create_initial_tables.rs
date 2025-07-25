// ABOUTME: Initial migration to create users, credentials, files, and file_versions tables
// ABOUTME: Sets up the complete schema for the file browser with versioning system

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create users table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Users::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Users::Username).string().not_null().unique_key())
                    .col(ColumnDef::new(Users::DisplayName).string().not_null())
                    .col(ColumnDef::new(Users::CreatedAt).big_integer().not_null().default(Expr::current_timestamp()))
                    .to_owned(),
            )
            .await?;

        // Create credentials table
        manager
            .create_table(
                Table::create()
                    .table(Credentials::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Credentials::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Credentials::UserId).uuid().not_null())
                    .col(ColumnDef::new(Credentials::CredentialData).blob().not_null())
                    .col(ColumnDef::new(Credentials::Counter).big_integer().not_null().default(0))
                    .col(ColumnDef::new(Credentials::CreatedAt).big_integer().not_null().default(Expr::current_timestamp()))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_credentials_user_id")
                            .from(Credentials::Table, Credentials::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create files table
        manager
            .create_table(
                Table::create()
                    .table(Files::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Files::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Files::UserId).uuid().not_null())
                    .col(ColumnDef::new(Files::PasskeyId).string().not_null())
                    .col(ColumnDef::new(Files::Filename).string().not_null())
                    .col(ColumnDef::new(Files::Tags).string().not_null().default(""))
                    .col(ColumnDef::new(Files::CurrentVersionId).uuid())
                    .col(ColumnDef::new(Files::CreatedAt).big_integer().not_null().default(Expr::current_timestamp()))
                    .col(ColumnDef::new(Files::UpdatedAt).big_integer().not_null().default(Expr::current_timestamp()))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_files_user_id")
                            .from(Files::Table, Files::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_files_passkey_id")
                            .from(Files::Table, Files::PasskeyId)
                            .to(Credentials::Table, Credentials::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create file_versions table
        manager
            .create_table(
                Table::create()
                    .table(FileVersions::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(FileVersions::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(FileVersions::FileId).uuid().not_null())
                    .col(ColumnDef::new(FileVersions::UserId).uuid().not_null())
                    .col(ColumnDef::new(FileVersions::VersionNumber).integer().not_null())
                    .col(ColumnDef::new(FileVersions::EncryptedContent).blob().not_null())
                    .col(ColumnDef::new(FileVersions::Nonce).blob().not_null())
                    .col(ColumnDef::new(FileVersions::Salt).blob().not_null())
                    .col(ColumnDef::new(FileVersions::ContentHash).string().not_null())
                    .col(ColumnDef::new(FileVersions::ChangeSummary).string())
                    .col(ColumnDef::new(FileVersions::CreatedAt).big_integer().not_null().default(Expr::current_timestamp()))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_file_versions_file_id")
                            .from(FileVersions::Table, FileVersions::FileId)
                            .to(Files::Table, Files::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_file_versions_user_id")
                            .from(FileVersions::Table, FileVersions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .index(
                        Index::create()
                            .name("idx_file_version_unique")
                            .table(FileVersions::Table)
                            .col(FileVersions::FileId)
                            .col(FileVersions::VersionNumber)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(FileVersions::Table).to_owned())
            .await?;
        
        manager
            .drop_table(Table::drop().table(Files::Table).to_owned())
            .await?;
        
        manager
            .drop_table(Table::drop().table(Credentials::Table).to_owned())
            .await?;
        
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Username,
    DisplayName,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Credentials {
    Table,
    Id,
    UserId,
    CredentialData,
    Counter,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Files {
    Table,
    Id,
    UserId,
    PasskeyId,
    Filename,
    Tags,
    CurrentVersionId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum FileVersions {
    Table,
    Id,
    FileId,
    UserId,
    VersionNumber,
    EncryptedContent,
    Nonce,
    Salt,
    ContentHash,
    ChangeSummary,
    CreatedAt,
}