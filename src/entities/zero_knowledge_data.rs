// ABOUTME: Zero-knowledge data entity for storing encrypted blobs that server cannot decrypt
// ABOUTME: Links to users and credentials for access control while maintaining true zero-knowledge

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "zero_knowledge_data")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub user_id: Uuid,
    pub passkey_id: String,
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::credential::Entity",
        from = "Column::PasskeyId",
        to = "super::credential::Column::Id"
    )]
    Credential,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
