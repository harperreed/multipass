// ABOUTME: Challenge generation and management for WebAuthn signature-based key derivation
// ABOUTME: Provides secure challenge-response system for cryptographic operations

use anyhow::{Result, anyhow};
use rand::{RngCore, rngs::OsRng};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const CHALLENGE_SIZE: usize = 32; // 256 bits for strong security
const CHALLENGE_LIFETIME: u64 = 300; // 5 minutes in seconds

#[derive(Debug, Clone)]
pub struct Challenge {
    pub id: String,
    pub challenge_bytes: [u8; CHALLENGE_SIZE],
    pub created_at: u64,
    pub expires_at: u64,
    pub user_id: Uuid,
    pub operation_type: ChallengeType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeType {
    FileCreate,
    FileRead,
    FileWrite,
    FileDelete,
    GeneralCrypto,
}

impl Challenge {
    pub fn new(user_id: Uuid, operation_type: ChallengeType) -> Result<Self> {
        let mut challenge_bytes = [0u8; CHALLENGE_SIZE];
        OsRng.fill_bytes(&mut challenge_bytes);

        // Basic entropy check
        if challenge_bytes.iter().all(|&b| b == challenge_bytes[0]) {
            return Err(anyhow!("Insufficient entropy in challenge generation"));
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        Ok(Challenge {
            id: Uuid::new_v4().to_string(),
            challenge_bytes,
            created_at: now,
            expires_at: now + CHALLENGE_LIFETIME,
            user_id,
            operation_type,
        })
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }
}

#[derive(Clone)]
pub struct ChallengeManager {
    challenges: Arc<RwLock<HashMap<String, Challenge>>>,
}

impl Default for ChallengeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeManager {
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new challenge for a cryptographic operation
    pub fn create_challenge(
        &self,
        user_id: Uuid,
        operation_type: ChallengeType,
    ) -> Result<Challenge> {
        let challenge = Challenge::new(user_id, operation_type)?;

        // Store the challenge
        if let Ok(mut challenges) = self.challenges.write() {
            challenges.insert(challenge.id.clone(), challenge.clone());

            // Clean up expired challenges while we have the lock
            challenges.retain(|_, c| !c.is_expired());
        }

        Ok(challenge)
    }

    /// Verify and consume a challenge (single-use)
    pub fn verify_and_consume_challenge(
        &self,
        challenge_id: &str,
        user_id: Uuid,
        operation_type: ChallengeType,
    ) -> Result<Challenge> {
        if let Ok(mut challenges) = self.challenges.write() {
            // Remove the challenge (single-use)
            let challenge = challenges
                .remove(challenge_id)
                .ok_or_else(|| anyhow!("Challenge not found"))?;

            // Verify challenge hasn't expired
            if challenge.is_expired() {
                return Err(anyhow!("Challenge has expired"));
            }

            // Verify challenge belongs to the requesting user
            if challenge.user_id != user_id {
                return Err(anyhow!("Challenge does not belong to user"));
            }

            // Verify challenge is for the correct operation type
            if challenge.operation_type != operation_type {
                return Err(anyhow!("Challenge is for wrong operation type"));
            }

            // Clean up expired challenges while we have the lock
            challenges.retain(|_, c| !c.is_expired());

            Ok(challenge)
        } else {
            Err(anyhow!("Failed to acquire challenge lock"))
        }
    }

    /// Get challenge info without consuming it (for verification)
    pub fn get_challenge(&self, challenge_id: &str) -> Result<Challenge> {
        if let Ok(challenges) = self.challenges.read() {
            let challenge = challenges
                .get(challenge_id)
                .ok_or_else(|| anyhow!("Challenge not found"))?
                .clone();

            if challenge.is_expired() {
                return Err(anyhow!("Challenge has expired"));
            }

            Ok(challenge)
        } else {
            Err(anyhow!("Failed to acquire challenge lock"))
        }
    }

    /// Clean up expired challenges (can be called periodically)
    pub fn cleanup_expired(&self) {
        if let Ok(mut challenges) = self.challenges.write() {
            challenges.retain(|_, c| !c.is_expired());
        }
    }

    /// Get statistics about active challenges
    pub fn get_stats(&self) -> (usize, usize) {
        if let Ok(challenges) = self.challenges.read() {
            let total = challenges.len();
            let expired = challenges.values().filter(|c| c.is_expired()).count();
            (total, expired)
        } else {
            (0, 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_challenge_creation() {
        let manager = ChallengeManager::new();
        let user_id = Uuid::new_v4();

        let challenge = manager
            .create_challenge(user_id, ChallengeType::FileRead)
            .unwrap();

        assert_eq!(challenge.user_id, user_id);
        assert_eq!(challenge.operation_type, ChallengeType::FileRead);
        assert!(!challenge.is_expired());
        assert_eq!(challenge.challenge_bytes.len(), CHALLENGE_SIZE);
    }

    #[test]
    fn test_challenge_verification() {
        let manager = ChallengeManager::new();
        let user_id = Uuid::new_v4();

        let challenge = manager
            .create_challenge(user_id, ChallengeType::FileWrite)
            .unwrap();
        let challenge_id = challenge.id.clone();

        // Should be able to verify and consume
        let verified = manager
            .verify_and_consume_challenge(&challenge_id, user_id, ChallengeType::FileWrite)
            .unwrap();

        assert_eq!(verified.id, challenge_id);

        // Should not be able to use the same challenge again
        assert!(
            manager
                .verify_and_consume_challenge(&challenge_id, user_id, ChallengeType::FileWrite)
                .is_err()
        );
    }

    #[test]
    fn test_challenge_user_mismatch() {
        let manager = ChallengeManager::new();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        let challenge = manager
            .create_challenge(user1, ChallengeType::FileRead)
            .unwrap();

        // Should fail with wrong user
        assert!(
            manager
                .verify_and_consume_challenge(&challenge.id, user2, ChallengeType::FileRead)
                .is_err()
        );
    }

    #[test]
    fn test_challenge_operation_mismatch() {
        let manager = ChallengeManager::new();
        let user_id = Uuid::new_v4();

        let challenge = manager
            .create_challenge(user_id, ChallengeType::FileRead)
            .unwrap();

        // Should fail with wrong operation type
        assert!(
            manager
                .verify_and_consume_challenge(&challenge.id, user_id, ChallengeType::FileWrite)
                .is_err()
        );
    }
}
