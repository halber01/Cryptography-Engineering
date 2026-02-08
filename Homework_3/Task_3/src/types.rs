//! Core types used throughout the OPAQUE protocol

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Username type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Username(pub String);

impl From<String> for Username {
    fn from(s: String) -> Self {
        Username(s)
    }
}

impl From<&str> for Username {
    fn from(s: &str) -> Self {
        Username(s.to_string())
    }
}

/// Password type
#[derive(Debug, Clone)]
pub struct Password(pub String);

impl From<String> for Password {
    fn from(s: String) -> Self {
        Password(s)
    }
}

impl From<&str> for Password {
    fn from(s: &str) -> Self {
        Password(s.to_string())
    }
}

/// Session key derived from the protocol
#[derive(Debug, Clone, PartialEq)]
pub struct SessionKey(pub Vec<u8>);

/// Salt for password hashing (stored on server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Salt(pub Vec<u8>);

/// RW value (derived from password + salt via OPRF)
#[derive(Debug, Clone)]
pub struct RwValue(pub Vec<u8>);

/// Encrypted client key bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyBundle {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Server's stored data for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRecord {
    pub username: Username,
    pub salt: Salt,
    pub server_key_bundle: ServerKeyBundle,
    pub client_encrypted_key_bundle: EncryptedKeyBundle,
}

/// Server's key bundle (unencrypted, stored on server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerKeyBundle {
    pub client_public_key: Vec<u8>,  // lpk_c (A)
    pub server_public_key: Vec<u8>,  // lpk_s (B)
    pub server_secret_key: Vec<u8>,  // lsk_s (b)
}

/// Client's key info (encrypted, sent to client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientKeyInfo {
    pub client_public_key: Vec<u8>,  // lpk_c (A)
    pub client_secret_key: Vec<u8>,  // lsk_c (a)
    pub server_public_key: Vec<u8>,  // lpk_s (B)
}

/// Error types for OPAQUE protocol
#[derive(Error, Debug)]
pub enum OpaqueError {
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Hash to curve error")]
    Hash2CurveError,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("User already exists: {0}")]
    UserAlreadyExists(String),

    #[error("Invalid MAC")]
    InvalidMac,

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}