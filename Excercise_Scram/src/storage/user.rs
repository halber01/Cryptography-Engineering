use serde::{Deserialize, Serialize};

/// Represents a user entry in the password file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    /// Username
    pub username: String,

    /// Salt value 'r' (stored as base64)
    pub salt: String,

    /// Iteration count 'n' for hash function
    pub iterations: u32,

    /// H^n(r, pw) - the hashed password (stored as base64)
    pub password_hash: String,
}

impl User {
    pub fn new(username: String, salt: String, iterations: u32, password_hash: String) -> Self {
        Self {
            username,
            salt,
            iterations,
            password_hash,
        }
    }
}