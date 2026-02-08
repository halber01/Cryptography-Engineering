use std::collections::HashMap;
use crate::types::{Username, ServerRecord, OpaqueError};

/// In-memory database for storing user registration data

#[derive(Debug, Default)]
pub struct Database {
    records: HashMap<String, ServerRecord>,
}

impl Database {
    /// Create a new empty database
    pub fn new() -> Self {
        Database {
            records: HashMap::new(),
        }
    }

    /// Store a server record for a user
    ///
    /// Returns error if user already exists
    pub fn store(&mut self, record: ServerRecord) -> Result<(), OpaqueError> {
        let username_key = record.username.0.clone();

        if self.records.contains_key(&username_key) {
            return Err(OpaqueError::UserAlreadyExists(username_key));
        }

        self.records.insert(username_key, record);
        Ok(())
    }

    /// Retrieve a server record by username
    ///
    /// Returns error if user not found
    pub fn get(&self, username: &Username) -> Result<&ServerRecord, OpaqueError> {
        self.records
            .get(&username.0)
            .ok_or_else(|| OpaqueError::UserNotFound(username.0.clone()))
    }

    /// Check if a user exists
    pub fn exists(&self, username: &Username) -> bool {
        self.records.contains_key(&username.0)
    }

    /// Update an existing record
    ///
    /// Returns error if user doesn't exist
    pub fn update(&mut self, record: ServerRecord) -> Result<(), OpaqueError> {
        let username_key = record.username.0.clone();

        if !self.records.contains_key(&username_key) {
            return Err(OpaqueError::UserNotFound(username_key));
        }

        self.records.insert(username_key, record);
        Ok(())
    }

    /// Delete a user's record
    ///
    /// Returns error if user doesn't exist
    pub fn delete(&mut self, username: &Username) -> Result<(), OpaqueError> {
        self.records
            .remove(&username.0)
            .map(|_| ())
            .ok_or_else(|| OpaqueError::UserNotFound(username.0.clone()))
    }

    /// Get number of registered users
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Clear all records
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// List all registered usernames
    pub fn list_users(&self) -> Vec<Username> {
        self.records
            .keys()
            .map(|k| Username(k.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Salt, ServerKeyBundle, EncryptedKeyBundle};

    fn create_dummy_record(username: &str) -> ServerRecord {
        ServerRecord {
            username: Username::from(username),
            salt: Salt(vec![1, 2, 3, 4]),
            server_key_bundle: ServerKeyBundle {
                client_public_key: vec![],
                server_public_key: vec![],
                server_secret_key: vec![],
            },
            client_encrypted_key_bundle: EncryptedKeyBundle {
                ciphertext: vec![],
                nonce: vec![],
            },
        }
    }

    #[test]
    fn test_store_and_retrieve() {
        let mut db = Database::new();
        let record = create_dummy_record("alice");

        db.store(record.clone()).unwrap();

        let retrieved = db.get(&Username::from("alice")).unwrap();
        assert_eq!(retrieved.username, record.username);
    }

    #[test]
    fn test_duplicate_user() {
        let mut db = Database::new();
        let record1 = create_dummy_record("alice");
        let record2 = create_dummy_record("alice");

        db.store(record1).unwrap();

        let result = db.store(record2);
        assert!(matches!(result, Err(OpaqueError::UserAlreadyExists(_))));
    }

    #[test]
    fn test_user_not_found() {
        let db = Database::new();

        let result = db.get(&Username::from("bob"));
        assert!(matches!(result, Err(OpaqueError::UserNotFound(_))));
    }

    #[test]
    fn test_exists() {
        let mut db = Database::new();
        let record = create_dummy_record("alice");

        assert!(!db.exists(&Username::from("alice")));

        db.store(record).unwrap();

        assert!(db.exists(&Username::from("alice")));
    }
}