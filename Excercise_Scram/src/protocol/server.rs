use anyhow::{Result, anyhow};
use rand::Rng;
use crate::crypto::scram;
use crate::storage::{PasswordFile, User};
use crate::tls::TlsSession;
use super::messages::{ClientFirst, ServerFirst, ClientFinal, ServerFinal};

/// SCRAM server for authentication
pub struct ScramServer {
    /// Password file for user lookup
    password_file: PasswordFile,

    /// Server challenge (ch₂) - generated when needed
    ch2: Option<Vec<u8>>,

    /// TLS session (must be established before SCRAM)
    tls_session: TlsSession,

    /// Current user being authenticated
    current_user: Option<User>,
}

impl ScramServer {
    /// Create a new SCRAM server
    ///
    /// # Arguments
    /// * `password_file` - Password file for user authentication
    /// * `tls_session` - Established TLS session
    pub fn new(password_file: PasswordFile, tls_session: TlsSession) -> Self {
        Self {
            password_file,
            ch2: None,
            tls_session,
            current_user: None,
        }
    }

    /// Step 1: Process ClientFirst and generate ServerFirst
    ///
    /// # Arguments
    /// * `client_first` - The ClientFirst message from client
    pub fn process_client_first(
        &mut self,
        client_first: &ClientFirst,
    ) -> Result<ServerFirst> {
        // 1. Lookup user in password file
        let user = self.password_file
            .get_user(&client_first.client_name)?
            .ok_or_else(|| anyhow!("User '{}' not found", client_first.client_name))?;

        // 2. Generate server challenge (ch₂)
        let mut rng = rand::thread_rng();
        let ch2: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();

        // 3. Store state for later verification
        self.ch2 = Some(ch2.clone());
        self.current_user = Some(user.clone());

        // 4. Convert salt and iterations from user record
        let salt = base64::decode(&user.salt)
            .map_err(|e| anyhow!("Failed to decode salt: {}", e))?;

        // 5. Create ServerFirst message
        let server_first = ServerFirst::new(
            client_first.ch1.clone(),
            ch2,
            salt,
            user.iterations,
        );

        Ok(server_first)
    }

    /// Step 2: Process ClientFinal and generate ServerFinal
    ///
    /// # Arguments
    /// * `client_final` - The ClientFinal message from client
    /// * `server_first` - The ServerFirst message we sent (needed for Auth_msg)
    pub fn process_client_final(
        &self,
        client_final: &ClientFinal,
        server_first: &ServerFirst,
    ) -> Result<ServerFinal> {
        // 1. Get the user we're authenticating
        let user = self.current_user
            .as_ref()
            .ok_or_else(|| anyhow!("No user authentication in progress"))?;

        // 2. Verify challenges match
        if client_final.ch1 != server_first.ch1 {
            return Err(anyhow!("Client challenge mismatch"));
        }
        if client_final.ch2 != server_first.ch2 {
            return Err(anyhow!("Server challenge mismatch"));
        }

        // 3. Get password hash from user record
        let password_hash_b64 = &user.password_hash;
        let password_hash_bytes = base64::decode(password_hash_b64)
            .map_err(|e| anyhow!("Failed to decode password hash: {}", e))?;

        if password_hash_bytes.len() != 32 {
            return Err(anyhow!("Invalid password hash length"));
        }

        let password_hash: [u8; 32] = password_hash_bytes
            .try_into()
            .map_err(|_| anyhow!("Failed to convert password hash"))?;

        // 4. Compute Auth_msg
        let auth_msg = scram::compute_auth_msg(
            &user.username,
            &client_final.ch1,
            &client_final.ch2,
            &server_first.r,
            server_first.n,
            &client_final.tls_info,
        );

        // 5. Verify Client_proof
        if !scram::verify_client_proof(&password_hash, &auth_msg, &client_final.client_proof) {
            return Err(anyhow!("Client proof verification failed - invalid credentials"));
        }

        // 6. Compute Server_sign
        let server_sign = scram::compute_server_sign(&password_hash, &auth_msg);

        // 7. Create ServerFinal message
        Ok(ServerFinal::new(server_sign))
    }

    /// Get the TLS session
    pub fn tls_session(&self) -> &TlsSession {
        &self.tls_session
    }

    /// Get the currently authenticated user (if any)
    pub fn current_user(&self) -> Option<&User> {
        self.current_user.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{TlsRole, TlsKeys};
    use tempfile::NamedTempFile;
    use std::io::Write;

    fn create_test_tls_session() -> TlsSession {
        TlsSession::new(
            TlsRole::Server,
            TlsKeys {
                k1_c: [1u8; 32],
                k1_s: [2u8; 32],
                k2_c: [3u8; 32],
                k2_s: [4u8; 32],
                k3_c: [5u8; 32],
                k3_s: [6u8; 32],
            },
            [0u8; 32],
            [1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            vec![4u8; 64],
            vec![5u8; 32],
        )
    }

    #[test]
    fn test_server_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let pw_file = PasswordFile::new(temp_file.path());
        pw_file.init().unwrap();

        let tls_session = create_test_tls_session();
        let server = ScramServer::new(pw_file, tls_session);

        assert!(server.ch2.is_none());
        assert!(server.current_user.is_none());
    }

    #[test]
    fn test_process_client_first() {
        // Create password file with a test user
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "# Format: username,salt,iterations,hash").unwrap();
        writeln!(temp_file, "Alice,c2FsdDEyMw==,10000,aGFzaDEyMw==").unwrap();

        let pw_file = PasswordFile::new(temp_file.path());
        let tls_session = create_test_tls_session();
        let mut server = ScramServer::new(pw_file, tls_session);

        let client_first = ClientFirst::new("Alice".to_string(), vec![1, 2, 3]);
        let server_first = server.process_client_first(&client_first).unwrap();

        assert_eq!(server_first.ch1, vec![1, 2, 3]);
        assert_eq!(server_first.ch2.len(), 32);
        assert!(server.ch2.is_some());
        assert!(server.current_user.is_some());
    }

    #[test]
    fn test_process_client_first_user_not_found() {
        let temp_file = NamedTempFile::new().unwrap();
        let pw_file = PasswordFile::new(temp_file.path());
        pw_file.init().unwrap();

        let tls_session = create_test_tls_session();
        let mut server = ScramServer::new(pw_file, tls_session);

        let client_first = ClientFirst::new("NonExistent".to_string(), vec![1, 2, 3]);
        let result = server.process_client_first(&client_first);

        assert!(result.is_err());
    }
}