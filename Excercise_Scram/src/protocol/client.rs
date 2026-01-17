use anyhow::{Result, anyhow};
use rand::Rng;
use crate::crypto::{pbkdf2, scram};
use crate::tls::session::TlsSession;
use super::messages::{ClientFirst, ServerFirst, ClientFinal, ServerFinal};

/// SCRAM client for authentication
pub struct ScramClient {
    /// Client username
    username: String,

    /// Client password
    password: Vec<u8>,

    /// Client challenge (ch₁)
    ch1: Vec<u8>,

    /// TLS session (must be established before SCRAM)
    tls_session: TlsSession,
}

impl ScramClient {
    /// Create a new SCRAM client
    ///
    /// # Arguments
    /// * `username` - Client username
    /// * `password` - Client password (will be hashed)
    /// * `tls_session` - Established TLS session
    pub fn new(username: String, password: Vec<u8>, tls_session: TlsSession) -> Self {
        // Generate random client challenge (32 bytes)
        let mut rng = rand::thread_rng();
        let ch1: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();

        Self {
            username,
            password,
            ch1,
            tls_session,
        }
    }

    /// Step 1: Generate ClientFirst message
    pub fn client_first(&self) -> ClientFirst {
        ClientFirst::new(self.username.clone(), self.ch1.clone())
    }

    /// Step 2: Process ServerFirst and generate ClientFinal
    ///
    /// # Arguments
    /// * `server_first` - The ServerFirst message from the server
    ///
    /// # Returns
    /// * `ClientFinal` - The ClientFinal message to send to server
    /// * `[u8; 32]` - The computed password hash (needed for verification later)
    pub fn process_server_first(
        &self,
        server_first: &ServerFirst,
    ) -> Result<(ClientFinal, [u8; 32])> {
        // 1. Verify ch₁ matches
        if server_first.ch1 != self.ch1 {
            return Err(anyhow!("Server echoed wrong client challenge"));
        }

        // 2. Compute password hash: H^n(r, pw)
        let password_hash = pbkdf2::iterate_hash_with_salt(
            &self.password,
            &server_first.r,
            server_first.n,
        )?;

        // 3. Get TLS_INFO
        let tls_info = self.tls_session.get_tls_info();
        let tls_info_serialized = tls_info.serialize();

        // 4. Compute Auth_msg
        let auth_msg = scram::compute_auth_msg(
            &self.username,
            &server_first.ch1,
            &server_first.ch2,
            &server_first.r,
            server_first.n,
            &tls_info_serialized,
        );

        // 5. Compute Client_proof
        let client_proof = scram::compute_client_proof(&password_hash, &auth_msg);

        // 6. Create ClientFinal message
        let client_final = ClientFinal::new(
            tls_info_serialized,
            server_first.ch1.clone(),
            server_first.ch2.clone(),
            client_proof,
        );

        Ok((client_final, password_hash))
    }

    /// Step 3: Verify ServerFinal
    ///
    /// # Arguments
    /// * `server_final` - The ServerFinal message from server
    /// * `server_first` - The ServerFirst message (needed for Auth_msg)
    /// * `password_hash` - The password hash computed in process_server_first
    pub fn verify_server_final(
        &self,
        server_final: &ServerFinal,
        server_first: &ServerFirst,
        password_hash: &[u8; 32],
    ) -> Result<()> {
        // 1. Get TLS_INFO
        let tls_info = self.tls_session.get_tls_info();
        let tls_info_serialized = tls_info.serialize();

        // 2. Recompute Auth_msg
        let auth_msg = scram::compute_auth_msg(
            &self.username,
            &server_first.ch1,
            &server_first.ch2,
            &server_first.r,
            server_first.n,
            &tls_info_serialized,
        );

        // 3. Verify Server_sign
        if !scram::verify_server_sign(password_hash, &auth_msg, &server_final.server_sign) {
            return Err(anyhow!("Server signature verification failed"));
        }

        Ok(())
    }

    /// Get the TLS session
    pub fn tls_session(&self) -> &TlsSession {
        &self.tls_session
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{TlsRole, TlsKeys};

    fn create_test_tls_session() -> TlsSession {
        TlsSession::new(
            TlsRole::Client,
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
    fn test_client_creation() {
        let tls_session = create_test_tls_session();
        let client = ScramClient::new(
            "Alice".to_string(),
            b"password123".to_vec(),
            tls_session,
        );

        assert_eq!(client.username, "Alice");
        assert_eq!(client.ch1.len(), 32);
    }

    #[test]
    fn test_client_first() {
        let tls_session = create_test_tls_session();
        let client = ScramClient::new(
            "Alice".to_string(),
            b"password123".to_vec(),
            tls_session,
        );

        let msg = client.client_first();

        assert_eq!(msg.client_name, "Alice");
        assert_eq!(msg.ch1.len(), 32);
    }
}