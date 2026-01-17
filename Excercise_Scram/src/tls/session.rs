use anyhow::{Result, anyhow};
use super::keys::TlsKeys;
use super::channel_binding::TlsInfo;
use crate::crypto::aead;  // Add this import

/// Represents the role in a TLS connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRole {
    Client,
    Server,
}

/// Represents an established TLS session after successful handshake
/// Both client and server will have their own TlsSession with the same keys
#[derive(Debug, Clone)]
pub struct TlsSession {
    /// Our role in this session (client or server)
    role: TlsRole,

    /// All 6 derived keys (identical for both parties)
    keys: TlsKeys,

    /// Client nonce (32 bytes)
    nonce_c: [u8; 32],

    /// Server nonce (32 bytes)
    nonce_s: [u8; 32],

    /// Client public key
    client_pk: Vec<u8>,

    /// Server public key
    server_pk: Vec<u8>,

    /// Server certificate
    server_cert: Vec<u8>,

    /// Shared secret from DHKE (the handshake key K)
    shared_secret: Vec<u8>,

    /// Session is authenticated and ready for use
    authenticated: bool,
}

impl TlsSession {
    /// Create a new authenticated TLS session
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: TlsRole,
        keys: TlsKeys,
        nonce_c: [u8; 32],
        nonce_s: [u8; 32],
        client_pk: Vec<u8>,
        server_pk: Vec<u8>,
        server_cert: Vec<u8>,
        shared_secret: Vec<u8>,
    ) -> Self {
        Self {
            role,
            keys,
            nonce_c,
            nonce_s,
            client_pk,
            server_pk,
            server_cert,
            shared_secret,
            authenticated: true,
        }
    }

    /// Get the session role
    pub fn role(&self) -> TlsRole {
        self.role
    }

    /// Get the TLS keys
    pub fn keys(&self) -> &TlsKeys {
        &self.keys
    }

    /// Check if session is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Get the handshake key K (shared secret)
    /// This is used in SCRAM protocol
    pub fn handshake_key(&self) -> &[u8] {
        &self.shared_secret
    }

    /// Generate TLS_INFO for SCRAM protocol
    pub fn get_tls_info(&self) -> TlsInfo {
        TlsInfo::new(
            &self.nonce_c,
            &self.client_pk,
            &self.nonce_s,
            &self.server_pk,
            &self.server_cert,
            self.shared_secret.clone(),
        )
    }

    /// Get the encryption key for sending messages
    /// Client uses k3_c, Server uses k3_s
    pub fn get_send_key(&self) -> &[u8; 32] {
        match self.role {
            TlsRole::Client => &self.keys.k3_c,
            TlsRole::Server => &self.keys.k3_s,
        }
    }

    /// Get the decryption key for receiving messages
    /// Client uses k3_s, Server uses k3_c
    pub fn get_recv_key(&self) -> &[u8; 32] {
        match self.role {
            TlsRole::Client => &self.keys.k3_s,
            TlsRole::Server => &self.keys.k3_c,
        }
    }

    /// Get the nonce for sending messages
    fn get_send_nonce(&self) -> [u8; 12] {
        match self.role {
            TlsRole::Client => self.nonce_c[..12].try_into().unwrap(),
            TlsRole::Server => self.nonce_s[..12].try_into().unwrap(),
        }
    }

    /// Get the nonce for receiving messages
    fn get_recv_nonce(&self) -> [u8; 12] {
        match self.role {
            TlsRole::Client => self.nonce_s[..12].try_into().unwrap(),
            TlsRole::Server => self.nonce_c[..12].try_into().unwrap(),
        }
    }

    /// Encrypt data using the session key
    /// Uses the appropriate key based on role (client uses k3_c, server uses k3_s)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.authenticated {
            return Err(anyhow!("Session not authenticated"));
        }

        let key = self.get_send_key();
        let nonce = self.get_send_nonce();

        aead::encrypt(key, &nonce, plaintext, b"")
            .map_err(|e| anyhow!("AEAD encryption failed: {:?}", e))
    }

    /// Decrypt data using the session key
    /// Uses the appropriate key based on role (client uses k3_s, server uses k3_c)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.authenticated {
            return Err(anyhow!("Session not authenticated"));
        }

        let key = self.get_recv_key();
        let nonce = self.get_recv_nonce();

        aead::decrypt(key, &nonce, ciphertext, b"")
            .map_err(|e| anyhow!("AEAD decryption failed: {:?}", e))
    }

    /// Get session info as a string (for debugging)
    pub fn info(&self) -> String {
        format!(
            "TlsSession [{:?}]:\n  Authenticated: {}\n  Handshake Key: {} bytes\n  Client PK: {} bytes\n  Server PK: {} bytes",
            self.role,
            self.authenticated,
            self.shared_secret.len(),
            self.client_pk.len(),
            self.server_pk.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_keys() -> TlsKeys {
        TlsKeys {
            k1_c: [1u8; 32],
            k1_s: [2u8; 32],
            k2_c: [3u8; 32],
            k2_s: [4u8; 32],
            k3_c: [5u8; 32],
            k3_s: [6u8; 32],
        }
    }

    fn create_test_session(role: TlsRole) -> TlsSession {
        TlsSession::new(
            role,
            create_test_keys(),
            [0u8; 32],  // nonce_c
            [1u8; 32],  // nonce_s
            vec![2u8; 32],  // client_pk
            vec![3u8; 32],  // server_pk
            vec![4u8; 64],  // server_cert
            vec![5u8; 32],  // shared_secret
        )
    }

    #[test]
    fn test_session_creation() {
        let session = create_test_session(TlsRole::Client);

        assert_eq!(session.role(), TlsRole::Client);
        assert!(session.is_authenticated());
        assert_eq!(session.handshake_key().len(), 32);
    }

    #[test]
    fn test_client_uses_correct_keys() {
        let client_session = create_test_session(TlsRole::Client);

        assert_eq!(client_session.get_send_key(), &[5u8; 32]);
        assert_eq!(client_session.get_recv_key(), &[6u8; 32]);
    }

    #[test]
    fn test_server_uses_correct_keys() {
        let server_session = create_test_session(TlsRole::Server);

        assert_eq!(server_session.get_send_key(), &[6u8; 32]);
        assert_eq!(server_session.get_recv_key(), &[5u8; 32]);
    }

    #[test]
    fn test_client_and_server_have_complementary_keys() {
        let client_session = create_test_session(TlsRole::Client);
        let server_session = create_test_session(TlsRole::Server);

        assert_eq!(client_session.get_send_key(), server_session.get_recv_key());
        assert_eq!(server_session.get_send_key(), client_session.get_recv_key());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let client_session = create_test_session(TlsRole::Client);
        let server_session = create_test_session(TlsRole::Server);

        let plaintext = b"Hello, SCRAM protocol!";

        // Client encrypts
        let ciphertext = client_session.encrypt(plaintext).unwrap();

        // Server decrypts
        let decrypted = server_session.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_get_tls_info() {
        let session = create_test_session(TlsRole::Client);
        let tls_info = session.get_tls_info();

        assert_eq!(tls_info.handshake_key(), session.handshake_key());
        assert_eq!(tls_info.channel_binding().len(), 32);
    }

    #[test]
    fn test_both_parties_generate_same_tls_info() {
        let client_session = create_test_session(TlsRole::Client);
        let server_session = create_test_session(TlsRole::Server);

        let client_tls_info = client_session.get_tls_info();
        let server_tls_info = server_session.get_tls_info();

        assert_eq!(client_tls_info, server_tls_info);
    }

    #[test]
    fn test_session_info_display() {
        let session = create_test_session(TlsRole::Client);
        let info = session.info();

        assert!(info.contains("TlsSession"));
        assert!(info.contains("Client"));
        assert!(info.contains("Authenticated: true"));
    }
}