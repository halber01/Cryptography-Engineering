use std::io::Read;
use anyhow::{Result, anyhow, Context};
use super::{
    keys::{key_schedule_1, key_schedule_2, key_schedule_3, TlsKeys},
    session::{TlsSession, TlsRole},
};

// You'll need to import these from your existing modules
// Adjust the paths based on where your crypto implementations are
// For now, I'll create placeholder imports - you'll need to fix these
use crate::crypto::{dhke, sign, aead, hmac};  // ← Adjust these paths!

/// Represents a TLS client during handshake
pub struct TlsClient {
    /// Client nonce
    nonce_c: [u8; 32],

    /// Client's DH keypair (x, g^x)
    keypair: dhke::DHkeypair,
}

/// Represents a TLS server during handshake
pub struct TlsServer {
    /// Server nonce
    nonce_s: [u8; 32],

    /// Server's DH keypair
    keypair: Option<dhke::DHkeypair>,

    /// Shared secret (computed during server_hello)
    shared_secret: Option<[u8; 32]>,

    /// Server public key (stored for later use)
    server_pk: Option<Vec<u8>>,

    /// Certificate Authority keypair
    ca_keypair: sign::Keypair,

    /// Server's signing keypair
    sigma_keypair: sign::Keypair,
}

/// Represents the server's hello message
pub struct ServerHello {
    pub nonce_s: [u8; 32],
    pub server_pk: Vec<u8>,
    pub encrypted_finished: Vec<u8>,  // Contains: server_cert || sigma_s || mac_s
}

/// Represents the client's finished message
pub struct ClientFinished {
    pub encrypted_mac: Vec<u8>,  // Contains: mac_c
}

impl TlsClient {
    /// Create a new TLS client
    pub fn new() -> Self {
        Self {
            nonce_c: rand::random(),
            keypair: dhke::DHkeypair::keygen(),
        }
    }

    /// Generate ClientHello message
    /// Returns: (nonce_c, client_public_key)
    pub fn client_hello(&self) -> ([u8; 32], Vec<u8>) {
        (self.nonce_c, self.keypair.pk.to_bytes().to_vec())
    }

    /// Process ServerHello and ServerFinished, then create ClientFinished
    /// This completes the handshake from the client side
    ///
    /// # Arguments
    /// * `server_hello` - The server's hello message
    ///
    /// # Returns
    /// * `ClientFinished` - The client's finished message to send back
    /// * `TlsSession` - The established session
    pub fn process_server_hello(
        mut self,  // Take ownership instead of &self
        server_hello: &ServerHello,
    ) -> Result<(ClientFinished, TlsSession)> {
        let client_pk = self.keypair.pk.to_bytes();

        // 1. Compute shared secret using DHKE
        let server_pk_parsed = parse_public_key(&server_hello.server_pk)?;
        let shared_secret = dhke::shared_secret(self.keypair.sk, &server_pk_parsed);

        // 2. Derive keys using key schedules
        let (k1_c, k1_s) = key_schedule_1(&shared_secret);
        let (k2_c, k2_s) = key_schedule_2(
            &self.nonce_c,
            &client_pk,
            &server_hello.nonce_s,
            &server_hello.server_pk,
            &shared_secret,
        );

        // 3. Decrypt ServerFinished message (contains: server_cert || sigma_s || mac_s)
        let aead_nonce_s: [u8; 12] = server_hello.nonce_s[..12].try_into()
            .context("Failed to create AEAD nonce")?;

        let decrypted = aead::decrypt(
            &k1_s,
            &aead_nonce_s,
            &server_hello.encrypted_finished,
            b"",
        );

        // 4. Split decrypted data: server_cert || sigma_s || mac_s
        let (server_cert, sigma_s, mac_s) = split_server_finished(&decrypted.unwrap())?;

        // 5. Verify server certificate signature (signed by CA)
        verify_server_certificate(&server_cert)?;

        // 6. Verify server signature (sigma_s)
        let server_sha = hash_handshake_data(
            &self.nonce_c,
            &client_pk,
            &server_hello.nonce_s,
            &server_hello.server_pk,
        );
        verify_server_signature(&sigma_s, &server_sha)?;

        // 7. Verify server MAC
        let expected_mac_s = compute_server_mac(
            &k2_s,
            &self.nonce_c,
            &client_pk,
            &server_hello.nonce_s,
            &server_hello.server_pk,
            &sigma_s,
            &server_cert,
        );

        if mac_s != expected_mac_s {
            return Err(anyhow!("Server MAC verification failed"));
        }

        // 8. Derive final keys (KeySchedule_3)
        let (k3_c, k3_s) = key_schedule_3(
            &self.nonce_c,
            &client_pk,
            &server_hello.nonce_s,
            &server_hello.server_pk,
            &shared_secret,
            &sigma_s,
            &server_cert,
            &mac_s,
        );

        // 9. Compute client MAC
        let mac_c = compute_client_mac(
            &k2_c,
            &self.nonce_c,
            &client_pk,
            &server_hello.nonce_s,
            &server_hello.server_pk,
            &sigma_s,
            &server_cert,
        );

        // 10. Encrypt client MAC for ClientFinished
        let aead_nonce_c: [u8; 12] = self.nonce_c[..12].try_into()
            .context("Failed to create AEAD nonce")?;

        let encrypted_mac = aead::encrypt(&k1_c, &aead_nonce_c, &mac_c, b"").unwrap().to_vec();

        let client_finished = ClientFinished { encrypted_mac };

        // 11. Create TLS session
        let keys = TlsKeys {
            k1_c, k1_s,
            k2_c, k2_s,
            k3_c, k3_s,
        };

        let session = TlsSession::new(
            TlsRole::Client,
            keys,
            self.nonce_c,
            server_hello.nonce_s,
            client_pk.to_vec(),
            server_hello.server_pk.clone(),
            server_cert.to_vec(),
            shared_secret.to_vec(),
        );

        Ok((client_finished, session))
    }
}

impl TlsServer {
    pub fn new(ca_keypair: sign::Keypair) -> Self {
        Self {
            nonce_s: rand::random(),
            keypair: Some(dhke::DHkeypair::keygen()),
            shared_secret: None,
            server_pk: None,
            ca_keypair,
            sigma_keypair: sign::keygen(),
        }
    }

    /// Process ClientHello and generate ServerHello + ServerFinished
    ///
    /// # Arguments
    /// * `nonce_c` - Client nonce
    /// * `client_pk` - Client public key
    ///
    /// # Returns
    /// * `ServerHello` - The server's hello message
    pub fn server_hello(
        &mut self,
        nonce_c: &[u8; 32],
        client_pk: &[u8],
    ) -> Result<ServerHello> {
        // Take the keypair temporarily
        let keypair = self.keypair.take()
            .ok_or_else(|| anyhow!("Server keypair already used"))?;

        let server_pk = keypair.pk.to_bytes();

        // Parse client key
        let client_pk_parsed = parse_public_key(client_pk)?;

        // Compute shared secret (this consumes keypair.sk)
        let shared_secret = dhke::shared_secret(keypair.sk, &client_pk_parsed);

        // Store the results we need later
        self.shared_secret = Some(shared_secret);
        self.server_pk = Some(server_pk.to_vec());

        // 2. Derive keys
        let (k1_c, k1_s) = key_schedule_1(&shared_secret);
        let (k2_c, k2_s) = key_schedule_2(
            nonce_c,
            client_pk,
            &self.nonce_s,
            &server_pk,
            &shared_secret,
        );

        // 3. Create server certificate (server_pk || CA_signature)
        let sigma_ca = sign::sign(&self.ca_keypair.sk, &server_pk);
        let server_cert = [&server_pk[..], &sigma_ca.to_bytes()[..]].concat();

        // 4. Create server signature (sigma_s)
        let server_sha = hash_handshake_data(nonce_c, client_pk, &self.nonce_s, &server_pk);
        let sigma_s = sign::sign(&self.sigma_keypair.sk, &server_sha);

        // 5. Compute server MAC
        let mac_s = compute_server_mac(
            &k2_s,
            nonce_c,
            client_pk,
            &self.nonce_s,
            &server_pk,
            &sigma_s.to_bytes(),
            &server_cert,
        );

        // 6. Encrypt ServerFinished: server_cert || sigma_s || mac_s
        let plaintext = [
            &server_cert[..],
            &sigma_s.to_bytes()[..],
            &mac_s[..],
        ].concat();

        let aead_nonce_s: [u8; 12] = self.nonce_s[..12].try_into()
            .context("Failed to create AEAD nonce")?;

        let encrypted_finished = aead::encrypt(&k1_s, &aead_nonce_s, &plaintext, b"");
        let server_hello = ServerHello {
            nonce_s: self.nonce_s,
            server_pk: server_pk.to_vec(),
            encrypted_finished: encrypted_finished.unwrap(),
        };

        Ok(server_hello)
    }

    /// Process ClientFinished and create TLS session
    ///
    /// # Arguments
    /// * `nonce_c` - Client nonce
    /// * `client_pk` - Client public key
    /// * `client_finished` - The client's finished message
    ///
    /// # Returns
    /// * `TlsSession` - The established session
    pub fn process_client_finished(
        &self,  // Change to &self (not &mut self)
        nonce_c: &[u8; 32],
        client_pk: &[u8],
        client_finished: &ClientFinished,
    ) -> Result<TlsSession> {
        // Use the stored shared_secret instead of recomputing
        let shared_secret = self.shared_secret
            .ok_or_else(|| anyhow!("Shared secret not available. Call server_hello first."))?;

        let server_pk = self.server_pk.as_ref()
            .ok_or_else(|| anyhow!("Server public key not available"))?;

        // Now use shared_secret and server_pk instead of recomputing
        let (k1_c, k1_s) = key_schedule_1(&shared_secret);
        let (k2_c, k2_s) = key_schedule_2(
            nonce_c,
            client_pk,
            &self.nonce_s,
            server_pk,  // Use stored server_pk
            &shared_secret,
        );

        // 3. Recreate server cert and signature (same as in server_hello)
        let sigma_ca = sign::sign(&self.ca_keypair.sk, &server_pk);
        let server_cert = [&server_pk[..], &sigma_ca.to_bytes()[..]].concat();

        let server_sha = hash_handshake_data(nonce_c, client_pk, &self.nonce_s, &server_pk);
        let sigma_s = sign::sign(&self.sigma_keypair.sk, &server_sha);

        let mac_s = compute_server_mac(
            &k2_s,
            nonce_c,
            client_pk,
            &self.nonce_s,
            &server_pk,
            &sigma_s.to_bytes(),
            &server_cert,
        );

        // 4. Derive final keys
        let (k3_c, k3_s) = key_schedule_3(
            nonce_c,
            client_pk,
            &self.nonce_s,
            &server_pk,
            &shared_secret,
            &sigma_s.to_bytes(),
            &server_cert,
            &mac_s,
        );

        // 5. Decrypt and verify client MAC
        let aead_nonce_c: [u8; 12] = nonce_c[..12].try_into()
            .context("Failed to create AEAD nonce")?;

        let decrypted_mac = aead::decrypt(
            &k1_c,
            &aead_nonce_c,
            &client_finished.encrypted_mac,
            b"",
        );

        // 6. Verify client MAC
        let expected_mac_c = compute_client_mac(
            &k2_c,
            nonce_c,
            client_pk,
            &self.nonce_s,
            &server_pk,
            &sigma_s.to_bytes(),
            &server_cert,
        );

        if decrypted_mac.unwrap().to_vec() != expected_mac_c.to_vec() {
            return Err(anyhow!("Client MAC verification failed"));
        }

        // 7. Create TLS session
        let keys = TlsKeys {
            k1_c, k1_s,
            k2_c, k2_s,
            k3_c, k3_s,
        };

        let session = TlsSession::new(
            TlsRole::Server,
            keys,
            *nonce_c,
            self.nonce_s,
            client_pk.to_vec(),
            server_pk.to_vec(),
            server_cert,
            shared_secret.to_vec(),
        );

        Ok(session)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Hash handshake data for signature
fn hash_handshake_data(
    nonce_c: &[u8],
    client_pk: &[u8],
    nonce_s: &[u8],
    server_pk: &[u8],
) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let data = [nonce_c, client_pk, nonce_s, server_pk].concat();
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize().into()
}

/// Compute server MAC
fn compute_server_mac(
    k2_s: &[u8; 32],
    nonce_c: &[u8],
    client_pk: &[u8],
    nonce_s: &[u8],
    server_pk: &[u8],
    sigma_s: &[u8],
    server_cert: &[u8],
) -> [u8; 32] {
    let hash_input = [
        nonce_c,
        client_pk,
        nonce_s,
        server_pk,
        sigma_s,
        server_cert,
        b"ServerMAC",
    ].concat();

    hmac::compute_hmac_sha256(k2_s, &hash_input)
}

/// Compute client MAC
fn compute_client_mac(
    k2_c: &[u8; 32],
    nonce_c: &[u8],
    client_pk: &[u8],
    nonce_s: &[u8],
    server_pk: &[u8],
    sigma_s: &[u8],
    server_cert: &[u8],
) -> [u8; 32] {
    let hash_input = [
        nonce_c,
        client_pk,
        nonce_s,
        server_pk,
        sigma_s,
        server_cert,
        b"ClientMAC",
    ].concat();

    hmac::compute_hmac_sha256(k2_c, &hash_input)
}

/// Split ServerFinished decrypted data into components
/// Format: server_cert || sigma_s || mac_s
fn split_server_finished(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, [u8; 32])> {
    if data.len() < 96 {
        return Err(anyhow!("ServerFinished data too short"));
    }

    let mac_start = data.len() - 32;
    let sigma_start = mac_start - 64;

    let server_cert = data[..sigma_start].to_vec();
    let sigma_s = data[sigma_start..mac_start].to_vec();
    let mac_s: [u8; 32] = data[mac_start..].try_into()
        .context("Failed to extract MAC")?;

    Ok((server_cert, sigma_s, mac_s))
}

/// Verify server certificate (signed by CA)
fn verify_server_certificate(server_cert: &[u8]) -> Result<()> {
    // Split cert into: server_pk || ca_signature
    // You'll need to adjust based on your actual sizes

    if server_cert.len() < 96 {  // Assuming 32 byte pk + 64 byte signature
        return Err(anyhow!("Invalid certificate length"));
    }

    let pk_len = server_cert.len() - 64;
    let server_pk = &server_cert[..pk_len];
    let ca_sig_bytes = &server_cert[pk_len..];

    // TODO: Verify CA signature
    // You'll need access to CA public key here
    // sgn::verify(&ca_pk, server_pk, ca_sig_bytes)?;

    // For now, just check it exists
    if ca_sig_bytes.len() != 64 {
        return Err(anyhow!("Invalid CA signature length"));
    }

    Ok(())
}

/// Verify server signature
fn verify_server_signature(sigma_s: &[u8], message: &[u8; 32]) -> Result<()> {
    // TODO: Verify server's signature on the handshake hash

    if sigma_s.len() != 64 {
        return Err(anyhow!("Invalid signature length"));
    }

    Ok(())
}

/// Parse a byte slice into a PublicKey
fn parse_public_key(bytes: &[u8]) -> Result<dhke::PublicKey> {
    let array: [u8; 32] = bytes
        .try_into()
        .context("Public key must be exactly 32 bytes")?;
    Ok(dhke::PublicKey::from(array))
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