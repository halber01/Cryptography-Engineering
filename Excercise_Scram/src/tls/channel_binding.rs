use sha2::{Sha256, Digest};

/// TLS channel binding information for SCRAM protocol
/// This binds the SCRAM authentication to a specific TLS session
#[derive(Debug, Clone, PartialEq)]
pub struct TlsInfo {
    /// Hash of the TLS handshake transcript (channel binding)
    /// Ensures SCRAM is bound to this specific TLS connection
    channel_binding: [u8; 32],

    /// The handshake key K (shared secret from DHKE)
    /// Used in SCRAM's Auth_msg computation
    handshake_key: Vec<u8>,
}

impl TlsInfo {
    /// Create TLS_INFO from handshake components
    ///
    /// # Arguments
    /// * `nonce_c` - Client nonce
    /// * `client_pk` - Client public key
    /// * `nonce_s` - Server nonce
    /// * `server_pk` - Server public key
    /// * `server_cert` - Server certificate
    /// * `handshake_key` - The shared secret K from DHKE
    pub fn new(
        nonce_c: &[u8],
        client_pk: &[u8],
        nonce_s: &[u8],
        server_pk: &[u8],
        server_cert: &[u8],
        handshake_key: Vec<u8>,
    ) -> Self {
        // Create channel binding: Hash(transcript)
        // Transcript = nonce_c || client_pk || nonce_s || server_pk || server_cert
        let transcript = [
            nonce_c,
            client_pk,
            nonce_s,
            server_pk,
            server_cert,
        ].concat();

        let channel_binding = Self::hash_transcript(&transcript);

        Self {
            channel_binding,
            handshake_key,
        }
    }

    /// Hash the TLS transcript for channel binding
    fn hash_transcript(transcript: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(transcript);
        hasher.finalize().into()
    }

    /// Get the channel binding hash
    pub fn channel_binding(&self) -> &[u8; 32] {
        &self.channel_binding
    }

    /// Get the handshake key K
    pub fn handshake_key(&self) -> &[u8] {
        &self.handshake_key
    }

    /// Serialize TLS_INFO for use in SCRAM Auth_msg
    /// Format: channel_binding || handshake_key
    ///
    /// According to the SCRAM diagram, Auth_msg includes TLS_INFO
    pub fn serialize(&self) -> Vec<u8> {
        [
            &self.channel_binding[..],
            &self.handshake_key[..],
        ].concat()
    }

    /// Get channel binding as base64 (useful for debugging/display)
    pub fn channel_binding_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(&self.channel_binding)
    }

    /// Get handshake key as base64 (useful for debugging/display)
    pub fn handshake_key_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(&self.handshake_key)
    }

    /// Display TLS_INFO in a human-readable format
    pub fn display(&self) -> String {
        format!(
            "TLS_INFO:\n  Channel Binding: {}\n  Handshake Key: {}",
            self.channel_binding_base64(),
            self.handshake_key_base64()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_info_creation() {
        let nonce_c = b"client_nonce_12345678901234567890";
        let client_pk = b"client_public_key";
        let nonce_s = b"server_nonce_12345678901234567890";
        let server_pk = b"server_public_key";
        let server_cert = b"server_certificate_data";
        let handshake_key = b"shared_secret_key".to_vec();

        let tls_info = TlsInfo::new(
            nonce_c,
            client_pk,
            nonce_s,
            server_pk,
            server_cert,
            handshake_key.clone(),
        );

        assert_eq!(tls_info.channel_binding().len(), 32);
        assert_eq!(tls_info.handshake_key(), handshake_key.as_slice());
    }

    #[test]
    fn test_tls_info_deterministic() {
        let nonce_c = b"client_nonce";
        let client_pk = b"client_pk";
        let nonce_s = b"server_nonce";
        let server_pk = b"server_pk";
        let server_cert = b"cert";
        let handshake_key = b"key".to_vec();

        let tls_info1 = TlsInfo::new(
            nonce_c, client_pk, nonce_s, server_pk, server_cert, handshake_key.clone()
        );

        let tls_info2 = TlsInfo::new(
            nonce_c, client_pk, nonce_s, server_pk, server_cert, handshake_key.clone()
        );

        assert_eq!(tls_info1, tls_info2);
    }

    #[test]
    fn test_different_transcripts_produce_different_bindings() {
        let handshake_key = b"key".to_vec();

        let tls_info1 = TlsInfo::new(
            b"nonce1", b"pk1", b"nonce_s", b"server_pk", b"cert", handshake_key.clone()
        );

        let tls_info2 = TlsInfo::new(
            b"nonce2", b"pk1", b"nonce_s", b"server_pk", b"cert", handshake_key.clone()
        );

        assert_ne!(tls_info1.channel_binding(), tls_info2.channel_binding());
    }

    #[test]
    fn test_serialize() {
        let nonce_c = b"c_nonce";
        let client_pk = b"c_pk";
        let nonce_s = b"s_nonce";
        let server_pk = b"s_pk";
        let server_cert = b"cert";
        let handshake_key = b"secret_key".to_vec();

        let tls_info = TlsInfo::new(
            nonce_c, client_pk, nonce_s, server_pk, server_cert, handshake_key.clone()
        );

        let serialized = tls_info.serialize();

        // Should be: 32 bytes (channel_binding) + handshake_key length
        assert_eq!(serialized.len(), 32 + handshake_key.len());

        // First 32 bytes should be channel binding
        assert_eq!(&serialized[..32], tls_info.channel_binding());

        // Remaining bytes should be handshake key
        assert_eq!(&serialized[32..], &handshake_key[..]);
    }

    #[test]
    fn test_base64_encoding() {
        let tls_info = TlsInfo::new(
            b"c_nonce", b"c_pk", b"s_nonce", b"s_pk", b"cert",
            b"key".to_vec()
        );

        let cb_b64 = tls_info.channel_binding_base64();
        let hk_b64 = tls_info.handshake_key_base64();

        // Should be valid base64
        assert!(!cb_b64.is_empty());
        assert!(!hk_b64.is_empty());

        // Should be decodable
        use base64::{Engine as _, engine::general_purpose};
        let decoded_cb = general_purpose::STANDARD.decode(&cb_b64).unwrap();
        let decoded_hk = general_purpose::STANDARD.decode(&hk_b64).unwrap();

        assert_eq!(decoded_cb.as_slice(), tls_info.channel_binding());
        assert_eq!(decoded_hk, tls_info.handshake_key());
    }

    #[test]
    fn test_display() {
        let tls_info = TlsInfo::new(
            b"c_nonce", b"c_pk", b"s_nonce", b"s_pk", b"cert",
            b"key".to_vec()
        );

        let display = tls_info.display();

        assert!(display.contains("TLS_INFO"));
        assert!(display.contains("Channel Binding:"));
        assert!(display.contains("Handshake Key:"));
    }
}