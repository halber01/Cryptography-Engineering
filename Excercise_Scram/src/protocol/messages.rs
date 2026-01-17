use serde::{Deserialize, Serialize};

/// ClientFirst message: [ClientName], ch₁
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFirst {
    pub client_name: String,
    pub ch1: Vec<u8>,  // Client challenge
}

/// ServerFirst message: ch₁ || ch₂, r, n
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFirst {
    pub ch1: Vec<u8>,  // Echo back client challenge
    pub ch2: Vec<u8>,  // Server challenge
    pub r: Vec<u8>,    // Salt
    pub n: u32,        // Iterations
}

/// ClientFinal message: TLS_INFO, ch₁ || ch₂, Client_proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFinal {
    pub tls_info: Vec<u8>,
    pub ch1: Vec<u8>,
    pub ch2: Vec<u8>,
    pub client_proof: [u8; 32],
}

/// ServerFinal message: Server_sign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFinal {
    pub server_sign: [u8; 32],
}

impl ClientFirst {
    pub fn new(client_name: String, ch1: Vec<u8>) -> Self {
        Self { client_name, ch1 }
    }
}

impl ServerFirst {
    pub fn new(ch1: Vec<u8>, ch2: Vec<u8>, r: Vec<u8>, n: u32) -> Self {
        Self { ch1, ch2, r, n }
    }
}

impl ClientFinal {
    pub fn new(tls_info: Vec<u8>, ch1: Vec<u8>, ch2: Vec<u8>, client_proof: [u8; 32]) -> Self {
        Self {
            tls_info,
            ch1,
            ch2,
            client_proof,
        }
    }
}

impl ServerFinal {
    pub fn new(server_sign: [u8; 32]) -> Self {
        Self { server_sign }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_first_creation() {
        let msg = ClientFirst::new("Alice".to_string(), vec![1, 2, 3]);
        assert_eq!(msg.client_name, "Alice");
        assert_eq!(msg.ch1, vec![1, 2, 3]);
    }

    #[test]
    fn test_server_first_creation() {
        let msg = ServerFirst::new(vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9], 10000);
        assert_eq!(msg.ch1, vec![1, 2, 3]);
        assert_eq!(msg.ch2, vec![4, 5, 6]);
        assert_eq!(msg.r, vec![7, 8, 9]);
        assert_eq!(msg.n, 10000);
    }
}