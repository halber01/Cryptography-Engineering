//! Login protocol for OPAQUE
//!
//! Flow:
//! 1. OPRF Stage: Client gets rw, decrypts AKE keys
//! 2. AKE Stage: Both parties derive session key SK
//! 3. Key Confirmation: Both verify they have the same SK

use serde::{Deserialize, Serialize};
use elliptic_curve::{
    CurveArithmetic,
    ProjectivePoint,
    Field,
    group::{GroupEncoding, ff::PrimeField},
};
use elliptic_curve::hash2curve::{ExpandMsg, GroupDigest};
use elliptic_curve::group::cofactor::CofactorGroup;
use elliptic_curve::ops::MulByGenerator;

use crate::types::{Username, Password, OpaqueError, ClientKeyInfo, SessionKey};
use crate::server::Database;
use crate::crypto::{
    primitives::*,
    oprf::{OprfClient, OprfServer},
    ake::{triple_dh_client, triple_dh_server},
};

// ============================================================================
// MESSAGE TYPES
// ============================================================================

/// Stage 1: Client -> Server (OPRF request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: Username,
    pub blinded_element: Vec<u8>,  // h(pw)^α
}

/// Stage 1: Server -> Client (OPRF response + encrypted keys)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse1 {
    pub blinded_response: Vec<u8>,        // h(pw)^(α·s)
    pub encrypted_key_bundle: Vec<u8>,    // AEAD(rw, client_keys)
    pub nonce: Vec<u8>,
    pub server_ephemeral_public: Vec<u8>, // Y (epk_s)
}

/// Stage 2: Client -> Server (AKE + Key Confirmation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest2 {
    pub client_ephemeral_public: Vec<u8>, // X (epk_c)
    pub client_mac: Vec<u8>,               // mac_c
}

/// Stage 3: Server -> Client (Key Confirmation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse2 {
    pub server_mac: Vec<u8>,  // mac_s
}

// ============================================================================
// CLIENT-SIDE LOGIN
// ============================================================================

/// Client state during login
pub struct ClientLogin<C>
where
    C: CurveArithmetic,
{
    username: Username,
    password: Vec<u8>,
    oprf_client: Option<OprfClient<C>>,
    client_long_secret: Option<C::Scalar>,      // a (lsk_c)
    client_long_public: Option<Vec<u8>>,        // A (lpk_c)
    client_ephemeral_secret: Option<C::Scalar>, // x (esk_c)
    server_long_public: Option<Vec<u8>>,        // B (lpk_s)
    session_key: Option<Vec<u8>>,
}

impl<C> ClientLogin<C>
where
    C: CurveArithmetic + GroupDigest,
    ProjectivePoint<C>: GroupEncoding + CofactorGroup + MulByGenerator,
    <C as CurveArithmetic>::Scalar: PrimeField,
{
    /// Start login: create OPRF request
    pub fn start<X>(username: Username, password: Password) -> Result<(Self, LoginRequest), OpaqueError>
    where
            for<'a> X: ExpandMsg<'a>,
    {
        let password_bytes = password.0.as_bytes().to_vec();

        // Blind the password
        let (oprf_client, blinded_element) = OprfClient::<C>::blind::<X>(password_bytes.clone())?;

        let request = LoginRequest {
            username: username.clone(),
            blinded_element,
        };

        let client = ClientLogin {
            username,
            password: password_bytes,
            oprf_client: Some(oprf_client),
            client_long_secret: None,
            client_long_public: None,
            client_ephemeral_secret: None,
            server_long_public: None,
            session_key: None,
        };

        Ok((client, request))
    }

    /// Process server's OPRF response and create AKE request
    pub fn process_response1(
        mut self,
        response: LoginResponse1,
    ) -> Result<(Self, LoginRequest2), OpaqueError> {
        // Step 1: Finalize OPRF to get rw
        let oprf_client = self.oprf_client.take()
            .ok_or_else(|| OpaqueError::ProtocolError("OPRF client not initialized".to_string()))?;

        let rw = oprf_client.finalize(&response.blinded_response)?;

        // Step 2: Decrypt client key bundle
        let rw_key = hkdf_expand(&rw, b"OPAQUE-RW-Key", 32)?;
        let decrypted = aead_decrypt(&rw_key, &response.encrypted_key_bundle, &response.nonce)?;

        // Step 3: Deserialize client keys
        let client_key_info: ClientKeyInfo = serde_json::from_slice(&decrypted)
            .map_err(|e| OpaqueError::SerializationError(e.to_string()))?;

        // Step 4: Parse client's long-term keys
        let client_long_secret = Self::bytes_to_scalar(&client_key_info.client_secret_key)?;
        self.client_long_secret = Some(client_long_secret);
        self.client_long_public = Some(client_key_info.client_public_key);
        self.server_long_public = Some(client_key_info.server_public_key.clone());

        // Step 5: Generate ephemeral key pair for AKE
        let client_ephemeral_secret = C::Scalar::random(&mut rand_core::OsRng);
        let client_ephemeral_public = ProjectivePoint::<C>::mul_by_generator(&client_ephemeral_secret);
        let client_ephemeral_public_bytes = point_to_bytes::<C>(&client_ephemeral_public);
        self.client_ephemeral_secret = Some(client_ephemeral_secret);

        // Step 6: Compute session key using 3DH
        let session_key = triple_dh_client::<C>(
            &client_long_secret,
            &client_ephemeral_secret,
            &client_key_info.server_public_key,
            &response.server_ephemeral_public,
        )?;
        self.session_key = Some(session_key.clone());

        // Step 7: Derive confirmation keys and compute client MAC
        let (k_c, _k_s) = hkdf_expand_two_keys(&session_key, b"Key Confirmation")?;
        let client_mac = hmac_compute(&k_c, b"Client KC");

        let request2 = LoginRequest2 {
            client_ephemeral_public: client_ephemeral_public_bytes,
            client_mac,
        };

        Ok((self, request2))
    }

    /// Process server's key confirmation and finalize
    pub fn finalize(self, response: LoginResponse2) -> Result<SessionKey, OpaqueError> {
        let session_key = self.session_key
            .ok_or_else(|| OpaqueError::ProtocolError("Session key not computed".to_string()))?;

        // Verify server's MAC
        let (_k_c, k_s) = hkdf_expand_two_keys(&session_key, b"Key Confirmation")?;

        if !hmac_verify(&k_s, b"Server KC", &response.server_mac) {
            return Err(OpaqueError::InvalidMac);
        }

        Ok(SessionKey(session_key))
    }

    fn bytes_to_scalar(bytes: &[u8]) -> Result<C::Scalar, OpaqueError> {
        let mut scalar_bytes = <C::Scalar as PrimeField>::Repr::default();
        let copy_len = bytes.len().min(scalar_bytes.as_ref().len());
        scalar_bytes.as_mut()[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Option::<C::Scalar>::from(C::Scalar::from_repr(scalar_bytes))
            .ok_or_else(|| OpaqueError::CryptoError("Invalid scalar".to_string()))
    }
}

// ============================================================================
// SERVER-SIDE LOGIN
// ============================================================================

/// Server state during login
pub struct ServerLogin<C>
where
    C: CurveArithmetic,
{
    username: Username,
    salt: Vec<u8>,
    server_long_secret: C::Scalar,        // b (lsk_s)
    server_long_public: Vec<u8>,          // B (lpk_s)
    server_ephemeral_secret: C::Scalar,   // y (esk_s)
    server_ephemeral_public: Vec<u8>,     // Y (epk_s)
    client_long_public: Vec<u8>,          // A (lpk_c)
    encrypted_key_bundle: Vec<u8>,
    nonce: Vec<u8>,
    session_key: Option<Vec<u8>>,
}

impl<C> ServerLogin<C>
where
    C: CurveArithmetic,
    ProjectivePoint<C>: GroupEncoding + MulByGenerator,
    <C as CurveArithmetic>::Scalar: PrimeField,
{
    /// Process login request and create OPRF response
    pub fn process_request(
        request: LoginRequest,
        database: &Database,
    ) -> Result<(Self, LoginResponse1), OpaqueError> {
        // Step 1: Retrieve user record
        let record = database.get(&request.username)?;

        // Step 2: Evaluate OPRF
        let blinded_response = OprfServer::evaluate::<C>(
            &request.blinded_element,
            &record.salt.0,
        )?;

        // Step 3: Generate ephemeral key pair for AKE
        let server_ephemeral_secret = C::Scalar::random(&mut rand_core::OsRng);
        let server_ephemeral_public_point = ProjectivePoint::<C>::mul_by_generator(&server_ephemeral_secret);
        let server_ephemeral_public = point_to_bytes::<C>(&server_ephemeral_public_point);

        // Step 4: Parse server's long-term keys
        let server_long_secret = Self::bytes_to_scalar(&record.server_key_bundle.server_secret_key)?;

        let response = LoginResponse1 {
            blinded_response,
            encrypted_key_bundle: record.client_encrypted_key_bundle.ciphertext.clone(),
            nonce: record.client_encrypted_key_bundle.nonce.clone(),
            server_ephemeral_public: server_ephemeral_public.clone(),
        };

        let server = ServerLogin {
            username: request.username,
            salt: record.salt.0.clone(),
            server_long_secret,
            server_long_public: record.server_key_bundle.server_public_key.clone(),
            server_ephemeral_secret,
            server_ephemeral_public,
            client_long_public: record.server_key_bundle.client_public_key.clone(),
            encrypted_key_bundle: record.client_encrypted_key_bundle.ciphertext.clone(),
            nonce: record.client_encrypted_key_bundle.nonce.clone(),
            session_key: None,
        };

        Ok((server, response))
    }

    /// Process client's AKE request and create key confirmation response
    pub fn process_request2(
        mut self,
        request: LoginRequest2,
    ) -> Result<(Self, LoginResponse2), OpaqueError> {
        // Step 1: Compute session key using 3DH
        let session_key = triple_dh_server::<C>(
            &self.server_long_secret,
            &self.server_ephemeral_secret,
            &self.client_long_public,
            &request.client_ephemeral_public,
        )?;
        self.session_key = Some(session_key.clone());

        // Step 2: Verify client's MAC
        let (k_c, k_s) = hkdf_expand_two_keys(&session_key, b"Key Confirmation")?;

        if !hmac_verify(&k_c, b"Client KC", &request.client_mac) {
            return Err(OpaqueError::InvalidMac);
        }

        // Step 3: Compute server's MAC
        let server_mac = hmac_compute(&k_s, b"Server KC");

        let response = LoginResponse2 {
            server_mac,
        };

        Ok((self, response))
    }

    /// Get the final session key
    pub fn get_session_key(self) -> Result<SessionKey, OpaqueError> {
        self.session_key
            .map(SessionKey)
            .ok_or_else(|| OpaqueError::ProtocolError("Session key not computed".to_string()))
    }

    fn bytes_to_scalar(bytes: &[u8]) -> Result<C::Scalar, OpaqueError> {
        let mut scalar_bytes = <C::Scalar as PrimeField>::Repr::default();
        let copy_len = bytes.len().min(scalar_bytes.as_ref().len());
        scalar_bytes.as_mut()[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Option::<C::Scalar>::from(C::Scalar::from_repr(scalar_bytes))
            .ok_or_else(|| OpaqueError::CryptoError("Invalid scalar".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::NistP256;
    use elliptic_curve::hash2curve::ExpandMsgXmd;
    use sha2::Sha256;
    use crate::protocol::registration::{ClientRegistration, ServerRegistration};

    type Curve = NistP256;
    type Expander = ExpandMsgXmd<Sha256>;

    #[test]
    fn test_full_login_flow() {
        // Setup: Register a user first
        let mut db = Database::new();
        let username = Username::from("alice");
        let password = Password::from("secure_password_123");

        let reg_request = ClientRegistration::<Curve>::create_request(
            username.clone(),
            password.clone(),
        );
        let record = ServerRegistration::<Curve, Expander>::process_request(reg_request)
            .expect("Registration should succeed");
        db.store(record).expect("Store should succeed");

        // Now test login flow

        // Stage 1: Client starts login (OPRF)
        let (client, login_req1) = ClientLogin::<Curve>::start::<Expander>(
            username.clone(),
            password.clone(),
        ).expect("Login start should succeed");

        // Server processes OPRF request
        let (server, login_resp1) = ServerLogin::<Curve>::process_request(
            login_req1,
            &db,
        ).expect("Server OPRF should succeed");

        // Stage 2: Client processes OPRF response and sends AKE request
        let (client, login_req2) = client.process_response1(login_resp1)
            .expect("Client AKE should succeed");

        // Server processes AKE and sends key confirmation
        let (server, login_resp2) = server.process_request2(login_req2)
            .expect("Server key confirmation should succeed");

        // Stage 3: Client verifies and finalizes
        let client_session_key = client.finalize(login_resp2)
            .expect("Client finalization should succeed");

        let server_session_key = server.get_session_key()
            .expect("Server should have session key");

        // Both should have the same session key
        assert_eq!(client_session_key.0, server_session_key.0);
        assert_eq!(client_session_key.0.len(), 32);
    }

    #[test]
    fn test_login_wrong_password() {
        // Register with one password
        let mut db = Database::new();
        let username = Username::from("bob");
        let correct_password = Password::from("correct_password");
        let wrong_password = Password::from("wrong_password");

        let reg_request = ClientRegistration::<Curve>::create_request(
            username.clone(),
            correct_password.clone(),
        );
        let record = ServerRegistration::<Curve, Expander>::process_request(reg_request).unwrap();
        db.store(record).unwrap();

        // Try to login with wrong password
        let (client, login_req1) = ClientLogin::<Curve>::start::<Expander>(
            username.clone(),
            wrong_password,
        ).unwrap();

        let (server, login_resp1) = ServerLogin::<Curve>::process_request(login_req1, &db).unwrap();

        // Client will decrypt with wrong rw, getting garbage keys
        // This should fail during key confirmation
        let result = client.process_response1(login_resp1);

        // May fail during decryption or later during key confirmation
        // Either way, authentication should fail
        assert!(result.is_err() || {
            let (client, login_req2) = result.unwrap();
            let result2 = server.process_request2(login_req2);
            result2.is_err()
        });
    }
}