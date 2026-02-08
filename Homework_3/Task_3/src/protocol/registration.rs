//! Registration protocol for OPAQUE

use serde::{Deserialize, Serialize};
use elliptic_curve::{
    CurveArithmetic,
    ProjectivePoint,
    ScalarPrimitive,
    Field,
    group::{GroupEncoding, ff::PrimeField},
};
use elliptic_curve::hash2curve::{ExpandMsg, GroupDigest};
use elliptic_curve::group::cofactor::CofactorGroup;
use elliptic_curve::ops::MulByGenerator;

use crate::types::{
    Username, Password, Salt, EncryptedKeyBundle,
    ServerKeyBundle, ClientKeyInfo, ServerRecord, OpaqueError, RwValue,
};
use crate::crypto::{
    primitives::*,
    hash2curve::hash_password_to_curve,
};

// ============================================================================
// MESSAGE TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub username: Username,
    pub password_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// CLIENT-SIDE REGISTRATION
// ============================================================================

pub struct ClientRegistration<C>
where
    C: CurveArithmetic,
{
    _phantom: std::marker::PhantomData<C>,
}

impl<C> ClientRegistration<C>
where
    C: CurveArithmetic + GroupDigest,
    ProjectivePoint<C>: GroupEncoding + CofactorGroup,
{
    pub fn create_request(
        username: Username,
        password: Password,
    ) -> RegistrationRequest {
        RegistrationRequest {
            username,
            password_hash: password.0.as_bytes().to_vec(),
        }
    }
}

// ============================================================================
// SERVER-SIDE REGISTRATION
// ============================================================================

pub struct ServerRegistration<C, X>
where
    C: CurveArithmetic,
{
    _phantom_curve: std::marker::PhantomData<C>,
    _phantom_expander: std::marker::PhantomData<X>,
}

impl<C, X> ServerRegistration<C, X>
where
    C: CurveArithmetic + GroupDigest,
    ProjectivePoint<C>: GroupEncoding + CofactorGroup + MulByGenerator,  // Fixed: removed <C>
    <C as CurveArithmetic>::Scalar: PrimeField,
    for<'a> X: ExpandMsg<'a>,
{
    pub fn process_request(
        request: RegistrationRequest,
    ) -> Result<ServerRecord, OpaqueError> {
        let username = request.username;
        let password = request.password_hash;

        let salt_bytes = random_scalar_bytes(32);
        let salt = Salt(salt_bytes.clone());

        let rw = Self::compute_rw(&password, &salt_bytes)?;
        let rw_key = hkdf_expand(&rw.0, b"OPAQUE-RW-Key", 32)?;

        let client_secret = Self::random_scalar()?;
        let client_public = ProjectivePoint::<C>::mul_by_generator(&client_secret);
        let client_secret_bytes = Self::scalar_to_bytes(&client_secret);

        let server_secret = Self::random_scalar()?;
        let server_public = ProjectivePoint::<C>::mul_by_generator(&server_secret);
        let server_secret_bytes = Self::scalar_to_bytes(&server_secret);

        let client_key_info = ClientKeyInfo {
            client_public_key: point_to_bytes::<C>(&client_public),  // Fixed: added ::<C>
            client_secret_key: client_secret_bytes.clone(),
            server_public_key: point_to_bytes::<C>(&server_public),  // Fixed: added ::<C>
        };

        let client_key_info_bytes = serde_json::to_vec(&client_key_info)
            .map_err(|e| OpaqueError::SerializationError(e.to_string()))?;

        let (ciphertext, nonce) = aead_encrypt(&rw_key, &client_key_info_bytes)?;

        let encrypted_bundle = EncryptedKeyBundle {
            ciphertext,
            nonce,
        };

        let server_key_bundle = ServerKeyBundle {
            client_public_key: point_to_bytes::<C>(&client_public),  // Fixed: added ::<C>
            server_public_key: point_to_bytes::<C>(&server_public),  // Fixed: added ::<C>
            server_secret_key: server_secret_bytes,
        };

        let server_record = ServerRecord {
            username,
            salt,
            server_key_bundle,
            client_encrypted_key_bundle: encrypted_bundle,
        };

        Ok(server_record)
    }

    fn compute_rw(password: &[u8], salt: &[u8]) -> Result<RwValue, OpaqueError> {
        let pw_point = hash_password_to_curve::<C, X>(password)?;
        let salt_scalar = Self::bytes_to_scalar(salt)?;
        let salted_point = pw_point * salt_scalar;
        let salted_point_bytes = point_to_bytes::<C>(&salted_point);  // Fixed: added ::<C>

        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(password);
        hasher_input.extend_from_slice(&salted_point_bytes);

        let rw_bytes = sha3_256(&hasher_input);
        Ok(RwValue(rw_bytes))
    }

    fn random_scalar() -> Result<C::Scalar, OpaqueError> {
        Ok(C::Scalar::random(&mut rand_core::OsRng))
    }

    fn scalar_to_bytes(scalar: &C::Scalar) -> Vec<u8> {
        scalar.to_repr().as_ref().to_vec()
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
    use sha2::Sha256;

    #[test]
    fn test_registration_flow() {
        type Curve = NistP256;
        type Expander = sha2::Sha256;

        let username = Username::from("alice");
        let password = Password::from("secure_password_123");

        let request = ClientRegistration::<Curve>::create_request(
            username.clone(),
            password.clone(),
        );

        let record = ServerRegistration::<Curve, Expander>::process_request(request)
            .expect("Registration should succeed");

        assert_eq!(record.username, username);
        assert!(!record.salt.0.is_empty());
        assert!(!record.client_encrypted_key_bundle.ciphertext.is_empty());
    }
}