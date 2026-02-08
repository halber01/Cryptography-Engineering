//! OPRF (Oblivious Pseudorandom Function) implementation

use elliptic_curve::{
    CurveArithmetic,
    ProjectivePoint,
    Field,
    group::{GroupEncoding, ff::PrimeField},
};
use elliptic_curve::hash2curve::{ExpandMsg, GroupDigest};
use elliptic_curve::group::cofactor::CofactorGroup;

use crate::types::OpaqueError;
use crate::crypto::{
    primitives::{point_to_bytes, bytes_to_point, sha3_256},
    hash2curve::hash_password_to_curve,
};

// ============================================================================
// CLIENT-SIDE OPRF
// ============================================================================

pub struct OprfClient<C>
where
    C: CurveArithmetic,
{
    alpha: C::Scalar,
    password: Vec<u8>,
}

impl<C> OprfClient<C>  // Removed X from here
where
    C: CurveArithmetic + GroupDigest,
    ProjectivePoint<C>: GroupEncoding + CofactorGroup,
    <C as CurveArithmetic>::Scalar: PrimeField,
{
    /// Start OPRF: blind the password
    pub fn blind<X>(password: Vec<u8>) -> Result<(Self, Vec<u8>), OpaqueError>
    where
            for<'a> X: ExpandMsg<'a>,  // X is now a generic parameter of the function
    {
        let pw_point = hash_password_to_curve::<C, X>(&password)?;
        let alpha = C::Scalar::random(&mut rand_core::OsRng);
        let blinded_point = pw_point * alpha;
        let blinded_bytes = point_to_bytes::<C>(&blinded_point);

        let client = OprfClient {
            alpha,
            password,
        };

        Ok((client, blinded_bytes))
    }

    /// Finalize OPRF: unblind server's response and compute rw
    pub fn finalize(self, blinded_response: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        let blinded_salted_point = bytes_to_point::<C>(blinded_response)?;

        // Compute α^(-1) using Field trait
        let alpha_inv = Option::<C::Scalar>::from(self.alpha.invert())
            .ok_or_else(|| OpaqueError::CryptoError("Scalar inversion failed".to_string()))?;

        let salted_point = blinded_salted_point * alpha_inv;
        let salted_point_bytes = point_to_bytes::<C>(&salted_point);

        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(&self.password);
        hasher_input.extend_from_slice(&salted_point_bytes);

        let rw = sha3_256(&hasher_input);

        Ok(rw)
    }
}

// ============================================================================
// SERVER-SIDE OPRF
// ============================================================================

pub struct OprfServer;

impl OprfServer {
    pub fn evaluate<C>(
        blinded_element: &[u8],
        salt: &[u8],
    ) -> Result<Vec<u8>, OpaqueError>
    where
        C: CurveArithmetic,
        ProjectivePoint<C>: GroupEncoding,
        <C as CurveArithmetic>::Scalar: PrimeField,
    {
        let blinded_point = bytes_to_point::<C>(blinded_element)?;
        let salt_scalar = Self::bytes_to_scalar::<C>(salt)?;
        let salted_blinded_point = blinded_point * salt_scalar;
        let result = point_to_bytes::<C>(&salted_blinded_point);

        Ok(result)
    }

    fn bytes_to_scalar<C>(bytes: &[u8]) -> Result<C::Scalar, OpaqueError>
    where
        C: CurveArithmetic,
        <C as CurveArithmetic>::Scalar: PrimeField,
    {
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

    type Curve = NistP256;
    type Expander = ExpandMsgXmd<Sha256>;

    #[test]
    fn test_oprf_protocol() {
        let password = b"test_password_123";
        let salt = vec![42u8; 32];

        let (client, blinded_element) = OprfClient::<Curve>::blind::<Expander>(password.to_vec())
            .expect("Blinding should succeed");

        let blinded_response = OprfServer::evaluate::<Curve>(&blinded_element, &salt)
            .expect("OPRF evaluation should succeed");

        let rw = client.finalize(&blinded_response)
            .expect("Finalization should succeed");

        assert_eq!(rw.len(), 32);

        let (client2, blinded2) = OprfClient::<Curve>::blind::<Expander>(password.to_vec())
            .unwrap();
        let response2 = OprfServer::evaluate::<Curve>(&blinded2, &salt).unwrap();
        let rw2 = client2.finalize(&response2).unwrap();

        assert_eq!(rw, rw2, "OPRF should be deterministic");
    }

    #[test]
    fn test_different_passwords_different_rw() {
        let password1 = b"password1";
        let password2 = b"password2";
        let salt = vec![42u8; 32];

        let (client1, blinded1) = OprfClient::<Curve>::blind::<Expander>(password1.to_vec()).unwrap();
        let response1 = OprfServer::evaluate::<Curve>(&blinded1, &salt).unwrap();
        let rw1 = client1.finalize(&response1).unwrap();

        let (client2, blinded2) = OprfClient::<Curve>::blind::<Expander>(password2.to_vec()).unwrap();
        let response2 = OprfServer::evaluate::<Curve>(&blinded2, &salt).unwrap();
        let rw2 = client2.finalize(&response2).unwrap();

        assert_ne!(rw1, rw2, "Different passwords should produce different rw");
    }
}