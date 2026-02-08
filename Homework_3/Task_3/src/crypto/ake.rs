//! AKE (Authenticated Key Exchange) implementation
//!
//! 3DH (Triple Diffie-Hellman) protocol from the lecture slides

use elliptic_curve::{
    CurveArithmetic,
    ProjectivePoint,
    group::{GroupEncoding, ff::PrimeField},
};

use crate::types::OpaqueError;
use crate::crypto::primitives::{point_to_bytes, bytes_to_point, hkdf_expand};

/// 3DH Client-side key derivation
///
/// Inputs:
/// - a: client's long-term secret key (lsk_c)
/// - x: client's ephemeral secret key (esk_c)
/// - B: server's long-term public key (lpk_s)
/// - Y: server's ephemeral public key (epk_s)
///
/// Computes: SK = HKDF(B^x, Y^x, Y^a)
pub fn triple_dh_client<C>(
    client_long_secret: &C::Scalar,     // a
    client_ephemeral_secret: &C::Scalar, // x
    server_long_public: &[u8],           // B (bytes)
    server_ephemeral_public: &[u8],      // Y (bytes)
) -> Result<Vec<u8>, OpaqueError>
where
    C: CurveArithmetic,
    ProjectivePoint<C>: GroupEncoding,
    <C as CurveArithmetic>::Scalar: PrimeField,
{
    // Deserialize server's public keys
    let B = bytes_to_point::<C>(server_long_public)?;      // lpk_s
    let Y = bytes_to_point::<C>(server_ephemeral_public)?;  // epk_s

    // Compute the three DH values:
    // dh1 = B^x (server long-term, client ephemeral)
    let dh1 = B * client_ephemeral_secret;

    // dh2 = Y^x (both ephemeral)
    let dh2 = Y * client_ephemeral_secret;

    // dh3 = Y^a (server ephemeral, client long-term)
    let dh3 = Y * client_long_secret;

    // Serialize all DH values
    let dh1_bytes = point_to_bytes::<C>(&dh1);
    let dh2_bytes = point_to_bytes::<C>(&dh2);
    let dh3_bytes = point_to_bytes::<C>(&dh3);

    // Concatenate all DH values as input to HKDF
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&dh1_bytes);
    ikm.extend_from_slice(&dh2_bytes);
    ikm.extend_from_slice(&dh3_bytes);

    // Derive session key using HKDF
    let session_key = hkdf_expand(&ikm, b"OPAQUE-3DH-SessionKey", 32)?;

    Ok(session_key)
}

/// 3DH Server-side key derivation
///
/// Inputs:
/// - b: server's long-term secret key (lsk_s)
/// - y: server's ephemeral secret key (esk_s)
/// - A: client's long-term public key (lpk_c)
/// - X: client's ephemeral public key (epk_c)
///
/// Computes: SK = HKDF(X^b, X^y, A^y)
pub fn triple_dh_server<C>(
    server_long_secret: &C::Scalar,      // b
    server_ephemeral_secret: &C::Scalar, // y
    client_long_public: &[u8],           // A (bytes)
    client_ephemeral_public: &[u8],      // X (bytes)
) -> Result<Vec<u8>, OpaqueError>
where
    C: CurveArithmetic,
    ProjectivePoint<C>: GroupEncoding,
    <C as CurveArithmetic>::Scalar: PrimeField,
{
    // Deserialize client's public keys
    let A = bytes_to_point::<C>(client_long_public)?;      // lpk_c
    let X = bytes_to_point::<C>(client_ephemeral_public)?;  // epk_c

    // Compute the three DH values:
    // dh1 = X^b (client ephemeral, server long-term)
    let dh1 = X * server_long_secret;

    // dh2 = X^y (both ephemeral)
    let dh2 = X * server_ephemeral_secret;

    // dh3 = A^y (client long-term, server ephemeral)
    let dh3 = A * server_ephemeral_secret;

    // Serialize all DH values
    let dh1_bytes = point_to_bytes::<C>(&dh1);
    let dh2_bytes = point_to_bytes::<C>(&dh2);
    let dh3_bytes = point_to_bytes::<C>(&dh3);

    // Concatenate all DH values as input to HKDF
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&dh1_bytes);
    ikm.extend_from_slice(&dh2_bytes);
    ikm.extend_from_slice(&dh3_bytes);

    // Derive session key using HKDF
    let session_key = hkdf_expand(&ikm, b"OPAQUE-3DH-SessionKey", 32)?;

    Ok(session_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::NistP256;
    use elliptic_curve::{Field, ops::MulByGenerator};

    type Curve = NistP256;

    #[test]
    fn test_3dh_protocol() {
        // Client generates keys
        let a = <Curve as CurveArithmetic>::Scalar::random(&mut rand_core::OsRng); // lsk_c
        let A = ProjectivePoint::<Curve>::mul_by_generator(&a);                     // lpk_c
        let x = <Curve as CurveArithmetic>::Scalar::random(&mut rand_core::OsRng); // esk_c
        let X = ProjectivePoint::<Curve>::mul_by_generator(&x);                     // epk_c

        // Server generates keys
        let b = <Curve as CurveArithmetic>::Scalar::random(&mut rand_core::OsRng); // lsk_s
        let B = ProjectivePoint::<Curve>::mul_by_generator(&b);                     // lpk_s
        let y = <Curve as CurveArithmetic>::Scalar::random(&mut rand_core::OsRng); // esk_s
        let Y = ProjectivePoint::<Curve>::mul_by_generator(&y);                     // epk_s

        // Serialize public keys
        use crate::crypto::primitives::point_to_bytes;
        let A_bytes = point_to_bytes::<Curve>(&A);
        let B_bytes = point_to_bytes::<Curve>(&B);
        let X_bytes = point_to_bytes::<Curve>(&X);
        let Y_bytes = point_to_bytes::<Curve>(&Y);

        // Client computes session key
        let sk_client = triple_dh_client::<Curve>(&a, &x, &B_bytes, &Y_bytes)
            .expect("Client 3DH should succeed");

        // Server computes session key
        let sk_server = triple_dh_server::<Curve>(&b, &y, &A_bytes, &X_bytes)
            .expect("Server 3DH should succeed");

        // Both should derive the same session key
        assert_eq!(sk_client, sk_server, "Session keys should match");
        assert_eq!(sk_client.len(), 32, "Session key should be 32 bytes");
    }

    #[test]
    fn test_3dh_different_keys_different_sessions() {
        // First session
        let a1 = <Curve as CurveArithmetic>::Scalar::random(&mut rand_core::OsRng);
        let A1 = ProjectivePoint::<Curve>::mul_by_generator(&a1);
        let x1 = <Curve as CurveArithmetic>::Scalar::random(&mut rand_core::OsRng);

        let b1 = <Curve as CurveArithmetic>::Scalar::random(&mut rand_core::OsRng);
        let B1 = ProjectivePoint::<Curve>::mul_by_generator(&b1);
        let y1 = <Curve as CurveArithmetic>::Scalar::random(&mut rand_core::OsRng);
        let Y1 = ProjectivePoint::<Curve>::mul_by_generator(&y1);

        use crate::crypto::primitives::point_to_bytes;
        let B1_bytes = point_to_bytes::<Curve>(&B1);
        let Y1_bytes = point_to_bytes::<Curve>(&Y1);

        let sk1 = triple_dh_client::<Curve>(&a1, &x1, &B1_bytes, &Y1_bytes).unwrap();

        // Second session with different ephemeral keys
        let x2 = <Curve as CurveArithmetic>::Scalar::random(&mut rand_core::OsRng);
        let y2 = <Curve as CurveArithmetic>::Scalar::random(&mut rand_core::OsRng);
        let Y2 = ProjectivePoint::<Curve>::mul_by_generator(&y2);
        let Y2_bytes = point_to_bytes::<Curve>(&Y2);

        let sk2 = triple_dh_client::<Curve>(&a1, &x2, &B1_bytes, &Y2_bytes).unwrap();

        // Different ephemeral keys should produce different session keys
        assert_ne!(sk1, sk2, "Different ephemeral keys should produce different session keys");
    }
}