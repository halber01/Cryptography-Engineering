//! Cryptographic primitives and operations

pub mod primitives;
pub mod hash2curve;
pub mod oprf;
pub mod ake;

pub use primitives::{
    random_scalar_bytes,
    sha3_256,
    sha3_512,
    hkdf_expand,
    hkdf_expand_two_keys,
    aead_encrypt,
    aead_decrypt,
    hmac_compute,
    hmac_verify,
    point_to_bytes,
    bytes_to_point,
};

pub use hash2curve::{
    hash2curve,
    hash2curve_demo,
    hash_password_to_curve,
};

pub use oprf::{
   OprfClient,
    OprfServer,
};

//pub use ake::{
//    triple_dh_client,
//    triple_dh_server,
//};