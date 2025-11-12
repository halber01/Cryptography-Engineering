use crypto::{dhke, aead};
use crypto::hkdf::{extract, expand};
use sha2::{Sha256, Digest};

pub fn hashValue(plaintext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(plaintext);
    let result = hasher.finalize();
}

pub fn KeySchedule_1(shared_secret) -> ([u8; 32], [u8; 32]) {
    let hs = DeriveHS(shared_secret);
    let k_1_c = hkdf::hkdf_expand(hs, None, hashValue(b"ClientKE"));
    let k_1_s = hkdf::hkdf_expand(hs, None, hashValue(b"ServerKE"));
    return (k_1_c, k_1_s)
}

pub fn KeySchedule_2(nonce_c: &[u8], pk_A: &[u8], nonce_s: &[u8], pk_B: &[u8], shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hs = DeriveHS(shared_secret);
    let clientKC = hashValue(&[nonce_c, pk_A, nonce_s, pk_B, b"ClientKC"].concat());
    let serverKC = hashValue(&[nonce_c, pk_A, nonce_s, pk_B, b"ServerKC"].concat());
    let k_2_c = hkdf::hkdf_expand(hs, None, clientKC);
    let k_2_s = hkdf::hkdf_expand(hs, None, serverKC);
    return (k_2_c, k_2_s);
}

pub fn KeySchedule_3(nonce_c: &[u8], pk_A: &[u8], nonce_s: &[u8], pk_B: &[u8], shared_secret: &[u8], sigma, cert, mac_s) -> ([u8; 32], [u8; 32]) {
    let zeros: [u8; 32] = [0u8; 32];
    let hs = DeriveHS(shared_secret);
    let dhs = hkdf::hkdf_expand(hs, hashValue("DerivedHS"));
    let ms = hkdf::hkdf_extract(&zeros, dhs);
    let clientSKH = hashValue(&[nonce_c, pk_A, nonce_s, pk_B, sigma, cert, mac_s, b"ClientEnck"].concat());
    let serverSKH = hashValue(&[nonce_c, pk_A, nonce_s, pk_B, sigma, cert, mac_s, b"ServerEnck"].concat());
    let k_3_c = hkdf::hkdf_expand(ms, None, clientKM);
    let k_3_s = hkdf::hkdf_expand(ms, None, serverKM);
    return (k_3_c, k_3_s);
}

pub fn DeriveHS(shared_secret) -> [u8; 32] {
    let zeros: [u8; 32] = [0u8; 32];
    let (es,hk) = hkdf_extract(&zeros, &zeros,)
    let dES = hkdf::hkdf_expand(es, Some(&zeros), hashValue(b"DerivedES"))
    let (hs, hk2) = hkdf_extract(&dES, hashValue(&shared_secret))
    return hs
}