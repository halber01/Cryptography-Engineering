use sha2::{Sha256, Digest};
use hkdf::Hkdf;

pub fn hashValue(plaintext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(plaintext);
    let result = hasher.finalize();
    result.into()
}

pub fn KeySchedule_1(shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hs = DeriveHS(shared_secret);
    let k_1_c = hkdf_expand(&hs, &hashValue(b"ClientKE"));
    let k_1_s = hkdf_expand(&hs, &hashValue(b"ServerKE"));
    (k_1_c, k_1_s)
}

pub fn KeySchedule_2(nonce_c: &[u8], pk_A: &[u8], nonce_s: &[u8], pk_B: &[u8], shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hs = DeriveHS(shared_secret);

    let client_input = [nonce_c, pk_A, nonce_s, pk_B, b"ClientKC"].concat();
    let server_input = [nonce_c, pk_A, nonce_s, pk_B, b"ServerKC"].concat();

    let clientKC = hashValue(&client_input);
    let serverKC = hashValue(&server_input);

    let k_2_c = hkdf_expand(&hs, &clientKC);
    let k_2_s = hkdf_expand(&hs, &serverKC);

    (k_2_c, k_2_s)
}

pub fn KeySchedule_3(nonce_c: &[u8], pk_A: &[u8], nonce_s: &[u8], pk_B: &[u8], shared_secret: &[u8], sigma: &[u8], cert: &[u8], mac_s: &[u8]) -> ([u8; 32], [u8; 32]) {
    let zeros: [u8; 32] = [0u8; 32];
    let hs = DeriveHS(shared_secret);

    let dhs = hkdf_expand(&hs, &hashValue(b"DerivedHS"));
    let ms = hkdf_extract(&zeros, &dhs);

    let client_input = [nonce_c, pk_A, nonce_s, pk_B, sigma, cert, mac_s, b"ClientEnck"].concat();
    let server_input = [nonce_c, pk_A, nonce_s, pk_B, sigma, cert, mac_s, b"ServerEnck"].concat();

    let clientSKH = hashValue(&client_input);
    let serverSKH = hashValue(&server_input);

    let k_3_c = hkdf_expand(&ms, &clientSKH);
    let k_3_s = hkdf_expand(&ms, &serverSKH);

    (k_3_c, k_3_s)
}

pub fn DeriveHS(shared_secret: &[u8]) -> [u8; 32] {
    let zeros: [u8; 32] = [0u8; 32];
    let es = hkdf_extract(&zeros, &zeros);
    let dES = hkdf_expand(&es, &hashValue(b"DerivedES"));
    let hs = hkdf_extract(&dES, shared_secret);
    hs
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut prk = [0u8; 32];
    hkdf.expand(&[], &mut prk).expect("HKDF expand failed");
    prk
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).expect("Invalid PRK");
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}