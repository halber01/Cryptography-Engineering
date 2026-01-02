mod crypto;
mod io;
mod encode;

use rand::Rng;
use anyhow::Result;
use crypto::{dhke, hkdf, aead, key_extract, hmac, vec_bytes};
use crypto::key_extract::hashValue;
use rand::{rngs::OsRng, RngCore};
use encode::encode_b64::b64;
use io::readline::read_line_prompt;
use base64::{engine::general_purpose, Engine as _};
use ml_kem::{MlKem768, KemCore, EncodedSizeUser};
use kem::{Encapsulate, Decapsulate};
use ml_dsa::{MlDsa65, KeyGen, signature::{Keypair, Signer, Verifier}};
use rand::thread_rng;
use ed25519_dalek::ed25519::SignatureEncoding;

fn main() {

    let mut rng = thread_rng();

    // Client keypair
    let nonce_c: [u8; 32] = rand::random(); // nonce_c
    let (dk_c, ek_c) = MlKem768::generate(&mut rng);

    // Server keypair
    let nonce_s: [u8; 32] = rand::random(); // nonce_s
    let (dk_s, ek_s) = MlKem768::generate(&mut rng);

    // Certificiate Authority (CA)
    let kp_ca = MlDsa65::key_gen(&mut rng);

    let ek_s_bytes = ek_s.as_bytes();
    let sigma_ca = kp_ca.signing_key().sign(ek_s_bytes.as_ref());
    assert!(kp_ca.verifying_key().verify(&ek_s_bytes, &sigma_ca).is_ok());

    let server_cert: Vec<u8> = [ek_s_bytes.as_ref(), &sigma_ca.to_bytes()[..]].concat();

    // Encapsulate to create shared secret and ciphertext
    let (ct_s, k_s_send) = ek_s.encapsulate(&mut rng).unwrap();

    // Decapsulate to recover shared secret
    let k_a_rec = dk_s.decapsulate(&ct_s).unwrap();
    assert_eq!(k_s_send, k_a_rec);

    // Server Hello + ServerKE Phase
    let (k_1_server_c, k_1_server_s) = key_extract::KeySchedule_1(&k_s_send); // K_1_server_c, K_1_server_s

    // ServerCert + ServerFinished Phase
    let kp_s = MlDsa65::key_gen(&mut rng);
    let ek_c_bytes_sha_binding: &[u8] = &ek_c.as_bytes();
    let ek_c_bytes_sha: &[u8] = ek_c_bytes_sha_binding.as_ref();
    let ek_s_bytes_sha_binding: &[u8] = &ek_s.as_bytes();
    let ek_s_bytes_sha: &[u8] = ek_s_bytes_sha_binding.as_ref();
    let server_sha = hashValue(&[&nonce_c[..], ek_c_bytes_sha, &nonce_s[..], ek_s_bytes_sha].concat());
    let sigma_s = kp_s.signing_key().sign(&server_sha);


    let (k_2_server_c, k_2_server_s) = key_extract::KeySchedule_2(&nonce_c, ek_c_bytes_sha, &nonce_s, ek_s_bytes_sha, &k_s_send); // K_2_server_c, K_2_server_s
    let sigma_s_bytes = sigma_s.to_bytes();
    //let sigma_hash = hashValue(&sigma_s);
    let hash_server = hashValue(&[
         &nonce_c[..],
         &ek_c_bytes_sha[..],
         &nonce_s[..],
         &ek_s_bytes_sha[..],
         &sigma_s_bytes.as_ref(),
         &server_cert[..],
         b"ServerMAC"
     ].concat());

     let mac_s = hmac::compute_hmac_sha256(&k_2_server_s, &hash_server);
     let (k_3_server_c, k_3_server_s) = key_extract::KeySchedule_3(&nonce_c, ek_c_bytes_sha, &nonce_s, ek_s_bytes_sha, &k_s_send, &sigma_s_bytes.as_ref(), &server_cert, &mac_s, ); // K_3_server_c, K_3_server_s

     let plaintext_s = [&server_cert, &sigma_s.to_bytes()[..], &mac_s[..]].concat();
     let aead_nonce_s: [u8; 12] = nonce_s[..12].try_into().unwrap();
     let aead_ct_from_server = aead::encrypt(&k_1_server_s, &aead_nonce_s, &plaintext_s, b"");

     // ClientFinished Phase
     let (k_1_client_c, k_1_client_s) = key_extract::KeySchedule_1(&k_a_rec); // K_1_client_c, K_1_client
     let (k_2_client_c, k_2_client_s) = key_extract::KeySchedule_2(&nonce_c, ek_c_bytes_sha, &nonce_s, ek_s_bytes_sha, &k_s_send); // K_2_client_c, K_2_client_s
     let (k_3_client_c, k_3_client_s) = key_extract::KeySchedule_3(&nonce_c, ek_c_bytes_sha, &nonce_s, ek_s_bytes_sha, &k_s_send, &sigma_s_bytes.as_ref(), &server_cert, &mac_s, ); // K_3_client_c, K_3_client_s

     assert_eq!(k_1_client_c, k_1_server_c);
     assert_eq!(k_2_client_c, k_2_server_c);
     assert_eq!(k_3_client_c, k_3_server_c);

     let decrypted_aead_from_server = aead::decrypt(&k_1_client_s, &aead_nonce_s, &aead_ct_from_server.unwrap(), b"").unwrap();
     let (cert_pk, sigma_s_verify, mac_s_verify) =vec_bytes::split_decrypted(decrypted_aead_from_server).unwrap();

     assert_eq!(cert_pk, server_cert.as_slice());
     assert_eq!(sigma_s_verify, sigma_s_bytes.as_ref());
     assert_eq!(mac_s_verify, mac_s);
     let hash_client = hashValue(&[
         &nonce_c[..],
         &ek_c_bytes_sha[..],
         &nonce_s[..],
         &ek_s_bytes_sha[..],
         &sigma_s_bytes.as_ref(),
         &server_cert[..],
         b"ClientMAC"
     ].concat());
     let mac_s = hmac::compute_hmac_sha256(&k_2_client_c, &hash_client);

     let aead_nonce_c: [u8; 12] = nonce_c[..12].try_into().unwrap();
     let aead_ct_from_client = aead::encrypt(&k_1_client_c, &aead_nonce_c, &mac_s[..], b"");
     let decrypted_aead_from_client = aead::decrypt(&k_1_server_c, &aead_nonce_c, &aead_ct_from_client.unwrap(), b"").unwrap();
     assert_eq!(decrypted_aead_from_client, mac_s);

    // At this point, both client and server have authenticated each other and established shared keys.
     println!("Mutual authentication successful. Shared keys established.");

}