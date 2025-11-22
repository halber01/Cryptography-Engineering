mod crypto;
mod io;
mod encode;

use rand::Rng;
use anyhow::Result;
use crypto::{dhke, hkdf, aead, key_extract, hmac};
use crypto::key_extract::hashValue;
use rand::{rngs::OsRng, RngCore};
use encode::encode_b64::b64;
use io::readline::read_line_prompt;
use crypto::signdemo::{keygen, sign, verify};
use base64::{engine::general_purpose, Engine as _};

fn main() {
    let nonce_c: [u8; 32] = rand::random(); // nonce_c
    let client = dhke::DHkeypair::keygen(); // X = g^x

    let nonce_s: [u8; 32] = rand::random(); // nonce_s
    let server = dhke::DHkeypair::keygen(); // Y = g^y

    let shared_secret_client = dhke::shared_secret(client.sk, &server.pk); // X^y
    let shared_secret_server = dhke::shared_secret(server.sk, &client.pk); // Y^x

    // Server Hello + ServerKE Phase
    let (k_1_server_c, k_1_server_s) = key_extract::KeySchedule_1(&shared_secret_server); // K_1_server_c, K_1_server_s

    // ServerCert + ServerFinished Phase
    let server_cert: [u8; 32] = rand::random();
    let sigma_s_keys = keygen();
    let server_sha = hashValue(&[nonce_c, client.pk.to_bytes(), nonce_s, server.pk.to_bytes()].concat());
    let sigma_s = sign(&sigma_s_keys.sk, &server_sha); // sign sigma_s

    let (k_2_server_c, k_2_server_s) = key_extract::KeySchedule_2(&nonce_c, &client.pk.to_bytes(), &nonce_s, &server.pk.to_bytes(), &shared_secret_server); // K_2_server_c, K_2_server_s

    let sigma_hash = hashValue(&sigma_s.to_bytes());
    let hash = hashValue(&[
        &nonce_c[..],
        &client.pk.to_bytes()[..],
        &nonce_s[..],
        &server.pk.to_bytes()[..],
    ].concat());
    let mac_s = hmac::compute_hmac_sha256(&k_2_server_s, &hash);
    let (k_3_server_c, k_3_server_s) = key_extract::KeySchedule_3(&nonce_c, &client.pk.to_bytes(), &nonce_s, &server.pk.to_bytes(), &shared_secret_server, &sigma_s.to_bytes(), &server_cert, &mac_s, ); // K_3_server_c, K_3_server_s

    let plaintext_s = [&server.pk.to_bytes()[..], &sigma_s.to_bytes()[..], &mac_s[..]].concat();
    let aead_nonce_s: [u8; 12] = nonce_s[..12].try_into().unwrap();
    let aead_ct_to_server = aead::encrypt(&k_1_server_s, &aead_nonce_s, &plaintext_s, b"");

    // ClientFinished Phase
    let (k_1_client_c, k_1_client_s) = key_extract::KeySchedule_1(&shared_secret_client); // K_1_client_c, K_1_client
    let (k_2_client_c, k_2_client_s) = key_extract::KeySchedule_2(&nonce_c, &client.pk.to_bytes(), &nonce_s, &server.pk.to_bytes(), &shared_secret_client); // K_2_client_c, K_2_client_s
    let (k_3_client_c, k_3_client_s) = key_extract::KeySchedule_3(&nonce_c, &client.pk.to_bytes(), &nonce_s, &server.pk.to_bytes(), &shared_secret_client, &sigma_s.to_bytes(), &server_cert, &mac_s, ); // K_3_client_c, K_3_client_s

    println!("Client's computed K_3_client_c: {:?}", k_3_client_c);
    println!("Server's computed K_3_server_c: {:?}", k_3_server_c);
}