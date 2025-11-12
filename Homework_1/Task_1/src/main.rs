mod crypto;
mod io;
mod encode;

use anyhow::Result;
use crypto::{dhke, hkdf, aead};
use rand::{rngs::OsRng, RngCore};
use encode::encode_b64::b64;
use io::readline::read_line_prompt;
use crypto::signdemo::{keygen, sign, verify};
use base64::{engine::general_purpose, Engine as _};

fn main() -> Result<()> {
    println!("DHKE + HKDF + AEAD demo");
    println!(" - DH: X25519 (ephemeral/ephemeral in one process)");
    println!(" - KDF: HKDF-SHA3-256");
    println!(" - AEAD: AES-256-GCM");
    println!("Type 'exit' to quit.\n");

    // DHKE
    let alice = dhke::DHkeypair::keygen();
    let bob   = dhke::DHkeypair::keygen();
    println!("Alice's pk (Base64): {}", b64(&alice.pk.to_bytes()));
    println!("Bob's pk (Base64): {}", b64(&bob.pk.to_bytes()));
    let ss_alice = dhke::shared_secret(alice.sk, &bob.pk);
    let ss_bob   = dhke::shared_secret(bob.sk, &alice.pk);
    println!("Shared secret (Base64): {}", b64(&ss_alice));

    println!("\n Signing demo using");
    // sign sigma_a
    let keypair_alice = keygen();
    let sigma_a_sk_bytes = keypair_alice.sk.to_bytes();        // [u8; 32]
    let sigma_a_pk_bytes = keypair_alice.pk.to_bytes();        // [u8; 32]
    println!("Public Key signing pair Alice (Base64): {}", b64(&sigma_a_sk_bytes));
    println!("Secret Key signing pair Alice (Base64): {}", b64(&sigma_a_pk_bytes));

    // sign sigma_b
    let keypair_bob = keygen();
    let sigma_b_sk_bytes = keypair_bob.sk.to_bytes();        // [u8; 32]
    let sigma_b_pk_bytes = keypair_bob.pk.to_bytes();        // [u8; 32]
    println!("Public Key signing pair Bob (Base64): {}", b64(&sigma_a_sk_bytes));
    println!("Secret Key signing pair Bob (Base64): {}", b64(&sigma_a_pk_bytes));


    // Sign sigma_a
    let m = alice.pk.to_bytes() ;
    let sig_a = sign(&keypair_alice.sk, &alice.pk.to_bytes());     // ed25519_dalek::Signature
    let sig_a_bytes: [u8; 64] = sig_a.to_bytes();
    println!("Signature alice (Base64): {}", b64(&sig_a_bytes));

    // Sign sigma_b
    let sig_b = sign(&keypair_bob.sk,  &alice.pk.to_bytes());        // A ed25519_dalek::Signature
    let sig_b_bytes: [u8; 64] = sig_b.to_bytes();
    println!("Signature bob (Base64): {}", b64(&sig_b_bytes));

     // Verify the same message
    let ok_alice = verify(&keypair_bob.pk,  &alice.pk.to_bytes(), &sig_b);
    println!("Verify (same message): {ok_alice}");
    let ok_bob = verify(&keypair_alice.pk,  &alice.pk.to_bytes(), &sig_a);
    println!("Verify (same message): {ok_bob}");
    
    Ok(())
}