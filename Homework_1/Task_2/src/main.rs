mod crypto;
mod io;
mod encode;

use rand::Rng;
use anyhow::Result;
use crypto::{dhke, hkdf, aead, keyExtract};
use rand::{rngs::OsRng, RngCore};
use encode::encode_b64::b64;
use io::readline::read_line_prompt;
use crypto::signdemo::{keygen, sign, verify};
use base64::{engine::general_purpose, Engine as _};

fn main() {
    let nonce_c: [u8; 32] = rand::random();
    let client = dhke::DHkeypair::keygen();

    let nonce_s: [u8; 32] = rand::random();
    let server = dhke::DHkeypair::keygen();

    let shared_secret_client = dhke::shared_secret(client.sk, &server.pk);
    let shared_secret_server = dhke::shared_secret(server.sk, &client.pk);

    /// Server Key Scheule 1
    let (k_1_server_c, k_1_server_s) = keyExtract::KeySchedule_1(&shared_secret_server);
}
