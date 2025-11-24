// rust
use std::convert::TryInto;

const PK_LEN: usize = 96;
const SIG_LEN: usize = 64;
const MAC_LEN: usize = 32;
pub fn split_decrypted(
    plaintext: Vec<u8>,
) -> Result<([u8; PK_LEN], [u8; SIG_LEN], [u8; MAC_LEN]), String> {
    let total = PK_LEN + SIG_LEN + MAC_LEN;
    if plaintext.len() != total {
        return Err(format!("Unerwartete Klartextlänge: got {}, expected {}", plaintext.len(), total));
    }

    let pk: [u8; PK_LEN] = plaintext[0..PK_LEN].try_into().map_err(|_| "PK slice to array failed".to_string())?;
    let sig: [u8; SIG_LEN] = plaintext[PK_LEN..PK_LEN + SIG_LEN].try_into().map_err(|_| "SIG slice to array failed".to_string())?;
    let mac: [u8; MAC_LEN] = plaintext[PK_LEN + SIG_LEN..total].try_into().map_err(|_| "MAC slice to array failed".to_string())?;

    Ok((pk, sig, mac))
}

