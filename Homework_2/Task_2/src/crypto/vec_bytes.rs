// rust
use std::convert::TryInto;
use ml_dsa::{MlDsa65, Signature, EncodedSignature};

const PK_LEN: usize = 1184;
const SIG_LEN: usize = 3309;
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

pub fn split_cert(
    cert: Vec<u8>,
) -> Result<([u8; PK_LEN], [u8; SIG_LEN]), String> {
    if cert.len() != PK_LEN + SIG_LEN {
        return Err(format!("Unerwartete Zertifikatslänge: got {}, expected {}", cert.len(), PK_LEN + SIG_LEN));
    }

    let pk: [u8; PK_LEN] = cert[0..PK_LEN].try_into().map_err(|_| "PK slice to array failed".to_string())?;
    let sig: [u8; SIG_LEN] = cert[PK_LEN..PK_LEN + SIG_LEN].try_into().map_err(|_| "SIG slice to array failed".to_string())?;

    Ok((pk, sig))
}

pub fn split_and_verify_cert(
    cert: Vec<u8>,
) -> Result<([u8; PK_LEN], Signature<MlDsa65>), String> {
    let (pk, sig_bytes) = split_cert(cert)?;

    let encoded_sig = EncodedSignature::<MlDsa65>::from(sig_bytes);
    let signature = Signature::<MlDsa65>::decode(&encoded_sig)
        .ok_or("Failed to decode signature")?;
    Ok((pk, signature))
}
