use Task_3::{
    protocol::{
        registration::{ClientRegistration, ServerRegistration},
        login::{ClientLogin, ServerLogin},
    },
    server::Database,
    types::{Username, Password},
};

type Curve = p256::NistP256;
type Expander = elliptic_curve::hash2curve::ExpandMsgXmd<sha2::Sha256>;

fn main() -> anyhow::Result<()> {
    println!("\n=== OPAQUE Protocol Demo ===\n");

    let mut database = Database::new();

    // ========================================================================
    // REGISTRATION
    // ========================================================================

    println!("--- REGISTRATION PHASE ---\n");

    let username = Username::from("alice");
    let password = Password::from("MySecurePassword123");

    println!("User: {}", username.0);
    println!("Password: {}\n", password.0);

    // Client creates registration request
    println!("[Client] Creating registration request");
    let reg_request = ClientRegistration::<Curve>::create_request(
        username.clone(),
        password.clone(),
    );

    // Server processes registration
    println!("[Server] Processing registration");
    let record = ServerRegistration::<Curve, Expander>::process_request(reg_request)?;
    println!("         - Generated salt");
    println!("         - Computed rw = H(pw, h(pw)^s)");
    println!("         - Generated AKE key pairs");
    println!("         - Encrypted client keys");

    // Server stores in database
    database.store(record)?;
    println!("[Server] Stored user record\n");
    println!("Registration complete!\n");

    // ========================================================================
    // LOGIN (CORRECT PASSWORD)
    // ========================================================================

    println!("--- LOGIN PHASE ---\n");

    // Stage 1: OPRF
    println!("[Client] Stage 1: OPRF");
    println!("         - Blinding password: h(pw)^α");
    let (client, login_req1) = ClientLogin::<Curve>::start::<Expander>(
        username.clone(),
        password.clone(),
    )?;

    println!("[Server] Processing OPRF request");
    println!("         - Applying salt: h(pw)^(α·s)");
    println!("         - Generating ephemeral keys");
    let (server, login_resp1) = ServerLogin::<Curve>::process_request(
        login_req1,
        &database,
    )?;

    // Stage 2: AKE (3DH)
    println!("[Client] Stage 2: AKE (3DH)");
    println!("         - Unblinding: h(pw)^s");
    println!("         - Computing rw = H(pw, h(pw)^s)");
    println!("         - Decrypting AKE keys");
    println!("         - Computing session key via 3DH");
    let (client, login_req2) = client.process_response1(login_resp1)?;

    println!("[Server] Computing session key via 3DH");
    println!("         - Verifying client MAC");
    let (server, login_resp2) = server.process_request2(login_req2)?;

    // Stage 3: Key Confirmation
    println!("[Client] Stage 3: Key Confirmation");
    println!("         - Verifying server MAC");
    let client_sk = client.finalize(login_resp2)?;

    let server_sk = server.get_session_key()?;

    // Verify both have same session key
    assert_eq!(client_sk.0, server_sk.0);
    println!("\nLogin successful!");
    println!("Session key (first 16 bytes): {}\n", hex::encode(&client_sk.0[..16]));

    // ========================================================================
    // LOGIN (WRONG PASSWORD)
    // ========================================================================

    println!("--- LOGIN WITH WRONG PASSWORD ---\n");

    let wrong_password = Password::from("WrongPassword");
    println!("Attempting login with: {}\n", wrong_password.0);

    println!("[Client] Starting OPRF with wrong password");
    let (client_wrong, login_req1_wrong) = ClientLogin::<Curve>::start::<Expander>(
        username.clone(),
        wrong_password,
    )?;

    println!("[Server] Processing OPRF (server doesn't know password is wrong)");
    let (server_wrong, login_resp1_wrong) = ServerLogin::<Curve>::process_request(
        login_req1_wrong,
        &database,
    )?;

    println!("[Client] Decrypting with wrong rw (produces garbage keys)");
    match client_wrong.process_response1(login_resp1_wrong) {
        Ok((client_ake, login_req2_wrong)) => {
            println!("[Server] Verifying MAC...");
            match server_wrong.process_request2(login_req2_wrong) {
                Ok(_) => println!("ERROR: Should have failed!"),
                Err(_) => println!("         - MAC verification FAILED"),
            }
        }
        Err(_) => println!("         - Decryption FAILED"),
    }

    println!("\nLogin failed (as expected)!\n");
    Ok(())
}