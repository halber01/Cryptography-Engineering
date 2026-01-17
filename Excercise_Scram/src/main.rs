use anyhow::Result;
use scram_protocol::{
    PasswordFile,
    tls::handshake::{TlsClient, TlsServer},
    protocol::{ScramClient, ScramServer},
    crypto::sign,
};
use std::io::{self, Write};

fn tls_session() -> Result<()> {
    // 1. Setup
    let ca_keypair = sign::keygen();
    let client = TlsClient::new();
    let mut server = TlsServer::new(ca_keypair);

    // 2. ClientHello
    let (nonce_c, client_pk) = client.client_hello();

    // 3. ServerHello - returns ServerHello AND shared_secret

    let server_hello = server.server_hello(&nonce_c, &client_pk)?;



    // 4. ClientFinished
    let (client_finished, client_session) = client.process_server_hello(&server_hello)?;

    // 5. Server creates session - needs shared_secret
    let server_session = server.process_client_finished(&nonce_c, &client_pk, &client_finished)?;
    Ok(())
}



fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║             SCRAM Protocol Authentication                  ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Get user credentials
    let username = prompt_input("Enter username: ")?;
    let password = prompt_password("Enter password: ")?;

    println!("\n[1/3] Loading password file...");
    let pw_file = PasswordFile::new("examples/password_file.txt");
    if !pw_file.exists() {
        return Err(anyhow::anyhow!(
            "Password file 'password_file.txt' not found. Please create it first."
        ));
    }
    println!("✓ Password file loaded");

    println!("\n[2/3] Establishing TLS connection...");

    // TLS Handshake
    let ca_keypair = sign::keygen();
    let tls_client = TlsClient::new();
    let mut tls_server = TlsServer::new(ca_keypair);

    // ClientHello
    let (nonce_c, client_pk) = tls_client.client_hello();

    // ServerHello
    let server_hello = tls_server.server_hello(&nonce_c, &client_pk)?;

    // ClientFinished
    let (client_finished, client_tls_session) = tls_client.process_server_hello(&server_hello)?;

    // Server creates session
    let server_tls_session = tls_server.process_client_finished(
        &nonce_c,
        &client_pk,
        &client_finished
    )?;

    println!("✓ TLS connection established");

    println!("\n[3/3] Running SCRAM authentication...");

    // SCRAM Authentication
    let scram_client = ScramClient::new(
        username.clone(),
        password.into_bytes(),
        client_tls_session,
    );

    let mut scram_server = ScramServer::new(
        pw_file,
        server_tls_session,
    );

    // ClientFirst
    let client_first = scram_client.client_first();

    // ServerFirst
    let server_first = scram_server.process_client_first(&client_first)?;

    // ClientFinal
    let (client_final, password_hash) = scram_client.process_server_first(&server_first)?;

    // ServerFinal
    let server_final = scram_server.process_client_final(&client_final, &server_first)?;

    // Verify server
    scram_client.verify_server_final(&server_final, &server_first, &password_hash)?;

    println!("✓ SCRAM authentication complete");

    // Success!
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║           🎉 Authentication Successful! 🎉                ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!("\nUser '{}' authenticated successfully.\n", username);

    Ok(())
}

/// Prompt for input
fn prompt_input(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim().to_string())
}

/// Prompt for password (hidden input on Unix)
fn prompt_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    // For Unix systems, use rpassword crate for hidden input
    // For now, simple version:
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;

    Ok(password.trim().to_string())
}