use Task_3::{
    protocol::registration::{ClientRegistration, ServerRegistration},
    server::Database,
    types::{Username, Password},
};

// Type aliases for convenience
type Curve = p256::NistP256;
type Expander = elliptic_curve::hash2curve::ExpandMsgXmd<sha2::Sha256>;

fn main() -> anyhow::Result<()> {
    println!("=== OPAQUE Registration Demo ===\n");

    // Initialize server database
    let mut db = Database::new();

    // User wants to register
    let username = Username::from("alice");
    let password = Password::from("secure_password_123");

    println!("1. Client creates registration request");
    println!("   Username: {}", username.0);
    println!("   Password: {}\n", password.0);

    // CLIENT SIDE: Create registration request
    let request = ClientRegistration::<Curve>::create_request(
        username.clone(),
        password.clone(),
    );

    // SERVER SIDE: Process registration
    println!("2. Server processes registration...");
    let record = ServerRegistration::<Curve, Expander>::process_request(request)?;

    println!("   - Generated random salt");
    println!("   - Computed rw = H(pw, h(pw)^s)");
    println!("   - Generated AKE key pairs");
    println!("   - Encrypted client keys with rw\n");

    // SERVER SIDE: Store in database
    db.store(record)?;

    println!("4. Server stored record in database");
    println!("   Total users: {}\n", db.count());

    // Verify we can retrieve it
    let retrieved = db.get(&username)?;
    println!("5. Verification: Retrieved user '{}'", retrieved.username.0);
    println!("   Salt length: {} bytes", retrieved.salt.0.len());
    println!("   Encrypted bundle length: {} bytes",
             retrieved.client_encrypted_key_bundle.ciphertext.len());

    println!("\n Registration complete!");

    Ok(())
}