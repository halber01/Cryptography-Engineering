use anyhow::Result;
use scram_protocol::{PasswordFile, User, crypto::pbkdf2};
use std::io::{self, Write};

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║           Password File Setup Tool                        ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    let pw_file = PasswordFile::new("examples/password_file.txt");
    pw_file.init()?;

    println!("Password file created: password_file.txt\n");

    loop {
        println!("Add a new user? (y/n): ");
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;

        if answer.trim().to_lowercase() != "y" {
            break;
        }

        // Get username
        print!("Username: ");
        io::stdout().flush()?;
        let mut username = String::new();
        io::stdin().read_line(&mut username)?;
        let username = username.trim().to_string();

        // Get password
        print!("Password: ");
        io::stdout().flush()?;
        let mut password = String::new();
        io::stdin().read_line(&mut password)?;
        let password = password.trim();

        // Get iterations (or use default)
        print!("Iterations (default 10000): ");
        io::stdout().flush()?;
        let mut iterations_str = String::new();
        io::stdin().read_line(&mut iterations_str)?;
        let iterations = if iterations_str.trim().is_empty() {
            10000
        } else {
            iterations_str.trim().parse()?
        };

        // Generate salt
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let salt: Vec<u8> = (0..16).map(|_| rng.r#gen()).collect();

        // Compute password hash
        println!("Computing password hash (this may take a moment)...");
        let password_hash = pbkdf2::iterate_hash_with_salt(
            password.as_bytes(),
            &salt,
            iterations,
        )?;

        // Encode to base64
        let salt_b64 = base64::encode(&salt);
        let hash_b64 = base64::encode(&password_hash);

        // Create user
        let user = User::new(
            username.clone(),
            salt_b64,
            iterations,
            hash_b64,
        );

        // Add to file
        pw_file.add_user(&user)?;

        println!("✓ User '{}' added successfully!\n", username);
    }

    println!("\n✓ Password file setup complete!");
    println!("Users can now authenticate using: cargo run\n");

    Ok(())
}