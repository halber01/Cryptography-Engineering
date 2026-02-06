use sha3::{Digest, Sha3_256};
use std::fs::File;
use std::io::{BufRead, BufReader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = "8yQ28QbbPQYfvpta2FBSgsZTGZlFdVYMhn7ePNbaKV8=";
    let target_digest = base64::decode(target)?;

    // File opening and iterating over each line inside it
    let file = File::open("./dictionaries/Dictionary.txt")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let password = line?.trim().to_string();
        if password.is_empty() {
            continue;
        }
        // Hash the password
        let mut hasher = Sha3_256::new();
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();

        if digest.as_slice() == target_digest.as_slice() {
            println!("Found password: {}", password);
            return Ok(());
        }
    }

    println!("Password not found in the dictionary.");
    Ok(())
}