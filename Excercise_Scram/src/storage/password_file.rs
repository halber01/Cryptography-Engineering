use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use anyhow::{Context, Result, anyhow};

use super::user::User;

/// Handles reading and writing to the password file
pub struct PasswordFile {
    path: PathBuf,
}

impl PasswordFile {
    /// Create a new PasswordFile handler
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Initialize the password file if it doesn't exist
    pub fn init(&self) -> Result<()> {
        if !self.path.exists() {
            let mut file = File::create(&self.path)
                .context("Failed to create password file")?;
            writeln!(file, "# Format: username,salt_base64,iterations,hash_base64")?;
        }
        Ok(())
    }

    /// Get a user by username
    pub fn get_user(&self, username: &str) -> Result<Option<User>> {
        let file = File::open(&self.path)
            .context("Failed to open password file")?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;

            // Skip comments and empty lines
            if line.trim().is_empty() || line.trim().starts_with('#') {
                continue;
            }

            let user = self.parse_line(&line)?;
            if user.username == username {
                return Ok(Some(user));
            }
        }

        Ok(None)
    }

    /// Get all users from the file
    pub fn get_all_users(&self) -> Result<Vec<User>> {
        let file = File::open(&self.path)
            .context("Failed to open password file")?;
        let reader = BufReader::new(file);

        let mut users = Vec::new();

        for line in reader.lines() {
            let line = line?;

            // Skip comments and empty lines
            if line.trim().is_empty() || line.trim().starts_with('#') {
                continue;
            }

            users.push(self.parse_line(&line)?);
        }

        Ok(users)
    }

    /// Add a new user to the file
    pub fn add_user(&self, user: &User) -> Result<()> {
        // Check if user already exists
        if self.get_user(&user.username)?.is_some() {
            return Err(anyhow!("User '{}' already exists", user.username));
        }

        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .context("Failed to open password file for writing")?;

        let line = format!(
            "{},{},{},{}\n",
            user.username,
            user.salt,
            user.iterations,
            user.password_hash
        );

        file.write_all(line.as_bytes())
            .context("Failed to write user to password file")?;

        Ok(())
    }

    /// Parse a single line into a User
    fn parse_line(&self, line: &str) -> Result<User> {
        let parts: Vec<&str> = line.split(',').collect();

        if parts.len() != 4 {
            return Err(anyhow!("Invalid line format: expected 4 fields, got {}", parts.len()));
        }

        Ok(User::new(
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].parse()
                .context("Failed to parse iterations")?,
            parts[3].to_string(),
        ))
    }

    /// Check if the password file exists
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}