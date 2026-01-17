use scram_protocol::{PasswordFile, User};
use tempfile::NamedTempFile;
use std::io::Write;

#[test]
fn test_init_creates_file() {
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path();

    let pw_file = PasswordFile::new(path);
    pw_file.init().unwrap();

    assert!(pw_file.exists());
}

#[test]
fn test_add_and_get_user() {
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path();

    let pw_file = PasswordFile::new(path);
    pw_file.init().unwrap();

    let user = User::new(
        "Alice".to_string(),
        "salt123".to_string(),
        10000,
        "hash456".to_string(),
    );

    pw_file.add_user(&user).unwrap();

    let retrieved = pw_file.get_user("Alice").unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), user);
}

#[test]
fn test_get_nonexistent_user() {
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path();

    let pw_file = PasswordFile::new(path);
    pw_file.init().unwrap();

    let result = pw_file.get_user("NonExistent").unwrap();
    assert!(result.is_none());
}

#[test]
fn test_get_all_users() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "# Format: username,salt,iterations,hash").unwrap();
    writeln!(temp_file, "Alice,salt1,10000,hash1").unwrap();
    writeln!(temp_file, "Bob,salt2,20000,hash2").unwrap();

    let pw_file = PasswordFile::new(temp_file.path());

    let users = pw_file.get_all_users().unwrap();
    assert_eq!(users.len(), 2);
    assert_eq!(users[0].username, "Alice");
    assert_eq!(users[1].username, "Bob");
}

#[test]
fn test_duplicate_user_error() {
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path();

    let pw_file = PasswordFile::new(path);
    pw_file.init().unwrap();

    let user = User::new(
        "Alice".to_string(),
        "salt123".to_string(),
        10000,
        "hash456".to_string(),
    );

    pw_file.add_user(&user).unwrap();
    let result = pw_file.add_user(&user);

    assert!(result.is_err());
}