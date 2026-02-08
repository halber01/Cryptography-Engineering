pub mod crypto;
pub mod protocol;
pub mod server;
pub mod types;
pub use types::{Username, Password, SessionKey};
pub use protocol::{
    registration::{RegistrationRequest, RegistrationResponse},
    //login::{LoginRequest, LoginResponse},
};
pub use server::database::Database;

pub use types::OpaqueError;

pub type Result<T> = std::result::Result<T, OpaqueError>;