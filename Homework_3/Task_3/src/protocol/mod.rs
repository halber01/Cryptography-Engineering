//! Protocol implementations for OPAQUE

pub mod registration;
pub mod login;

// Re-export main types
pub use registration::{
    ClientRegistration,
    ServerRegistration,
    RegistrationRequest,
    RegistrationResponse,
};

pub use login::{
    ClientLogin,
    ServerLogin,
    LoginRequest,
    LoginResponse1,
    LoginRequest2,
    LoginResponse2,
};