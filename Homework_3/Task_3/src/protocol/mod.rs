//! Protocol implementations for OPAQUE

pub mod registration;


// Re-export main types
pub use registration::{
    ClientRegistration,
    ServerRegistration,
    RegistrationRequest,
    RegistrationResponse,
};

// pub use login::{
//    ClientLogin,
//    ServerLogin,
//    LoginRequest,
//    LoginResponse,
// };