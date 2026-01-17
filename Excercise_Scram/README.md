# SCRAM Protocol Implementation

A secure implementation of the SCRAM (Salted Challenge Response Authentication Mechanism) protocol with TLS channel binding in Rust.

## Overview

This project implements a complete SCRAM authentication system that combines:
- **TLS 1.3-style handshake** with Diffie-Hellman key exchange
- **SCRAM authentication** with password hashing (PBKDF2)
- **Channel binding** to prevent man-in-the-middle attacks

## Quick Start
- cd into the project directory
- Run `cargo build` to compile the project
- Run `cargo test` to execute the test suite 
- First, create the password file and add users:
```bash
cargo run --example setup_password_file
```
- Then, start the scram protocol:
```bash
cargo run
```