//! TLS metadata helpers shared by collectors.
//!
//! Parsing stops at the ClientHello. Nothing here inspects a ServerHello, a
//! certificate, or a key exchange.

mod client_hello;

pub use client_hello::{parse_client_hello, ClientHelloInfo, EchInfo, ParseError};
