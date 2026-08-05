//! Library surface of the x402 verifier.
//!
//! Only the client lives here: the server modules are binary-local, but the
//! payment client is shared by `x402-pay` and `x402-demo`.

pub mod payclient;
