//! Trawl's web reconnaissance service.
//!
//! The offline half of Trawl reads a file you already have. This half reaches a
//! site you point it at, which is the one thing the rest of the tool refuses to
//! do, so it lives apart: its own crate, its own binary, and above all its own
//! gate on where it is allowed to go.
//!
//! Built in the order risk demands. [`guard`] comes first and alone, because a
//! fetcher without it is an attack on its own network. [`fetch`] enforces the
//! guard on every request, and [`server`] is the thin HTTP surface the frontend
//! polls and scans through.

pub mod active;
pub mod crawl;
pub mod decode;
pub mod fetch;
pub mod guard;
pub mod server;
