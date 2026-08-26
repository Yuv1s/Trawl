//! Starts the scanner.
//!
//! Binds loopback only, never a public interface: the scanner is for the person
//! who launched it, reached from their own browser, and has no business being
//! visible to the rest of the network. The port is 8099 unless `PORT` says
//! otherwise, and it is printed on start so the frontend's default matches.
//!
//! `--allow-local` (or `TRAWL_ALLOW_LOCAL` set) lets it reach targets on this
//! machine and on private networks, for challenges hosted locally. It is off by
//! default, because a scanner that reaches inward is the danger it guards
//! against, so turning it on is a choice the person starting it makes.

use std::net::SocketAddr;
use trawl_scan::server::Config;

fn required_environment(name: &str) -> Result<String, String> {
    match std::env::var(name) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => Err(format!("{name} is required")),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
    }
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8099u16);

    let allow_local = std::env::args().any(|arg| arg == "--allow-local")
        || std::env::var_os("TRAWL_ALLOW_LOCAL").is_some();

    let config = match required_environment("TRAWL_TOKEN").and_then(|token| {
        required_environment("TRAWL_ORIGIN")
            .and_then(|origin| Config::new(allow_local, token, origin))
    }) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("trawl-scan refused to start: {error}.");
            eprintln!(
                "set TRAWL_TOKEN to a random token of at least 32 characters and TRAWL_ORIGIN to the exact Trawl page origin."
            );
            std::process::exit(2);
        }
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("trawl-scan could not bind {addr}: {error}");
            eprintln!("something else may be using port {port}; set PORT to pick another.");
            std::process::exit(1);
        }
    };

    println!("trawl-scan is listening on http://{addr}");
    println!("leave this running; the Trawl page will connect on its own.");
    if allow_local {
        println!("local mode: targets on this machine and private networks are allowed.");
    }

    if let Err(error) = axum::serve(listener, trawl_scan::server::app(config)).await {
        eprintln!("trawl-scan stopped: {error}");
        std::process::exit(1);
    }
}
