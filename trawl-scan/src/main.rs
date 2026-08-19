//! Starts the scanner.
//!
//! Binds loopback only, never a public interface: the scanner is for the person
//! who launched it, reached from their own browser, and has no business being
//! visible to the rest of the network. The port is 8099 unless `PORT` says
//! otherwise, and it is printed on start so the frontend's default matches.

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8099u16);

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

    if let Err(error) = axum::serve(listener, trawl_scan::server::app()).await {
        eprintln!("trawl-scan stopped: {error}");
        std::process::exit(1);
    }
}
