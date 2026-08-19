//! The HTTP surface the frontend talks to.
//!
//! Two routes. `GET /health` is what the "waiting for the scanner" panel polls;
//! the moment it answers, the panel knows the scanner is up and switches to the
//! URL input. `POST /scan` takes a target and, for now, fetches it once through
//! the guard and runs the body past the same flag detection the offline tool
//! uses. The passive and active checks layer onto this route next.
//!
//! CORS is open, because the frontend and the scanner are two different origins
//! by design — the page may be served from anywhere while the scanner runs on
//! the user's own machine — and the scanner holds nothing worth protecting from
//! the person who started it.

use axum::{
    Json, Router,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

pub fn app() -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan))
        .layer(cors)
}

#[derive(Serialize)]
struct Health {
    service: &'static str,
    version: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health {
        service: "trawl-scan",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Deserialize)]
struct ScanRequest {
    url: String,
}

#[derive(Serialize)]
struct Finding {
    kind: String,
    detail: String,
}

async fn scan(
    Json(request): Json<ScanRequest>,
) -> Result<Json<Vec<Finding>>, (StatusCode, String)> {
    let fetched = crate::fetch::fetch(&request.url)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let mut findings = vec![Finding {
        kind: "fetched".into(),
        detail: format!(
            "{} returned {}{}",
            fetched.final_url,
            fetched.status,
            if fetched.truncated {
                " (body truncated)"
            } else {
                ""
            }
        ),
    }];

    // The reuse the whole approach turns on: the response body goes through the
    // exact flag detector the offline half uses, with nothing reimplemented.
    for found in trawl_core::bytes::flag_candidates(&fetched.body) {
        findings.push(Finding {
            kind: "flag".into(),
            detail: found.text,
        });
    }

    Ok(Json(findings))
}
