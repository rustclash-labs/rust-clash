use axum::{
    body::Body,
    http::{Response, StatusCode, Uri, header},
    response::IntoResponse,
};
#[cfg(feature = "embedded-ui")]
use rust_embed::RustEmbed;

#[cfg(feature = "embedded-ui")]
#[derive(RustEmbed)]
#[folder = "../../ui/dist"]
pub struct EmbeddedUiAssets;

#[cfg(feature = "embedded-ui")]
pub async fn serve_embedded_spa(uri: Uri) -> impl IntoResponse {
    let raw_path = uri.path().trim_start_matches('/');
    let target = if raw_path.is_empty() {
        "index.html"
    } else {
        raw_path
    };

    if let Some(asset) = EmbeddedUiAssets::get(target) {
        return build_asset_response(target, asset.data.into_owned());
    }

    // SPA client-side route fallback -> serve `index.html` for non-asset routes
    if !target.contains('.')
        && let Some(index) = EmbeddedUiAssets::get("index.html")
    {
        return build_asset_response("index.html", index.data.into_owned());
    }

    not_found_json()
}

#[cfg(not(feature = "embedded-ui"))]
pub async fn serve_embedded_spa(_uri: Uri) -> impl IntoResponse {
    not_found_json()
}

fn not_found_json() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"message":"resource not found"}"#))
        .unwrap()
}

#[cfg(feature = "embedded-ui")]
fn build_asset_response(path: &str, bytes: Vec<u8>) -> Response<Body> {
    let content_type = content_type_for_path(path);
    let cache_ctrl = if path == "index.html" {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, cache_ctrl)
        .body(Body::from(bytes))
        .unwrap()
}

#[cfg(feature = "embedded-ui")]
fn content_type_for_path(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
