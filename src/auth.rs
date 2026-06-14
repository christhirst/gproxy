use pingora::proxy::Session;
use pingora::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use crate::config::{Settings, OidcSettings, UpstreamRoute};

// ── helpers ────────────────────────────────────────────────────────────

/// Extract the value of a named cookie from the Cookie header.
fn extract_cookie(session: &Session, name: &str) -> Option<String> {
    let req = session.req_header();
    if let Some(cookie_hdr) = req.headers.get("cookie") {
        if let Ok(cookie_str) = cookie_hdr.to_str() {
            for pair in cookie_str.split(';') {
                let pair = pair.trim();
                if let Some(rest) = pair.strip_prefix(name) {
                    if let Some(val) = rest.strip_prefix('=') {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Find the first `UpstreamRoute` whose path is a prefix of the request path.
fn find_route_for_path<'a>(settings: &'a Settings, path: &str) -> Option<&'a UpstreamRoute> {
    settings
        .upstream
        .routes
        .iter()
        .find(|r| path.starts_with(&r.path))
        .or(settings.upstream.fallback.as_ref())
}

/// Build the IdP authorization redirect URL for a given OIDC config.
fn build_auth_redirect_url(oidc: &OidcSettings, original_url: &str) -> String {
    let scopes = oidc.scopes.join(" ");
    format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        oidc.auth_url,
        urlencoding::encode(&oidc.client_id),
        urlencoding::encode(&oidc.redirect_uri),
        urlencoding::encode(&scopes),
        urlencoding::encode(original_url),
    )
}

/// Exchange an authorization code for an ID token via the IdP's token endpoint.
async fn exchange_code_for_id_token(
    oidc: &OidcSettings,
    code: &str,
) -> std::result::Result<String, String> {
    let client = reqwest::Client::new();
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &oidc.redirect_uri),
        ("client_id", &oidc.client_id),
        ("client_secret", &oidc.client_secret),
    ];

    let resp = client
        .post(&oidc.token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Token request failed: {e}"))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {e}"))?;

    body.get("id_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "No id_token in token response".to_string())
}

/// Decode JWT claims without signature verification (the IdP signature is
/// implicitly trusted because we just received the token over TLS from the
/// token endpoint).
fn decode_jwt_claims(token: &str) -> std::result::Result<serde_json::Value, String> {
    let key = jsonwebtoken::DecodingKey::from_secret(&[]);
    let mut validation = jsonwebtoken::Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|e| format!("JWT decode error: {e}"))?;
    Ok(data.claims)
}

/// Create a signed local session JWT that contains the claims we care about.
fn sign_session_jwt(
    claims: &serde_json::Value,
    secret: &[u8],
    ttl_secs: u64,
) -> std::result::Result<String, String> {
    let now = chrono::Utc::now().timestamp() as u64;
    let mut payload = claims.clone();
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("exp".to_string(), serde_json::json!(now + ttl_secs));
        obj.insert("iat".to_string(), serde_json::json!(now));
    }
    let header = jsonwebtoken::Header::default();
    let key = jsonwebtoken::EncodingKey::from_secret(secret);
    jsonwebtoken::encode(&header, &payload, &key).map_err(|e| format!("JWT sign error: {e}"))
}

/// Verify and decode the local session JWT.
fn verify_session_jwt(
    token: &str,
    secret: &[u8],
) -> std::result::Result<serde_json::Value, String> {
    let key = jsonwebtoken::DecodingKey::from_secret(secret);
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|e| format!("Session JWT validation failed: {e}"))?;
    Ok(data.claims)
}

// ── helper to write a simple HTTP response ─────────────────────────────

async fn send_response(session: &mut Session, status: u16, body: &str) -> Result<()> {
    let mut resp = pingora::http::ResponseHeader::build(status, Some(2)).unwrap();
    resp.insert_header("Content-Type", "text/plain").unwrap();
    session.write_response_header(Box::new(resp), false).await?;
    session.write_response_body(Some(bytes::Bytes::from(body.to_string())), true).await?;
    Ok(())
}

async fn send_redirect(session: &mut Session, location: &str, cookie: Option<&str>) -> Result<()> {
    let mut resp = pingora::http::ResponseHeader::build(302, Some(4)).unwrap();
    resp.insert_header("Location", location).unwrap();
    resp.insert_header("Content-Length", "0").unwrap();
    if let Some(c) = cookie {
        resp.insert_header("Set-Cookie", c).unwrap();
    }
    session.write_response_header(Box::new(resp), false).await?;
    session.write_response_body(Some(bytes::Bytes::new()), true).await?;
    Ok(())
}

// ── main entry point for OIDC interception/auth ─────────────────────────

/// Processes OIDC configuration for incoming requests.
/// Returns `Ok(true)` if the request was intercepted (e.g. redirected or callback handled).
/// Returns `Ok(false)` if the request should proceed to the backend.
pub async fn handle_oidc(
    session: &mut Session,
    settings: &Arc<RwLock<Settings>>,
    cookie_secret: &[u8],
    oidc_headers: &mut Vec<(String, String)>,
) -> Result<bool> {
    let path = session.req_header().uri.path().to_string();
    let method = session.req_header().method.clone();

    // ── Intercept GET /_oidc/callback ──────────────────────────
    if method == pingora::http::Method::GET && path == "/_oidc/callback" {
        info!("Intercepted OIDC callback");

        let query = session.req_header().uri.query().unwrap_or("").to_string();
        let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();

        let code = match params.get("code") {
            Some(c) => c.clone(),
            None => {
                send_response(session, 400, "Missing 'code' parameter").await?;
                return Ok(true);
            }
        };
        let state = params.get("state").cloned().unwrap_or_else(|| "/".to_string());

        // We need to find which route's OIDC config to use.
        // The `state` parameter carries the original request path,
        // so look up the route by that path.
        let maybe_oidc = {
            let settings = settings.read().map_err(|_| Error::new_str("Lock failed"))?;
            let route = find_route_for_path(&settings, &state);
            route.and_then(|r| r.oidc.clone())
        }; // lock dropped here

        let oidc_cfg = match maybe_oidc {
            Some(o) => o,
            None => {
                send_response(session, 400, "No OIDC configuration for the originating route").await?;
                return Ok(true);
            }
        };

        // Exchange the authorization code for an ID token
        let id_token = match exchange_code_for_id_token(&oidc_cfg, &code).await {
            Ok(t) => t,
            Err(e) => {
                warn!("OIDC token exchange failed: {}", e);
                send_response(session, 502, &format!("Token exchange failed: {e}")).await?;
                return Ok(true);
            }
        };

        // Decode the claims from the ID token
        let claims = match decode_jwt_claims(&id_token) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to decode ID token: {}", e);
                send_response(session, 502, &format!("ID token decode failed: {e}")).await?;
                return Ok(true);
            }
        };

        // Sign a local session cookie JWT (1-hour TTL)
        let session_jwt = match sign_session_jwt(&claims, cookie_secret, 3600) {
            Ok(j) => j,
            Err(e) => {
                warn!("Failed to sign session JWT: {}", e);
                send_response(session, 500, "Internal error").await?;
                return Ok(true);
            }
        };

        let cookie_val = format!(
            "gproxy_session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600",
            session_jwt
        );
        send_redirect(session, &state, Some(&cookie_val)).await?;
        return Ok(true);
    }

    // ── OIDC gate for protected routes ─────────────────────────
    {
        let oidc_cfg = {
            let settings = settings.read().map_err(|_| Error::new_str("Lock failed"))?;
            let route = find_route_for_path(&settings, &path);
            route.and_then(|r| r.oidc.clone())
        };

        if let Some(oidc) = oidc_cfg {
            // Check for existing session cookie
            if let Some(session_cookie) = extract_cookie(session, "gproxy_session") {
                match verify_session_jwt(&session_cookie, cookie_secret) {
                    Ok(claims) => {
                        // Map configured claims → headers
                        for attr in &oidc.attributes {
                            if let Some(val) = claims.get(&attr.claim) {
                                let header_val = match val {
                                    serde_json::Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                };
                                oidc_headers.push((attr.header.clone(), header_val));
                            }
                        }
                        // Fall through – request is authenticated
                    }
                    Err(e) => {
                        info!("Invalid/expired session cookie, redirecting to IdP: {}", e);
                        let redirect_url = build_auth_redirect_url(&oidc, &path);
                        send_redirect(session, &redirect_url, None).await?;
                        return Ok(true);
                    }
                }
            } else {
                // No session cookie → redirect to IdP
                info!("No OIDC session cookie, redirecting to IdP");
                let redirect_url = build_auth_redirect_url(&oidc, &path);
                send_redirect(session, &redirect_url, None).await?;
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Resolves the cookie signing secret from the configuration, or generates
/// a cryptographically secure random 32-byte secret if not configured.
pub fn resolve_cookie_secret(settings: &Settings) -> Vec<u8> {
    match &settings.server.cookie_secret {
        Some(b64) => {
            info!("Using cookie_secret from configuration");
            b64.as_bytes().to_vec()
        }
        None => {
            info!("No cookie_secret configured — generating random 32-byte secret");
            let mut buf = [0u8; 32];
            use rand::Rng;
            rand::thread_rng().fill(&mut buf);
            buf.to_vec()
        }
    }
}
