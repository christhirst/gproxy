use async_trait::async_trait;
use pingora::protocols::ALPN;
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, Result};
use pingora::proxy::{ProxyHttp, Session};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use crate::config::Settings;
use crate::error::ProxyError;
use prometheus::Encoder;
use std::collections::HashMap;

/// Per-request context that carries OIDC-injected headers to `upstream_request_filter`.
pub struct RequestContext {
    pub oidc_headers: Vec<(String, String)>,
}

pub struct GrpcProxy {
    pub settings: Arc<RwLock<Settings>>,
    pub counter: Arc<AtomicUsize>,
    pub healthy_backends: Arc<RwLock<HashMap<String, bool>>>,
    /// Secret used to sign / verify the local OIDC session cookie (HMAC-HS256).
    pub cookie_secret: Vec<u8>,
}

// auth helpers moved to auth.rs

// ── ProxyHttp implementation ───────────────────────────────────────────

#[async_trait]
impl ProxyHttp for GrpcProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            oidc_headers: Vec::new(),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut RequestContext) -> Result<bool> {
        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.clone();

        // ── Intercept GET /health ──────────────────────────────────
        if method == pingora::http::Method::GET && path == "/health" {
            info!("Intercepted health check request");
            let mut resp = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
            resp.insert_header("Content-Type", "application/json").unwrap();
            session.write_response_header(Box::new(resp), false).await?;
            session.write_response_body(Some(bytes::Bytes::from("{\"status\":\"healthy\"}\n")), true).await?;
            return Ok(true);
        }

        // ── Intercept GET /metrics ─────────────────────────────────
        if method == pingora::http::Method::GET && path == "/metrics" {
            info!("Intercepted Prometheus metrics request");
            let encoder = prometheus::TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = Vec::new();
            if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
                warn!("Failed to encode metrics: {:?}", e);
                let mut resp = pingora::http::ResponseHeader::build(500, Some(2)).unwrap();
                resp.insert_header("Content-Type", "text/plain").unwrap();
                session.write_response_header(Box::new(resp), false).await?;
                session.write_response_body(Some(bytes::Bytes::from("Failed to encode metrics")), true).await?;
                return Ok(true);
            }
            
            let mut resp = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
            resp.insert_header("Content-Type", "text/plain; version=0.0.4").unwrap();
            session.write_response_header(Box::new(resp), false).await?;
            session.write_response_body(Some(bytes::Bytes::from(buffer)), true).await?;
            return Ok(true);
        }

        // ── Intercept GET /_config ─────────────────────────────────
        if method == pingora::http::Method::GET && path == "/_config" {
            info!("Intercepted request to retrieve active configuration");
            let settings_json = {
                let settings = self.settings.read().map_err(|_| {
                    Error::new_str("Failed to acquire settings read lock")
                })?;
                serde_json::to_vec(&*settings).map_err(|_| {
                    Error::new_str("Failed to serialize settings to JSON")
                })?
            };
            
            let mut resp = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
            resp.insert_header("Content-Type", "application/json").unwrap();
            session.write_response_header(Box::new(resp), false).await?;
            session.write_response_body(Some(bytes::Bytes::from(settings_json)), true).await?;
            return Ok(true);
        }

        // ── Intercept POST /_config ────────────────────────────────
        if method == pingora::http::Method::POST && path == "/_config" {
            info!("Intercepted request to hot-reload configuration");
            
            // Read body
            let mut body = Vec::new();
            while let Some(chunk) = session.read_request_body().await? {
                body.extend_from_slice(&chunk);
            }
            
            // Parse JSON into Settings
            match serde_json::from_slice::<Settings>(&body) {
                Ok(new_settings) => {
                    info!("Updating proxy settings dynamically without restart: {:?}", new_settings);
                    let update_result = {
                        match self.settings.write() {
                            Ok(mut settings_guard) => {
                                *settings_guard = new_settings;
                                Ok(())
                            }
                            Err(e) => {
                                Err(format!("Failed to acquire write lock on settings: {:?}", e))
                            }
                        }
                    }; // settings_guard is dropped here
                    
                    match update_result {
                        Ok(()) => {
                            let mut resp = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
                            resp.insert_header("Content-Type", "application/json").unwrap();
                            session.write_response_header(Box::new(resp), false).await?;
                            session.write_response_body(Some(bytes::Bytes::from("{\"status\":\"updated\"}\n")), true).await?;
                        }
                        Err(e_msg) => {
                            warn!("{}", e_msg);
                            let mut resp = pingora::http::ResponseHeader::build(500, Some(2)).unwrap();
                            resp.insert_header("Content-Type", "application/json").unwrap();
                            session.write_response_header(Box::new(resp), false).await?;
                            session.write_response_body(Some(bytes::Bytes::from("{\"error\":\"Internal lock error\"}\n")), true).await?;
                        }
                    }
                }
                Err(err) => {
                    warn!("Failed to parse JSON config payload: {:?}", err);
                    let mut resp = pingora::http::ResponseHeader::build(400, Some(2)).unwrap();
                    resp.insert_header("Content-Type", "application/json").unwrap();
                    session.write_response_header(Box::new(resp), false).await?;
                    let err_msg = format!("{{\"error\":\"Invalid JSON: {}\"}}\n", err);
                    session.write_response_body(Some(bytes::Bytes::from(err_msg)), true).await?;
                }
            }
            return Ok(true);
        }

        // ── OIDC Authentication Gate ───────────────────────────────
        if crate::auth::handle_oidc(session, &self.settings, &self.cookie_secret, &mut ctx.oidc_headers).await? {
            return Ok(true);
        }

        Ok(false)
    }

    /// Inject OIDC-derived headers into the upstream request.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> Result<()> {
        for (name, value) in std::mem::take(&mut ctx.oidc_headers) {
            upstream_request.append_header(name, &value)?;
        }
        Ok(())
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut RequestContext) -> Result<Box<HttpPeer>> {
        let path = session.req_header().uri.path();
        
        let (backend_addr, tls, host_header, protocol) = {
            let settings = self.settings.read().map_err(|_| ProxyError::ReadLockFailed)?;
            
            // Find a matching route based on path prefix, otherwise fallback
            let route = settings.upstream.routes.iter()
                .find(|r| path.starts_with(&r.path))
                .or(settings.upstream.fallback.as_ref());
                
            match route {
                Some(r) => {
                    if r.backends.is_empty() {
                        return Err(ProxyError::NoBackends.into());
                    }

                    // Filter healthy backends
                    let healthy_map = self.healthy_backends.read().unwrap();
                    let healthy_list: Vec<String> = r.backends.iter()
                        .filter(|b| *healthy_map.get(*b).unwrap_or(&true))
                        .cloned()
                        .collect();

                    let chosen_list = if healthy_list.is_empty() {
                        r.backends.clone() // Fallback to all if none are reported healthy
                    } else {
                        healthy_list
                    };

                    // Round-robin selection of backend
                    let idx = self.counter.fetch_add(1, Ordering::Relaxed) % chosen_list.len();
                    (
                        chosen_list[idx].clone(),
                        r.tls,
                        r.host_header.clone(),
                        r.protocol.clone(),
                    )
                }
                None => {
                    return Err(ProxyError::NoRouteMatched.into());
                }
            }
        };

        info!(
            path = %path,
            backend = %backend_addr,
            protocol = %protocol,
            "Routing request to backend"
        );

        // Create the HTTP peer
        let mut peer = Box::new(HttpPeer::new(
            &backend_addr,
            tls,
            host_header,
        ));

        // Set ALPN based on configured protocol
        peer.options.alpn = match protocol.as_str() {
            "http1" => ALPN::H1,
            _ => ALPN::H2, // "http2" or any other value defaults to H2 (gRPC)
        };

        Ok(peer)
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, _ctx: &mut RequestContext) {
        let req = session.req_header();
        let status = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        
        info!(
            method = %req.method,
            uri = %req.uri,
            status = status,
            "Request proxied successfully"
        );
    }
}
