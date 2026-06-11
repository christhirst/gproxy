mod config;

use async_trait::async_trait;
use pingora::protocols::ALPN;
use pingora::server::configuration::Opt;
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, Result};
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use crate::config::Settings;

pub struct GrpcProxy {
    settings: Arc<RwLock<Settings>>,
    counter: Arc<AtomicUsize>,
}

#[async_trait]
impl ProxyHttp for GrpcProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ()) -> Result<bool> {
        let req = session.req_header();
        
        // Intercept POST /_config
        if req.method == pingora::http::Method::POST && req.uri.path() == "/_config" {
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
                            // Respond with success JSON
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
            return Ok(true); // Stop processing request further (do not proxy to upstream)
        }
        Ok(false)
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> {
        let path = session.req_header().uri.path();
        
        let (backend_addr, tls, host_header) = {
            let settings = self.settings.read().map_err(|_| {
                Error::new_str("Failed to acquire settings read lock")
            })?;
            
            // Find a matching route based on path prefix, otherwise fallback
            let route = settings.upstream.routes.iter()
                .find(|r| path.starts_with(&r.path))
                .or(settings.upstream.fallback.as_ref());
                
            match route {
                Some(r) => {
                    if r.backends.is_empty() {
                        return Err(Error::new_str("No backends configured for matched route"));
                    }
                    // Round-robin selection of backend
                    let idx = self.counter.fetch_add(1, Ordering::Relaxed) % r.backends.len();
                    (
                        r.backends[idx].clone(),
                        r.tls,
                        r.host_header.clone(),
                    )
                }
                None => {
                    return Err(Error::new_str("No route matched the request path and no fallback was configured"));
                }
            }
        };

        info!(
            path = %path,
            backend = %backend_addr,
            "Routing gRPC request to backend"
        );

        // Create the HTTP peer
        let mut peer = Box::new(HttpPeer::new(
            &backend_addr,
            tls,
            host_header,
        ));

        // Enforce HTTP/2 for gRPC (and/or h2c if TLS is false)
        peer.options.alpn = ALPN::H2;

        Ok(peer)
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, _ctx: &mut ()) {
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

fn main() {
    // 1. Load configuration
    let settings = Settings::new("config.yaml").expect("Failed to load config.yaml");

    // 2. Initialize Tracing
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&settings.server.log_level));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    info!("Starting gRPC Proxy with configuration: {:?}", settings);

    // 3. Initialize Pingora Server
    let opt = Some(Opt::default());
    let mut server = Server::new(opt).expect("Failed to initialize server");
    server.bootstrap();

    // Configure grace period from config
    if let Some(conf) = Arc::get_mut(&mut server.configuration) {
        conf.grace_period_seconds = Some(settings.server.grace_period_sec);
    }

    // 4. Create and register the proxy service
    let settings_arc = Arc::new(RwLock::new(settings));
    let proxy = GrpcProxy {
        settings: settings_arc.clone(),
        counter: Arc::new(AtomicUsize::new(0)),
    };
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&settings_arc.read().unwrap().server.addr);

    info!("gRPC proxy listening on {}", settings_arc.read().unwrap().server.addr);

    // 5. Run the server
    server.add_service(proxy_service);
    server.run_forever();
}
