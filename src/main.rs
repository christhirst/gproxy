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

use std::collections::HashMap;
use std::time::Duration;
use std::path::Path;

use pingora::listeners::TlsAccept;
use pingora::listeners::tls::TlsSettings;
use pingora::tls::ssl::SslRef;

use openssl::x509::X509;
use openssl::pkey::{PKey, Private};
use openssl::asn1::Asn1Time;

use rustls_pki_types::{PrivatePkcs8KeyDer, PrivateKeyDer};
use instant_acme::{Account, Key, LetsEncrypt, Identifier, NewOrder, ChallengeType, RetryPolicy};

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

pub struct RedirectProxy {
    challenges: Arc<RwLock<HashMap<String, String>>>,
}

#[async_trait]
impl ProxyHttp for RedirectProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ()) -> Result<bool> {
        let req = session.req_header();
        let path = req.uri.path();

        // 1. Intercept ACME HTTP-01 challenge
        if path.starts_with("/.well-known/acme-challenge/") {
            let token = path.trim_start_matches("/.well-known/acme-challenge/");
            let key_auth = self.challenges.read().unwrap().get(token).cloned();
            if let Some(key_auth_val) = key_auth {
                info!("Responding to ACME challenge token: {}", token);
                let mut resp = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
                resp.insert_header("Content-Type", "text/plain").unwrap();
                session.write_response_header(Box::new(resp), false).await?;
                session.write_response_body(Some(bytes::Bytes::from(key_auth_val)), true).await?;
                return Ok(true); // Stop processing
            }
        }

        // 2. Redirect all other requests to HTTPS
        let host = req.headers.get("Host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");

        let redirect_url = format!("https://{}{}", host, path);
        info!("Redirecting HTTP request to HTTPS: {}", redirect_url);

        let mut resp = pingora::http::ResponseHeader::build(301, Some(2)).unwrap();
        resp.insert_header("Location", redirect_url).unwrap();
        session.write_response_header(Box::new(resp), true).await?;
        Ok(true) // Stop processing
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> {
        // Unreachable since request_filter always intercepts and returns true
        Ok(Box::new(HttpPeer::new("127.0.0.1:80", false, "".to_string())))
    }
}

pub struct DynamicCert {
    pub cert_key: Arc<RwLock<Option<(X509, PKey<Private>)>>>,
}

#[async_trait]
impl TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let guard = self.cert_key.read().unwrap();
        if let Some((cert, key)) = &*guard {
            if let Err(e) = ssl.set_certificate(cert) {
                warn!("DynamicCert: Failed to set certificate on connection: {:?}", e);
            }
            if let Err(e) = ssl.set_private_key(key) {
                warn!("DynamicCert: Failed to set private key on connection: {:?}", e);
            }
        } else {
            warn!("DynamicCert: No certificate available in dynamic cert callback");
        }
    }
}

fn load_certs_from_disk(cert_path: &Path, key_path: &Path) -> Option<(X509, PKey<Private>)> {
    if cert_path.exists() && key_path.exists() {
        let cert_bytes = std::fs::read(cert_path).ok()?;
        let key_bytes = std::fs::read(key_path).ok()?;
        let cert = X509::from_pem(&cert_bytes).ok()?;
        let key = PKey::private_key_from_pem(&key_bytes).ok()?;
        Some((cert, key))
    } else {
        None
    }
}

async fn run_acme_worker(
    settings: Arc<RwLock<Settings>>,
    challenges: Arc<RwLock<HashMap<String, String>>>,
    cert_key_cache: Arc<RwLock<Option<(X509, PKey<Private>)>>>,
) {
    loop {
        let (acme_enabled, domains, email, staging, cache_dir, custom_directory_url) = {
            let s = settings.read().unwrap();
            if let Some(tls) = &s.server.tls {
                if let Some(acme) = &tls.acme {
                    (
                        acme.enabled,
                        acme.domains.clone(),
                        acme.email.clone(),
                        acme.staging,
                        acme.cache_dir.clone(),
                        acme.directory_url.clone(),
                    )
                } else {
                    (false, vec![], String::new(), true, String::new(), None)
                }
            } else {
                (false, vec![], String::new(), true, String::new(), None)
            }
        };

        if acme_enabled && !domains.is_empty() {
            info!("ACME worker: Checking certificates for domains: {:?}", domains);
            let certs_dir = Path::new(&cache_dir);
            let cert_path = certs_dir.join("cert.pem");
            let key_path = certs_dir.join("key.pem");
            let account_key_path = certs_dir.join("account_key.der");

            // Create cache directory if it doesn't exist
            if let Err(e) = tokio::fs::create_dir_all(certs_dir).await {
                warn!("ACME worker: Failed to create cache directory {:?}: {:?}", certs_dir, e);
            }

            // Load existing certs from disk and check if they need renewal
            let mut need_renewal = true;
            if let Some((cert, key)) = load_certs_from_disk(&cert_path, &key_path) {
                let thirty_days_from_now = match Asn1Time::days_from_now(30) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!("ACME worker: Failed to compute Asn1Time: {:?}", e);
                        Asn1Time::days_from_now(0).unwrap()
                    }
                };
                let cert_expiry = cert.not_after();
                match cert_expiry.compare(&thirty_days_from_now) {
                    Ok(std::cmp::Ordering::Greater) => {
                        info!("ACME worker: Existing certificate is valid and does not expire in the next 30 days.");
                        need_renewal = false;
                        let mut cache = cert_key_cache.write().unwrap();
                        if cache.is_none() {
                            *cache = Some((cert, key));
                        }
                    }
                    _ => {
                        info!("ACME worker: Certificate expires soon or is invalid. Initiating renewal.");
                    }
                }
            } else {
                info!("ACME worker: No valid certificates found on disk.");
            }

            if need_renewal {
                let directory_url = if let Some(url) = custom_directory_url {
                    info!("ACME worker: Requesting certificate from custom directory URL: {}", url);
                    url
                } else {
                    info!("ACME worker: Requesting certificate from Let's Encrypt...");
                    if staging {
                        LetsEncrypt::Staging.url().to_string()
                    } else {
                        LetsEncrypt::Production.url().to_string()
                    }
                };

                // Load or generate account key
                let key = if account_key_path.exists() {
                    match tokio::fs::read(&account_key_path).await {
                        Ok(der_bytes) => {
                            let private_key_der = PrivatePkcs8KeyDer::from(der_bytes);
                            match Key::from_pkcs8_der(private_key_der) {
                                Ok(k) => k,
                                Err(e) => {
                                    warn!("ACME worker: Failed to parse account key from disk: {:?}", e);
                                    let (k, der) = Key::generate_pkcs8().unwrap();
                                    let _ = tokio::fs::write(&account_key_path, der.secret_pkcs8_der()).await;
                                    k
                                }
                            }
                        }
                        Err(_) => {
                            let (k, der) = Key::generate_pkcs8().unwrap();
                            let _ = tokio::fs::write(&account_key_path, der.secret_pkcs8_der()).await;
                            k
                        }
                    }
                } else {
                    let (k, der) = Key::generate_pkcs8().unwrap();
                    if let Err(e) = tokio::fs::write(&account_key_path, der.secret_pkcs8_der()).await {
                        warn!("ACME worker: Failed to write account key to disk: {:?}", e);
                    }
                    k
                };

                let builder = match Account::builder() {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("ACME worker: Failed to create AccountBuilder: {:?}", e);
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        continue;
                    }
                };

                // Load existing or register new account using key
                let account_key_bytes = match tokio::fs::read(&account_key_path).await {
                    Ok(b) => b,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                };
                let pkey_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(account_key_bytes));

                let account_res = builder.create_from_key((key, pkey_der), directory_url).await;
                match account_res {
                    Ok((account, _credentials)) => {
                        if !email.is_empty() {
                            let mailto = format!("mailto:{}", email);
                            if let Err(e) = account.update_contacts(&[&mailto]).await {
                                warn!("ACME worker: Failed to update contact email: {:?}", e);
                            } else {
                                info!("ACME worker: Updated contact email to {}", email);
                            }
                        }

                        // Create order
                        let mut identifiers = vec![];
                        for domain in &domains {
                            identifiers.push(Identifier::Dns(domain.clone()));
                        }
                        let new_order = NewOrder::new(&identifiers);
                        match account.new_order(&new_order).await {
                            Ok(mut order) => {
                                // Solve authorizations
                                let mut authorizations = order.authorizations();
                                let mut auth_success = true;
                                while let Some(auth_res) = authorizations.next().await {
                                    match auth_res {
                                        Ok(mut auth) => {
                                            match auth.challenge(ChallengeType::Http01) {
                                                Some(mut challenge) => {
                                                    let token = challenge.token.clone();
                                                    let key_auth = challenge.key_authorization().as_str().to_string();

                                                    challenges.write().unwrap().insert(token.clone(), key_auth);

                                                    info!("ACME worker: Notifying CA that challenge for token {} is ready", token);
                                                    if let Err(e) = challenge.set_ready().await {
                                                        warn!("ACME worker: Failed to set challenge ready: {:?}", e);
                                                        auth_success = false;
                                                        break;
                                                    }
                                                }
                                                None => {
                                                    warn!("ACME worker: HTTP-01 challenge not found in authorization");
                                                    auth_success = false;
                                                    break;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("ACME worker: Failed to get next authorization: {:?}", e);
                                            auth_success = false;
                                            break;
                                        }
                                    }
                                }

                                if auth_success {
                                    // Poll order ready
                                    let policy = RetryPolicy::new().timeout(Duration::from_secs(120));
                                    match order.poll_ready(&policy).await {
                                        Ok(status) => {
                                            info!("ACME worker: Order status after polling: {:?}", status);
                                            // Finalize order
                                            match order.finalize().await {
                                                Ok(domain_key_pem) => {
                                                    // Download certificate
                                                    match order.poll_certificate(&policy).await {
                                                        Ok(cert_chain_pem) => {
                                                            info!("ACME worker: Certificate successfully retrieved!");
                                                            if let Err(e) = tokio::fs::write(&cert_path, cert_chain_pem.as_bytes()).await {
                                                                warn!("ACME worker: Failed to write cert.pem to disk: {:?}", e);
                                                            }
                                                            if let Err(e) = tokio::fs::write(&key_path, domain_key_pem.as_bytes()).await {
                                                                warn!("ACME worker: Failed to write key.pem to disk: {:?}", e);
                                                            }

                                                            // Update memory cache
                                                            if let Ok(cert) = X509::from_pem(cert_chain_pem.as_bytes()) {
                                                                if let Ok(key) = PKey::private_key_from_pem(domain_key_pem.as_bytes()) {
                                                                    let mut cache = cert_key_cache.write().unwrap();
                                                                    *cache = Some((cert, key));
                                                                    info!("ACME worker: TLS certificate cache successfully updated in memory.");
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!("ACME worker: Failed to poll certificate: {:?}", e);
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("ACME worker: Failed to finalize order: {:?}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("ACME worker: Failed to poll order status: {:?}", e);
                                        }
                                    }
                                }

                                // Clear challenges map
                                challenges.write().unwrap().clear();
                            }
                            Err(e) => {
                                warn!("ACME worker: Failed to create new order: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("ACME worker: Failed to create or load account from key: {:?}", e);
                    }
                }
            }
        }

        // Check again in 24 hours
        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
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

    // Enable HTTP/2 cleartext (h2c) for downstream cleartext gRPC requests
    if let Some(app_logic) = proxy_service.app_logic_mut() {
        let mut http_server_options = pingora::apps::HttpServerOptions::default();
        http_server_options.h2c = true;
        app_logic.server_options = Some(http_server_options);
    }

    // Setup TLS & ACME if configured
    let (tls_enabled, acme_enabled) = {
        let s = settings_arc.read().unwrap();
        if let Some(tls) = &s.server.tls {
            (tls.enabled, tls.acme.as_ref().map_or(false, |a| a.enabled))
        } else {
            (false, false)
        }
    };

    if tls_enabled {
        let cert_key_cache = Arc::new(RwLock::new(None));
        let challenges_map = Arc::new(RwLock::new(HashMap::new()));

        // Populate cert_key_cache on startup if certificates already exist on disk
        {
            let s = settings_arc.read().unwrap();
            let tls = s.server.tls.as_ref().unwrap();
            let (cert_path, key_path) = if acme_enabled {
                let acme = tls.acme.as_ref().unwrap();
                let certs_dir = Path::new(&acme.cache_dir);
                (certs_dir.join("cert.pem"), certs_dir.join("key.pem"))
            } else {
                (
                    Path::new(tls.cert_path.as_ref().expect("cert_path is required if ACME is disabled")).to_path_buf(),
                    Path::new(tls.key_path.as_ref().expect("key_path is required if ACME is disabled")).to_path_buf(),
                )
            };

            if let Some((cert, key)) = load_certs_from_disk(&cert_path, &key_path) {
                info!("Loaded existing certificates from disk successfully.");
                *cert_key_cache.write().unwrap() = Some((cert, key));
            } else {
                warn!("No existing certificates found on disk on startup.");
            }
        }

        // Register Dynamic TLS Callback settings
        let dynamic_cert = DynamicCert {
            cert_key: cert_key_cache.clone(),
        };
        let mut tls_settings = TlsSettings::with_callbacks(Box::new(dynamic_cert)).unwrap();
        tls_settings.enable_h2();

        // Listen on TLS port (e.g. 443)
        let https_addr = settings_arc.read().unwrap().server.addr.clone();
        info!("Registering TLS listener on: {}", https_addr);
        proxy_service.add_tls_with_settings(&https_addr, None, tls_settings);

        // If ACME is enabled, start the challenge solver redirect proxy and background worker
        if acme_enabled {
            let http_addr = settings_arc.read().unwrap().server.http_addr.clone().unwrap_or_else(|| "0.0.0.0:80".to_string());
            let redirect_proxy = RedirectProxy {
                challenges: challenges_map.clone(),
            };
            let mut redirect_service = http_proxy_service(&server.configuration, redirect_proxy);
            info!("Registering HTTP redirect/challenge listener on: {}", http_addr);
            redirect_service.add_tcp(&http_addr);
            server.add_service(redirect_service);

            // Spawn ACME background worker in an OS thread
            let worker_settings = settings_arc.clone();
            let worker_challenges = challenges_map.clone();
            let worker_cache = cert_key_cache.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    run_acme_worker(worker_settings, worker_challenges, worker_cache).await;
                });
            });
        }
    } else {
        // Standard non-TLS TCP listener
        let addr = settings_arc.read().unwrap().server.addr.clone();
        info!("Registering TCP listener on: {}", addr);
        proxy_service.add_tcp(&addr);
    }

    server.add_service(proxy_service);
    server.run_forever();
}
