mod acme;
mod auth;
mod config;
mod error;
mod proxy;
mod redirect;
mod health;

use acme::{load_certs_from_disk, run_acme_worker, DynamicCert};
use proxy::GrpcProxy;
use redirect::RedirectProxy;

use pingora::proxy::http_proxy_service;
use pingora::server::configuration::Opt;
use pingora::server::Server;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use crate::config::Settings;

use std::collections::HashMap;
use std::path::Path;

use pingora::listeners::tls::TlsSettings;

fn main() {
    // 1. Load configuration
    let settings = Settings::new("config.yaml").expect("Failed to load config.yaml");

    // 2. Initialize Tracing
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&settings.server.log_level));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

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
    let healthy_backends = Arc::new(RwLock::new(HashMap::new()));

    // Spawn background health prober
    let settings_clone = settings_arc.clone();
    let healthy_clone = healthy_backends.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            health::run_health_check_worker(settings_clone, healthy_clone).await;
        });
    });

    // Resolve OIDC cookie signing secret
    let cookie_secret: Vec<u8> = {
        let s = settings_arc.read().unwrap();
        auth::resolve_cookie_secret(&s)
    };

    let proxy = GrpcProxy {
        settings: settings_arc.clone(),
        counter: Arc::new(AtomicUsize::new(0)),
        healthy_backends: healthy_backends.clone(),
        cookie_secret,
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
                    Path::new(
                        tls.cert_path
                            .as_ref()
                            .expect("cert_path is required if ACME is disabled"),
                    )
                    .to_path_buf(),
                    Path::new(
                        tls.key_path
                            .as_ref()
                            .expect("key_path is required if ACME is disabled"),
                    )
                    .to_path_buf(),
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
            let http_addr = settings_arc
                .read()
                .unwrap()
                .server
                .http_addr
                .clone()
                .unwrap_or_else(|| "0.0.0.0:80".to_string());
            let redirect_proxy = RedirectProxy {
                challenges: challenges_map.clone(),
            };
            let mut redirect_service = http_proxy_service(&server.configuration, redirect_proxy);
            info!(
                "Registering HTTP redirect/challenge listener on: {}",
                http_addr
            );
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
