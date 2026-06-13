use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::tls::ssl::SslRef;
use openssl::x509::X509;
use openssl::pkey::{PKey, Private};
use openssl::asn1::Asn1Time;
use rustls_pki_types::{PrivatePkcs8KeyDer, PrivateKeyDer};
use instant_acme::{Account, Key, LetsEncrypt, Identifier, NewOrder, ChallengeType, RetryPolicy};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::time::Duration;
use std::path::Path;
use tracing::{info, warn};
use crate::config::Settings;

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

pub fn load_certs_from_disk(cert_path: &Path, key_path: &Path) -> Option<(X509, PKey<Private>)> {
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

pub async fn run_acme_worker(
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
