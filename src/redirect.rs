use async_trait::async_trait;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::Result;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;

pub struct RedirectProxy {
    pub challenges: Arc<RwLock<HashMap<String, String>>>,
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
