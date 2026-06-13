use thiserror::Error;
use pingora::Error as PingoraError;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Failed to acquire settings read lock")]
    ReadLockFailed,

    #[error("No backends configured for matched route")]
    NoBackends,

    #[error("No route matched the request path and no fallback was configured")]
    NoRouteMatched,
}

impl From<ProxyError> for Box<PingoraError> {
    fn from(err: ProxyError) -> Self {
        match err {
            ProxyError::ReadLockFailed => PingoraError::new_str("Failed to acquire settings read lock"),
            ProxyError::NoBackends => PingoraError::new_str("No backends configured for matched route"),
            ProxyError::NoRouteMatched => PingoraError::new_str("No route matched the request path and no fallback was configured"),
        }
    }
}
