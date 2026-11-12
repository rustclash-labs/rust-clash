use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Protocol error ({protocol}): {message}")]
    Protocol {
        protocol: &'static str,
        message: String,
    },

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Routing error: {0}")]
    Routing(String),

    #[error("Connection rejected by rule")]
    Rejected,

    #[error("Operation timed out")]
    Timeout,
}

impl ProxyError {
    /// Construct a `ProxyError::Config` while stripping any nested `"Configuration error: "` prefixes
    /// accumulated when inner errors were converted via `.to_string()` for secret redaction.
    pub fn config_clean(message: impl Into<String>) -> Self {
        let mut msg = message.into();
        while let Some(rest) = msg.strip_prefix("Configuration error: ") {
            msg = rest.to_string();
        }
        Self::Config(msg)
    }

    pub fn protocol(protocol: &'static str, message: impl Into<String>) -> Self {
        Self::Protocol {
            protocol,
            message: message.into(),
        }
    }

    pub fn into_io(self) -> io::Error {
        match self {
            Self::Io(err) => err,
            Self::Timeout => io::Error::new(io::ErrorKind::TimedOut, "operation timed out"),
            Self::Dns(msg) => io::Error::new(io::ErrorKind::HostUnreachable, msg),
            Self::Routing(msg) => io::Error::new(io::ErrorKind::PermissionDenied, msg),
            Self::Rejected => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "connection rejected by rule",
            ),
            other => io::Error::other(other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;
