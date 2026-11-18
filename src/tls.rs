//! HTTPS, so agents and admins can reach the proxy from other machines
//! without a separate TLS proxy in front of it.
//!
//! The certificate and key are PEM files named by `TLS_CERT` and `TLS_KEY`.
//! The handshake runs on the operating system's own TLS library: SChannel on
//! Windows, Secure Transport on macOS and OpenSSL on Linux.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::serve::Listener;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
};
use tokio_native_tls::{native_tls, TlsAcceptor, TlsStream};

/// A client that has not finished its handshake by then is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Handshakes in progress at once. A flood of slow clients is turned away
/// rather than queued, and cannot stop others from connecting.
const MAX_HANDSHAKES: usize = 256;

const PKCS8_START: &[u8] = b"-----BEGIN PRIVATE KEY-----";

/// Load the certificate chain and private key. Errors never show the key.
pub fn acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, String> {
    let cert = std::fs::read(cert_path)
        .map_err(|err| format!("cannot read TLS_CERT {cert_path}: {err}"))?;
    let key =
        std::fs::read(key_path).map_err(|err| format!("cannot read TLS_KEY {key_path}: {err}"))?;
    let key = trim_start(&key);
    if !key.starts_with(PKCS8_START) {
        return Err(format!(
            "TLS_KEY {key_path} must be a PEM key in PKCS#8 form, which starts with \
             -----BEGIN PRIVATE KEY-----. Convert it with: \
             openssl pkcs8 -topk8 -nocrypt -in <old key> -out {key_path}"
        ));
    }
    if !trim_start(&cert).starts_with(b"-----BEGIN CERTIFICATE-----") {
        return Err(format!(
            "TLS_CERT {cert_path} must be a PEM certificate, which starts with -----BEGIN CERTIFICATE-----"
        ));
    }
    let identity = native_tls::Identity::from_pkcs8(trim_start(&cert), key)
        .map_err(|err| format!("TLS_CERT and TLS_KEY cannot be used: {err}"))?;
    let acceptor = native_tls::TlsAcceptor::builder(identity)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()
        .map_err(|err| format!("TLS_CERT and TLS_KEY cannot be used: {err}"))?;
    Ok(TlsAcceptor::from(acceptor))
}

fn trim_start(bytes: &[u8]) -> &[u8] {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// Accepts TCP connections and hands over only those that finished a TLS
/// handshake. Handshakes run side by side, so one slow client does not hold
/// up the others.
pub struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    pub fn new(tcp: TcpListener, acceptor: TlsAcceptor) -> std::io::Result<TlsListener> {
        let local = tcp.local_addr()?;
        let (sender, ready) = mpsc::channel(64);
        let acceptor = Arc::new(acceptor);
        let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match tcp.accept().await {
                    Ok(connection) => connection,
                    Err(err) => {
                        // Usually out of file handles. Wait instead of spinning.
                        eprintln!("razorwire: cannot accept a connection: {err}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                let Ok(permit) = handshakes.clone().try_acquire_owned() else {
                    continue; // dropping the stream closes it
                };
                let acceptor = acceptor.clone();
                let sender = sender.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let handshake =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream));
                    if let Ok(Ok(stream)) = handshake.await {
                        let _ = sender.send((stream, peer)).await;
                    }
                });
            }
        });
        Ok(TlsListener { ready, local })
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(connection) => connection,
            // The accepting task never ends, so this does not happen.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(name: &str, text: &str) -> String {
        let path =
            std::env::temp_dir().join(format!("razorwire-tls-{}-{name}", std::process::id()));
        std::fs::write(&path, text).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn keys_that_are_not_pkcs8_are_explained() {
        let cert = write(
            "cert.pem",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        );
        let rsa = write(
            "rsa.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----\n",
        );
        let err = acceptor(&cert, &rsa).err().unwrap();
        assert!(err.contains("PKCS#8"), "{err}");
        assert!(!err.contains("secret"), "errors must not show the key");

        let key = write(
            "key.pem",
            "\u{feff}\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
        );
        let not_cert = write("not-cert.pem", "hello");
        let err = acceptor(&not_cert, &key).err().unwrap();
        assert!(err.contains("PEM certificate"), "{err}");

        let err = acceptor(&cert, &key).err().unwrap();
        assert!(err.contains("cannot be used"), "{err}");
        assert!(!err.contains("secret"), "errors must not show the key");

        let err = acceptor("no-such-cert.pem", &key).err().unwrap();
        assert!(err.contains("cannot read TLS_CERT"), "{err}");
    }
}
