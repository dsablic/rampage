//! Byte transports to an operator-started stub: TCP `host:port` and Unix socket paths.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::DebugError;

/// A connected byte stream. Reads honor the timeout last set, so a silent stub cannot block a command forever.
pub trait Transport: Read + Write + Send {
    fn set_read_timeout(&mut self, timeout: Duration) -> io::Result<()>;
    /// Closes both directions; later reads and writes fail.
    fn shutdown(&mut self);
}

impl Transport for TcpStream {
    fn set_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        TcpStream::set_read_timeout(self, Some(timeout.max(Duration::from_millis(1))))
    }

    fn shutdown(&mut self) {
        let _ = TcpStream::shutdown(self, std::net::Shutdown::Both);
    }
}

#[cfg(unix)]
impl Transport for std::os::unix::net::UnixStream {
    fn set_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, Some(timeout.max(Duration::from_millis(1))))
    }

    fn shutdown(&mut self) {
        let _ = std::os::unix::net::UnixStream::shutdown(self, std::net::Shutdown::Both);
    }
}

/// Where a stub listens, as the operator configured it: `host:port`, or `unix:` followed by a socket path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Tcp { host: String, port: u16 },
    Unix(PathBuf),
}

impl std::str::FromStr for Endpoint {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if let Some(path) = text.strip_prefix("unix:") {
            if !path.starts_with('/') || path.contains('\0') {
                return Err(format!("debug endpoint `{text}`: a Unix socket path must be absolute"));
            }
            return Ok(Endpoint::Unix(PathBuf::from(path)));
        }
        let (host, port) = text
            .rsplit_once(':')
            .ok_or_else(|| format!("debug endpoint `{text}`: expected host:port or unix:/path"))?;
        let host = host.strip_prefix('[').and_then(|host| host.strip_suffix(']')).unwrap_or(host);
        let port: u16 = port
            .parse()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("debug endpoint `{text}`: invalid port"))?;
        if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c == '/') {
            return Err(format!("debug endpoint `{text}`: invalid host"));
        }
        Ok(Endpoint::Tcp { host: host.to_owned(), port })
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Tcp { host, port } if host.contains(':') => write!(formatter, "[{host}]:{port}"),
            Endpoint::Tcp { host, port } => write!(formatter, "{host}:{port}"),
            Endpoint::Unix(path) => write!(formatter, "unix:{}", path.display()),
        }
    }
}

impl Endpoint {
    /// Whether the endpoint can only reach this machine: a Unix socket, or a host that is a loopback address or
    /// `localhost`. Others are reachable only because the operator listed them.
    pub fn is_local(&self) -> bool {
        match self {
            Endpoint::Unix(_) => true,
            Endpoint::Tcp { host, .. } => {
                host.eq_ignore_ascii_case("localhost")
                    || host.parse::<std::net::IpAddr>().is_ok_and(|address| address.is_loopback())
            }
        }
    }

    /// Opens the endpoint within `timeout` in all, name resolution and every address tried included. Nothing is
    /// sent. A resolver that hangs is abandoned (its thread finishes on its own) when the timeout passes.
    pub fn connect(&self, timeout: Duration) -> Result<Box<dyn Transport>, DebugError> {
        let failed = |error: io::Error| DebugError::Connect(format!("{self}: {error}"));
        let deadline = Instant::now() + timeout;
        match self {
            Endpoint::Tcp { host, port } => {
                let addresses: Vec<SocketAddr> = match host.parse::<std::net::IpAddr>() {
                    Ok(address) => vec![SocketAddr::new(address, *port)],
                    Err(_) => {
                        let (sender, receiver) = std::sync::mpsc::channel();
                        let name = (host.clone(), *port);
                        std::thread::Builder::new()
                            .name("rampage-debug-resolve".into())
                            .spawn(move || {
                                let resolved = name.to_socket_addrs().map(|addresses| addresses.take(8).collect());
                                let _ = sender.send(resolved);
                            })
                            .map_err(failed)?;
                        match receiver.recv_timeout(timeout) {
                            Ok(resolved) => resolved.map_err(failed)?,
                            Err(_) => return Err(failed(io::Error::new(io::ErrorKind::TimedOut, "name resolution"))),
                        }
                    }
                };
                let mut last = None;
                for address in addresses {
                    let Some(remaining) =
                        deadline.checked_duration_since(Instant::now()).filter(|remaining| !remaining.is_zero())
                    else {
                        break;
                    };
                    match TcpStream::connect_timeout(&address, remaining) {
                        Ok(stream) => {
                            stream.set_nodelay(true).map_err(failed)?;
                            stream.set_write_timeout(Some(timeout)).map_err(failed)?;
                            return Ok(Box::new(stream));
                        }
                        Err(error) => last = Some(error),
                    }
                }
                Err(failed(
                    last.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "no address answered in time")),
                ))
            }
            #[cfg(unix)]
            Endpoint::Unix(path) => {
                // Unix connects complete or fail immediately; only a full listen backlog could wait, and the
                // write timeout below bounds what follows.
                let stream = std::os::unix::net::UnixStream::connect(path).map_err(failed)?;
                stream.set_write_timeout(Some(timeout)).map_err(failed)?;
                Ok(Box::new(stream))
            }
            #[cfg(not(unix))]
            Endpoint::Unix(_) => Err(DebugError::Connect("Unix socket endpoints are unavailable here".into())),
        }
    }
}

impl Transport for Box<dyn Transport> {
    fn set_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        (**self).set_read_timeout(timeout)
    }

    fn shutdown(&mut self) {
        (**self).shutdown()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays_endpoints() {
        for (text, local) in [
            ("127.0.0.1:2345", true),
            ("localhost:1234", true),
            ("[::1]:2345", true),
            ("unix:/tmp/gdb.sock", true),
            ("10.0.0.5:3333", false),
            ("board.lab:3333", false),
        ] {
            let endpoint: Endpoint = text.parse().unwrap();
            assert_eq!(endpoint.to_string(), text);
            assert_eq!(endpoint.is_local(), local, "{text}");
        }
        for text in ["", "2345", "host:", "host:0", "host:99999", "unix:relative", ":2345", "a b:1"] {
            assert!(text.parse::<Endpoint>().is_err(), "{text}");
        }
    }
}
