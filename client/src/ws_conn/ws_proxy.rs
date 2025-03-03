use std::io::Error;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use url::Url;

use crate::ws_conn::PROXY_ADDR;

pub async fn connect_async(target: &str) -> Result<ProxyStream, Error> {
    let target_url = Url::parse(target)
        .unwrap_or_else(|_| panic!("failed to parse target url: {}", target));
    let host = match target_url.host_str() {
        Some(host) => host.to_string(),
        None => return Err(Error::new(ErrorKind::Unsupported, "target host not available")),
    };
    let port = target_url.port().unwrap_or(443);
    let stream = Socks5Stream::connect(PROXY_ADDR, (host.as_str(), port)).await;
    match stream {
        Ok(s) => Ok(ProxyStream(s)),
        Err(_) => Err(Error::new(ErrorKind::NotConnected, "failed to create socks proxy stream"))
    }
}

pub struct ProxyStream(Socks5Stream<TcpStream>);

impl AsyncRead for ProxyStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyStream(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            ProxyStream(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            ProxyStream(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            ProxyStream(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
