// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{borrow::Cow, io, os::fd::AsFd, sync::Arc};

use compio_buf::{BufResult, IoBuf, IoBufMut, IoVectoredBuf, IoVectoredBufMut};
use compio_io::{
    AsyncRead, AsyncWrite,
    ancillary::{AsyncReadAncillary, AsyncWriteAncillary},
    util::Splittable,
};

use super::stream::{KtlsDuplexStream, ReadHalf, WriteHalf};

/// A kTLS connector for establishing client-side TLS connections.
///
/// This connector performs the TLS handshake in userspace and then offloads
/// the encryption/decryption to the Linux kernel for better performance.
///
/// # Example
///
/// ```
/// # compio::runtime::Runtime::new().unwrap().block_on(async {
/// # use std::sync::Arc;
/// #
/// use compio::{io::AsyncWrite, net::TcpStream};
/// use compio_ktls::KtlsConnector;
///
/// // Setup rustls client config with secret extraction enabled
/// # let mut roots = rustls::RootCertStore::empty();
/// # for cert in rustls_native_certs::load_native_certs().unwrap() {
/// #     roots.add(cert).unwrap();
/// # }
/// let mut config = rustls::ClientConfig::builder()
///     .with_root_certificates(roots)
///     .with_no_client_auth();
/// config.enable_secret_extraction = true;
/// let connector = KtlsConnector::from(Arc::new(config));
///
/// // Attempt to connect with kTLS
/// let tcp_stream = TcpStream::connect("github.com:443").await.unwrap();
/// match connector.connect("github.com", tcp_stream).await.unwrap() {
///     Ok(mut ktls_stream) => {
///         // kTLS enabled successfully
///         ktls_stream.shutdown().await.unwrap();
///     }
///     Err(mut stream) => {
///         // kTLS unavailable, use the original stream
///         stream.shutdown().await.unwrap();
///     }
/// }
/// # })
/// ```
#[derive(Clone)]
pub struct KtlsConnector(KtlsConnectorInner);

#[derive(Clone)]
enum KtlsConnectorInner {
    #[cfg(feature = "rustls")]
    Rustls(Arc<rustls::ClientConfig>),
    #[cfg(not(feature = "rustls"))]
    None(std::convert::Infallible),
}

#[cfg(feature = "rustls")]
impl From<Arc<rustls::ClientConfig>> for KtlsConnector {
    fn from(c: Arc<rustls::ClientConfig>) -> Self {
        Self(KtlsConnectorInner::Rustls(c))
    }
}

impl KtlsConnector {
    pub async fn connect<S>(&self, domain: &str, stream: S) -> io::Result<Result<KtlsStream<S>, S>>
    where
        S: AsyncRead + AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd + 'static,
    {
        match &self.0 {
            #[cfg(feature = "rustls")]
            KtlsConnectorInner::Rustls(c) => {
                if !c.enable_secret_extraction {
                    return Ok(Err(stream));
                }
            }
            #[cfg(not(feature = "rustls"))]
            KtlsConnectorInner::None(_) => return Ok(Err(stream)),
        }
        match ktls_core::setup_ulp(&stream) {
            Ok(()) => Ok(Ok(match &self.0 {
                #[cfg(feature = "rustls")]
                KtlsConnectorInner::Rustls(c) => {
                    super::rtls::connect_ktls(
                        c.clone(),
                        domain.to_string().try_into().map_err(io::Error::other)?,
                        stream,
                    )
                    .await?
                }
                #[cfg(not(feature = "rustls"))]
                KtlsConnectorInner::None(v) => match *v {},
            })),
            Err(e) if e.is_ktls_unsupported() => Ok(Err(stream)),
            Err(ktls_core::Error::Ulp(e)) => Err(e),
            // Only Ulp variant can be returned from setup_ulp
            _ => unreachable!(),
        }
    }
}

/// A kTLS acceptor for establishing server-side TLS connections.
///
/// This acceptor performs the TLS handshake in userspace and then offloads
/// the encryption/decryption to the Linux kernel for better performance.
///
/// # Example
///
/// ```
/// # use std::{fs, sync::Arc};
/// #
/// use compio::{io::AsyncWrite, net::TcpListener, tls::TlsAcceptor};
/// use compio_ktls::KtlsAcceptor;
///
/// # compio::runtime::Runtime::new().unwrap().block_on(async {
/// #
/// # // Load test certificates
/// # let cert_pem = fs::read("tests/fixtures/cert.pem").unwrap();
/// # let key_pem = fs::read("tests/fixtures/key.pem").unwrap();
/// # let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
/// #     .collect::<Result<Vec<_>, _>>()
/// #     .unwrap();
/// # let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
/// #     .unwrap()
/// #     .unwrap();
/// #
/// // Setup rustls server config with secret extraction enabled
/// let mut config = rustls::server::ServerConfig::builder()
///     .with_no_client_auth()
///     .with_single_cert(certs, key)
///     .unwrap();
/// config.enable_secret_extraction = true;
/// let config = Arc::new(config);
///
/// // Start a server
/// let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
///
/// # let addr = listener.local_addr().unwrap();
/// # compio::runtime::spawn(async move {
/// #     use compio::{net::TcpStream, tls::TlsConnector};
/// #
/// #     let mut client_config = rustls::ClientConfig::builder()
/// #         .dangerous()
/// #         .with_custom_certificate_verifier(Arc::new(NoVerifier))
/// #         .with_no_client_auth();
/// #     let stream = TcpStream::connect(addr).await.unwrap();
/// #     let connector = TlsConnector::from(Arc::new(client_config));
/// #     let mut stream = connector.connect("localhost", stream).await.unwrap();
/// #     stream.shutdown().await.ok();
/// # })
/// # .detach();
/// #
/// // Accept a connection with kTLS
/// let (stream, _) = listener.accept().await.unwrap();
/// let acceptor = KtlsAcceptor::from(config.clone());
/// match acceptor.accept(stream).await.unwrap() {
///     Ok(mut ktls_stream) => {
///         // kTLS enabled successfully
///         ktls_stream.shutdown().await.ok();
///     }
///     Err(mut stream) => {
///         // kTLS unavailable, fallback to original stream
///         let acceptor = TlsAcceptor::from(config);
///         let mut stream = acceptor.accept(stream).await.unwrap();
///         stream.shutdown().await.ok();
///     }
/// }
/// #
/// # #[derive(Debug)]
/// # struct NoVerifier;
/// # impl rustls::client::danger::ServerCertVerifier for NoVerifier {
/// #     fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>], _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> { Ok(rustls::client::danger::ServerCertVerified::assertion()) }
/// #     fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) }
/// #     fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) }
/// #     fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { vec![rustls::SignatureScheme::RSA_PSS_SHA256, rustls::SignatureScheme::RSA_PSS_SHA384, rustls::SignatureScheme::RSA_PSS_SHA512, rustls::SignatureScheme::RSA_PKCS1_SHA256, rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ED25519] }
/// # }
/// # })
/// ```
#[derive(Clone)]
pub struct KtlsAcceptor(KtlsAcceptorInner);

#[derive(Clone)]
enum KtlsAcceptorInner {
    #[cfg(feature = "rustls")]
    Rustls(Arc<rustls::server::ServerConfig>),
    #[cfg(not(feature = "rustls"))]
    None(std::convert::Infallible),
}

#[cfg(feature = "rustls")]
impl From<Arc<rustls::server::ServerConfig>> for KtlsAcceptor {
    fn from(c: Arc<rustls::server::ServerConfig>) -> Self {
        Self(KtlsAcceptorInner::Rustls(c))
    }
}

impl KtlsAcceptor {
    pub async fn accept<S>(&self, stream: S) -> io::Result<Result<KtlsStream<S>, S>>
    where
        S: AsyncRead + AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd + 'static,
    {
        match &self.0 {
            #[cfg(feature = "rustls")]
            KtlsAcceptorInner::Rustls(c) => {
                if !c.enable_secret_extraction || c.max_early_data_size > 0 {
                    return Ok(Err(stream));
                }
            }
            #[cfg(not(feature = "rustls"))]
            KtlsAcceptorInner::None(_) => return Ok(Err(stream)),
        }
        match ktls_core::setup_ulp(&stream) {
            Ok(()) => Ok(Ok(match &self.0 {
                #[cfg(feature = "rustls")]
                KtlsAcceptorInner::Rustls(c) => super::rtls::accept_ktls(c.clone(), stream).await?,
                #[cfg(not(feature = "rustls"))]
                KtlsAcceptorInner::None(v) => match *v {},
            })),
            Err(e) if e.is_ktls_unsupported() => Ok(Err(stream)),
            Err(ktls_core::Error::Ulp(e)) => Err(e),
            // Only Ulp variant can be returned from setup_ulp
            _ => unreachable!(),
        }
    }
}

#[cfg(feature = "rustls")]
type RustlsClientConnection<S> =
    KtlsDuplexStream<S, rustls::kernel::KernelConnection<rustls::client::ClientConnectionData>>;
#[cfg(feature = "rustls")]
type RustlsServerConnection<S> =
    KtlsDuplexStream<S, rustls::kernel::KernelConnection<rustls::server::ServerConnectionData>>;

/// A kTLS stream that encrypts/decrypts data in the Linux kernel.
///
/// This stream wraps an underlying transport stream and a TLS session,
/// offloading cryptographic operations to the kernel for better performance.
///
/// Implements [`AsyncRead`] and [`AsyncWrite`] traits for async I/O operations.
#[derive(Debug)]
pub struct KtlsStream<S>(KtlsStreamInner<S>);

#[derive(Debug)]
enum KtlsStreamInner<S> {
    #[cfg(feature = "rustls")]
    RustlsClient(RustlsClientConnection<S>),
    #[cfg(feature = "rustls")]
    RustlsServer(RustlsServerConnection<S>),
    #[cfg(not(feature = "rustls"))]
    None(std::convert::Infallible, std::marker::PhantomData<S>),
}

#[cfg(feature = "rustls")]
impl<S> From<RustlsClientConnection<S>> for KtlsStream<S> {
    fn from(s: RustlsClientConnection<S>) -> Self {
        Self(KtlsStreamInner::RustlsClient(s))
    }
}

#[cfg(feature = "rustls")]
impl<S> From<RustlsServerConnection<S>> for KtlsStream<S> {
    fn from(s: RustlsServerConnection<S>) -> Self {
        Self(KtlsStreamInner::RustlsServer(s))
    }
}

impl<S> KtlsStream<S> {
    pub fn negotiated_alpn(&self) -> Option<Cow<'_, [u8]>> {
        match &self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.alpn_protocol().map(Cow::from),
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.alpn_protocol().map(Cow::from),
            #[cfg(not(feature = "rustls"))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }
}

impl<S> AsyncRead for KtlsStream<S>
where
    S: AsyncRead + AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd,
{
    async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.read(buf).await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.read(buf).await,
            #[cfg(not(feature = "rustls"))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }

    async fn read_vectored<V: IoVectoredBufMut>(&mut self, buf: V) -> BufResult<usize, V> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.read_vectored(buf).await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.read_vectored(buf).await,
            #[cfg(not(feature = "rustls"))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }
}

impl<S> AsyncWrite for KtlsStream<S>
where
    S: AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd,
{
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.write(buf).await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.write(buf).await,
            #[cfg(not(feature = "rustls"))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }

    async fn write_vectored<V: IoVectoredBuf>(&mut self, buf: V) -> BufResult<usize, V> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.write_vectored(buf).await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.write_vectored(buf).await,
            #[cfg(not(feature = "rustls"))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.flush().await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.flush().await,
            #[cfg(not(feature = "rustls"))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.shutdown().await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.shutdown().await,
            #[cfg(not(feature = "rustls"))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }
}

impl<S> Splittable for KtlsStream<S>
where
    S: Clone,
{
    type ReadHalf = KtlsReadHalf<S>;
    type WriteHalf = KtlsWriteHalf<S>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        match self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => {
                let (r, w) = s.split();
                let r = KtlsReadHalf(KtlsReadHalfInner::RustlsClient(r));
                let w = KtlsWriteHalf(KtlsWriteHalfInner::RustlsClient(w));
                (r, w)
            }
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => {
                let (r, w) = s.split();
                let r = KtlsReadHalf(KtlsReadHalfInner::RustlsServer(r));
                let w = KtlsWriteHalf(KtlsWriteHalfInner::RustlsServer(w));
                (r, w)
            }
            #[cfg(not(feature = "rustls"))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }
}

pub struct KtlsReadHalf<S>(KtlsReadHalfInner<S>);

#[cfg(feature = "rustls")]
type RustlsClientReadHalf<S> =
    ReadHalf<S, rustls::kernel::KernelConnection<rustls::client::ClientConnectionData>>;
#[cfg(feature = "rustls")]
type RustlsServerReadHalf<S> =
    ReadHalf<S, rustls::kernel::KernelConnection<rustls::server::ServerConnectionData>>;

enum KtlsReadHalfInner<S> {
    #[cfg(feature = "rustls")]
    RustlsClient(RustlsClientReadHalf<S>),
    #[cfg(feature = "rustls")]
    RustlsServer(RustlsServerReadHalf<S>),
    #[cfg(not(feature = "rustls"))]
    None(std::convert::Infallible, std::marker::PhantomData<S>),
}

impl<S> AsyncRead for KtlsReadHalf<S>
where
    S: AsyncRead + AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd,
{
    async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsReadHalfInner::RustlsClient(s) => s.read(buf).await,
            #[cfg(feature = "rustls")]
            KtlsReadHalfInner::RustlsServer(s) => s.read(buf).await,
            #[cfg(not(feature = "rustls"))]
            KtlsReadHalfInner::None(f, ..) => match *f {},
        }
    }

    async fn read_vectored<V: IoVectoredBufMut>(&mut self, buf: V) -> BufResult<usize, V> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsReadHalfInner::RustlsClient(s) => s.read_vectored(buf).await,
            #[cfg(feature = "rustls")]
            KtlsReadHalfInner::RustlsServer(s) => s.read_vectored(buf).await,
            #[cfg(not(feature = "rustls"))]
            KtlsReadHalfInner::None(f, ..) => match *f {},
        }
    }
}

pub struct KtlsWriteHalf<S>(KtlsWriteHalfInner<S>);

#[cfg(feature = "rustls")]
type RustlsClientWriteHalf<S> =
    WriteHalf<S, rustls::kernel::KernelConnection<rustls::client::ClientConnectionData>>;
#[cfg(feature = "rustls")]
type RustlsServerWriteHalf<S> =
    WriteHalf<S, rustls::kernel::KernelConnection<rustls::server::ServerConnectionData>>;

enum KtlsWriteHalfInner<S> {
    #[cfg(feature = "rustls")]
    RustlsClient(RustlsClientWriteHalf<S>),
    #[cfg(feature = "rustls")]
    RustlsServer(RustlsServerWriteHalf<S>),
    #[cfg(not(feature = "rustls"))]
    None(std::convert::Infallible, std::marker::PhantomData<S>),
}

impl<S> AsyncWrite for KtlsWriteHalf<S>
where
    S: AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd,
{
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsClient(s) => s.write(buf).await,
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsServer(s) => s.write(buf).await,
            #[cfg(not(feature = "rustls"))]
            KtlsWriteHalfInner::None(f, ..) => match *f {},
        }
    }

    async fn write_vectored<V: IoVectoredBuf>(&mut self, buf: V) -> BufResult<usize, V> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsClient(s) => s.write_vectored(buf).await,
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsServer(s) => s.write_vectored(buf).await,
            #[cfg(not(feature = "rustls"))]
            KtlsWriteHalfInner::None(f, ..) => match *f {},
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsClient(s) => s.flush().await,
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsServer(s) => s.flush().await,
            #[cfg(not(feature = "rustls"))]
            KtlsWriteHalfInner::None(f, ..) => match *f {},
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsClient(s) => s.shutdown().await,
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsServer(s) => s.shutdown().await,
            #[cfg(not(feature = "rustls"))]
            KtlsWriteHalfInner::None(f, ..) => match *f {},
        }
    }
}
