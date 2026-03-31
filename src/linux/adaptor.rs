// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{io, os::fd::AsFd, sync::Arc};

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
    #[cfg(feature = "openssl")]
    OpenSsl {
        connector: Arc<openssl::ssl::SslConnector>,
        memmem_mode: Option<super::ossl::MemmemMode>,
    },
    #[cfg(not(any(feature = "rustls", feature = "openssl")))]
    None(std::convert::Infallible),
}

#[cfg(feature = "rustls")]
impl From<Arc<rustls::ClientConfig>> for KtlsConnector {
    fn from(c: Arc<rustls::ClientConfig>) -> Self {
        Self(KtlsConnectorInner::Rustls(c))
    }
}

#[cfg(feature = "openssl")]
impl From<Arc<openssl::ssl::SslConnector>> for KtlsConnector {
    fn from(connector: Arc<openssl::ssl::SslConnector>) -> Self {
        Self(KtlsConnectorInner::OpenSsl {
            connector,
            memmem_mode: None,
        })
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
            #[cfg(feature = "openssl")]
            KtlsConnectorInner::OpenSsl { .. } => {}
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
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
                #[cfg(feature = "openssl")]
                KtlsConnectorInner::OpenSsl {
                    connector: c,
                    memmem_mode: mode,
                } => {
                    let mode = mode.unwrap_or(super::ossl::MemmemMode::Fork);
                    super::ossl::connect_ktls(c.clone(), domain, stream, mode).await?
                }
                #[cfg(not(any(feature = "rustls", feature = "openssl")))]
                KtlsConnectorInner::None(v) => match *v {},
            })),
            Err(e) if e.is_ktls_unsupported() => Ok(Err(stream)),
            Err(ktls_core::Error::Ulp(e)) => Err(e),
            // Only Ulp variant can be returned from setup_ulp
            _ => unreachable!(),
        }
    }

    #[cfg(feature = "openssl")]
    pub fn set_memmem_mode(&mut self, mode: super::ossl::MemmemMode) {
        if let KtlsConnectorInner::OpenSsl { memmem_mode, .. } = &mut self.0 {
            *memmem_mode = Some(mode);
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
    #[cfg(feature = "openssl")]
    OpenSsl {
        acceptor: Arc<openssl::ssl::SslAcceptor>,
        memmem_mode: Option<super::ossl::MemmemMode>,
    },
    #[cfg(not(any(feature = "rustls", feature = "openssl")))]
    None(std::convert::Infallible),
}

#[cfg(feature = "rustls")]
impl From<Arc<rustls::server::ServerConfig>> for KtlsAcceptor {
    fn from(c: Arc<rustls::server::ServerConfig>) -> Self {
        Self(KtlsAcceptorInner::Rustls(c))
    }
}

#[cfg(feature = "openssl")]
impl From<Arc<openssl::ssl::SslAcceptor>> for KtlsAcceptor {
    fn from(acceptor: Arc<openssl::ssl::SslAcceptor>) -> Self {
        Self(KtlsAcceptorInner::OpenSsl {
            acceptor,
            memmem_mode: None,
        })
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
            #[cfg(feature = "openssl")]
            KtlsAcceptorInner::OpenSsl { .. } => {}
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsAcceptorInner::None(_) => return Ok(Err(stream)),
        }
        match ktls_core::setup_ulp(&stream) {
            Ok(()) => Ok(Ok(match &self.0 {
                #[cfg(feature = "rustls")]
                KtlsAcceptorInner::Rustls(c) => super::rtls::accept_ktls(c.clone(), stream).await?,
                #[cfg(feature = "openssl")]
                KtlsAcceptorInner::OpenSsl {
                    acceptor,
                    memmem_mode: mode,
                } => {
                    let mode = mode.unwrap_or(super::ossl::MemmemMode::Fork);
                    super::ossl::accept_ktls(acceptor.clone(), stream, mode).await?
                }
                #[cfg(not(any(feature = "rustls", feature = "openssl")))]
                KtlsAcceptorInner::None(v) => match *v {},
            })),
            Err(e) if e.is_ktls_unsupported() => Ok(Err(stream)),
            Err(ktls_core::Error::Ulp(e)) => Err(e),
            // Only Ulp variant can be returned from setup_ulp
            _ => unreachable!(),
        }
    }

    #[cfg(feature = "openssl")]
    pub fn set_memmem_mode(&mut self, mode: super::ossl::MemmemMode) {
        if let KtlsAcceptorInner::OpenSsl { memmem_mode, .. } = &mut self.0 {
            *memmem_mode = Some(mode);
        }
    }
}

#[cfg(feature = "rustls")]
type RustlsClientConnection<S> =
    KtlsDuplexStream<S, rustls::kernel::KernelConnection<rustls::client::ClientConnectionData>>;
#[cfg(feature = "rustls")]
type RustlsServerConnection<S> =
    KtlsDuplexStream<S, rustls::kernel::KernelConnection<rustls::server::ServerConnectionData>>;
#[cfg(feature = "openssl")]
type OpenSslConnection<S> = KtlsDuplexStream<S, super::ossl::KtlsSession<S>>;

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
    #[cfg(feature = "openssl")]
    OpenSsl(OpenSslConnection<S>),
    #[cfg(not(any(feature = "rustls", feature = "openssl")))]
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

#[cfg(feature = "openssl")]
impl<S> From<OpenSslConnection<S>> for KtlsStream<S> {
    fn from(s: OpenSslConnection<S>) -> Self {
        Self(KtlsStreamInner::OpenSsl(s))
    }
}

impl<S> KtlsStream<S>
where
    S: AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd,
{
    /// Initiates a TLS 1.3 key update.
    ///
    /// This updates the outgoing (TX) traffic secret. If `request_peer` is
    /// `true`, the peer is also asked to update its outgoing secret so that
    /// both directions will use fresh keys after the next round-trip.
    #[cfg(key_update)]
    pub async fn key_update(&mut self, request_peer: bool) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.key_update(request_peer).await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.key_update(request_peer).await,
            #[cfg(feature = "openssl")]
            KtlsStreamInner::OpenSsl(s) => s.key_update(request_peer).await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
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
            #[cfg(feature = "openssl")]
            KtlsStreamInner::OpenSsl(s) => s.read(buf).await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }

    async fn read_vectored<V: IoVectoredBufMut>(&mut self, buf: V) -> BufResult<usize, V> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.read_vectored(buf).await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.read_vectored(buf).await,
            #[cfg(feature = "openssl")]
            KtlsStreamInner::OpenSsl(s) => s.read_vectored(buf).await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
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
            #[cfg(feature = "openssl")]
            KtlsStreamInner::OpenSsl(s) => s.write(buf).await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }

    async fn write_vectored<V: IoVectoredBuf>(&mut self, buf: V) -> BufResult<usize, V> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.write_vectored(buf).await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.write_vectored(buf).await,
            #[cfg(feature = "openssl")]
            KtlsStreamInner::OpenSsl(s) => s.write_vectored(buf).await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.flush().await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.flush().await,
            #[cfg(feature = "openssl")]
            KtlsStreamInner::OpenSsl(s) => s.flush().await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsStreamInner::None(f, ..) => match *f {},
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsClient(s) => s.shutdown().await,
            #[cfg(feature = "rustls")]
            KtlsStreamInner::RustlsServer(s) => s.shutdown().await,
            #[cfg(feature = "openssl")]
            KtlsStreamInner::OpenSsl(s) => s.shutdown().await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
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
            #[cfg(feature = "openssl")]
            KtlsStreamInner::OpenSsl(s) => {
                let (r, w) = s.split();
                let r = KtlsReadHalf(KtlsReadHalfInner::OpenSsl(r));
                let w = KtlsWriteHalf(KtlsWriteHalfInner::OpenSsl(w));
                (r, w)
            }
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
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
#[cfg(feature = "openssl")]
type OpenSslReadHalf<S> = ReadHalf<S, super::ossl::KtlsSession<S>>;

enum KtlsReadHalfInner<S> {
    #[cfg(feature = "rustls")]
    RustlsClient(RustlsClientReadHalf<S>),
    #[cfg(feature = "rustls")]
    RustlsServer(RustlsServerReadHalf<S>),
    #[cfg(feature = "openssl")]
    OpenSsl(OpenSslReadHalf<S>),
    #[cfg(not(any(feature = "rustls", feature = "openssl")))]
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
            #[cfg(feature = "openssl")]
            KtlsReadHalfInner::OpenSsl(s) => s.read(buf).await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsReadHalfInner::None(f, ..) => match *f {},
        }
    }

    async fn read_vectored<V: IoVectoredBufMut>(&mut self, buf: V) -> BufResult<usize, V> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsReadHalfInner::RustlsClient(s) => s.read_vectored(buf).await,
            #[cfg(feature = "rustls")]
            KtlsReadHalfInner::RustlsServer(s) => s.read_vectored(buf).await,
            #[cfg(feature = "openssl")]
            KtlsReadHalfInner::OpenSsl(s) => s.read_vectored(buf).await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsReadHalfInner::None(f, ..) => match *f {},
        }
    }
}

pub struct KtlsWriteHalf<S>(KtlsWriteHalfInner<S>);

impl<S> KtlsWriteHalf<S>
where
    S: AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd,
{
    /// Initiates a TLS 1.3 key update.
    ///
    /// This updates the outgoing (TX) traffic secret. If `request_peer` is
    /// `true`, the peer is also asked to update its outgoing secret so that
    /// both directions will use fresh keys after the next round-trip.
    #[cfg(key_update)]
    pub async fn key_update(&mut self, request_peer: bool) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsClient(s) => s.key_update(request_peer).await,
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsServer(s) => s.key_update(request_peer).await,
            #[cfg(feature = "openssl")]
            KtlsWriteHalfInner::OpenSsl(s) => s.key_update(request_peer).await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsWriteHalfInner::None(f, ..) => match *f {},
        }
    }
}

#[cfg(feature = "rustls")]
type RustlsClientWriteHalf<S> =
    WriteHalf<S, rustls::kernel::KernelConnection<rustls::client::ClientConnectionData>>;
#[cfg(feature = "rustls")]
type RustlsServerWriteHalf<S> =
    WriteHalf<S, rustls::kernel::KernelConnection<rustls::server::ServerConnectionData>>;
#[cfg(feature = "openssl")]
type OpenSslWriteHalf<S> = WriteHalf<S, super::ossl::KtlsSession<S>>;

enum KtlsWriteHalfInner<S> {
    #[cfg(feature = "rustls")]
    RustlsClient(RustlsClientWriteHalf<S>),
    #[cfg(feature = "rustls")]
    RustlsServer(RustlsServerWriteHalf<S>),
    #[cfg(feature = "openssl")]
    OpenSsl(OpenSslWriteHalf<S>),
    #[cfg(not(any(feature = "rustls", feature = "openssl")))]
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
            #[cfg(feature = "openssl")]
            KtlsWriteHalfInner::OpenSsl(s) => s.write(buf).await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsWriteHalfInner::None(f, ..) => match *f {},
        }
    }

    async fn write_vectored<V: IoVectoredBuf>(&mut self, buf: V) -> BufResult<usize, V> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsClient(s) => s.write_vectored(buf).await,
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsServer(s) => s.write_vectored(buf).await,
            #[cfg(feature = "openssl")]
            KtlsWriteHalfInner::OpenSsl(s) => s.write_vectored(buf).await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsWriteHalfInner::None(f, ..) => match *f {},
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsClient(s) => s.flush().await,
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsServer(s) => s.flush().await,
            #[cfg(feature = "openssl")]
            KtlsWriteHalfInner::OpenSsl(s) => s.flush().await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsWriteHalfInner::None(f, ..) => match *f {},
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsClient(s) => s.shutdown().await,
            #[cfg(feature = "rustls")]
            KtlsWriteHalfInner::RustlsServer(s) => s.shutdown().await,
            #[cfg(feature = "openssl")]
            KtlsWriteHalfInner::OpenSsl(s) => s.shutdown().await,
            #[cfg(not(any(feature = "rustls", feature = "openssl")))]
            KtlsWriteHalfInner::None(f, ..) => match *f {},
        }
    }
}
