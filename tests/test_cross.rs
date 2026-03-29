// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

/// Cross-protocol tests: OpenSSL kTLS client <-> rustls TLS server (and vice
/// versa)
#[cfg(all(feature = "openssl", feature = "rustls"))]
mod ossl_rustls_cross_tests {
    use std::sync::Arc;

    use compio::{
        io::{AsyncRead, AsyncWrite, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        tls::TlsConnector,
    };
    use compio_ktls::{KtlsAcceptor, KtlsConnector};
    use openssl::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};

    fn make_ossl_server_config() -> Arc<SslAcceptor> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
        builder
            .set_certificate_chain_file("tests/fixtures/cert.pem")
            .unwrap();
        builder
            .set_private_key_file("tests/fixtures/key.pem", SslFiletype::PEM)
            .unwrap();
        Arc::new(builder.build())
    }

    fn make_ossl_client_config() -> Arc<SslConnector> {
        let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        Arc::new(builder.build())
    }

    fn make_rustls_server_config() -> Arc<rustls::server::ServerConfig> {
        let cert_pem = std::fs::read("tests/fixtures/cert.pem").unwrap();
        let key_pem = std::fs::read("tests/fixtures/key.pem").unwrap();
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .unwrap()
            .unwrap();
        Arc::new(
            rustls::server::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        )
    }

    fn make_rustls_client_config() -> Arc<rustls::ClientConfig> {
        Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth(),
        )
    }

    /// Test OpenSSL kTLS client connecting to a rustls TLS server
    #[compio::test]
    async fn test_ossl_ktls_client_to_rustls_server() {
        let server_config = make_rustls_server_config();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        compio::runtime::spawn(async move {
            let acceptor = compio::tls::TlsAcceptor::from(server_config);
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();

            // Echo server
            let buf = vec![0u8; 1024];
            let (n, buf) = stream.read(buf).await.unwrap();
            stream.write_all(buf[..n].to_vec()).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.ok();
        })
        .detach();

        let client_config = make_ossl_client_config();
        let connector = KtlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();

        match connector.connect("localhost", stream).await.unwrap() {
            Ok(mut ktls_stream) => {
                let msg = b"Hello cross-protocol kTLS!";
                ktls_stream.write_all(msg.to_vec()).await.unwrap();
                ktls_stream.flush().await.unwrap();

                let (n, buf) = ktls_stream.read(vec![0u8; 1024]).await.unwrap();
                assert_eq!(&buf[..n], msg);
                ktls_stream.shutdown().await.ok();
            }
            Err(stream) => {
                drop(stream);
                eprintln!("Warning: kTLS not available on this system");
            }
        }
    }

    /// Test OpenSSL kTLS server accepting connection from rustls TLS client
    #[compio::test]
    async fn test_ossl_ktls_server_from_rustls_client() {
        let server_config = make_ossl_server_config();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        compio::runtime::spawn(async move {
            let acceptor = KtlsAcceptor::from(server_config);
            let (stream, _) = listener.accept().await.unwrap();

            match acceptor.accept(stream).await.unwrap() {
                Ok(mut ktls_stream) => {
                    let buf = vec![0u8; 1024];
                    let (n, buf) = ktls_stream.read(buf).await.unwrap();
                    ktls_stream.write_all(buf[..n].to_vec()).await.unwrap();
                    ktls_stream.flush().await.unwrap();
                    ktls_stream.shutdown().await.ok();
                }
                Err(mut stream) => {
                    stream.shutdown().await.ok();
                }
            }
        })
        .detach();

        let client_config = make_rustls_client_config();
        let connector = TlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut stream = connector.connect("localhost", stream).await.unwrap();

        let msg = b"Hello from rustls to OpenSSL kTLS!";
        stream.write_all(msg.to_vec()).await.unwrap();
        stream.flush().await.unwrap();

        let (n, buf) = stream.read(vec![0u8; 1024]).await.unwrap();
        assert_eq!(&buf[..n], msg);
        stream.shutdown().await.ok();
    }

    #[derive(Debug)]
    struct NoVerifier;

    impl rustls::client::danger::ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }
}
