// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

#[cfg(feature = "rustls")]
mod ktls_tests {
    use std::sync::Arc;

    use compio::{
        io::{AsyncRead, AsyncWrite, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        tls::TlsConnector,
    };
    use compio_ktls::{KtlsAcceptor, KtlsConnector};

    /// Test client connecting with kTLS to a regular TLS server
    #[compio::test]
    async fn test_ktls_client_to_tls_server() {
        // Load test certificates for server
        let cert_pem = std::fs::read("tests/fixtures/cert.pem").unwrap();
        let key_pem = std::fs::read("tests/fixtures/key.pem").unwrap();
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .unwrap()
            .unwrap();

        let server_config = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        // Start server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn server task
        compio::runtime::spawn(async move {
            let acceptor = compio::tls::TlsAcceptor::from(Arc::new(server_config));
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

        // Connect with kTLS client
        let mut client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        client_config.enable_secret_extraction = true;

        let connector = KtlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(addr).await.unwrap();

        let result = connector.connect("localhost", stream).await.unwrap();
        match result {
            Ok(mut ktls_stream) => {
                // Test data transfer
                let msg = b"Hello kTLS!";
                ktls_stream.write_all(msg.to_vec()).await.unwrap();
                ktls_stream.flush().await.unwrap();
                let (n, buf) = ktls_stream.read(vec![0u8; 1024]).await.unwrap();
                assert_eq!(&buf[..n], msg);
                ktls_stream.shutdown().await.ok();
            }
            Err(stream) => {
                // kTLS not available, skip test
                drop(stream);
            }
        }
    }

    /// Test kTLS server accepting connections from regular TLS client
    #[compio::test]
    async fn test_ktls_server_from_tls_client() {
        // Load test certificates
        let cert_pem = std::fs::read("tests/fixtures/cert.pem").unwrap();
        let key_pem = std::fs::read("tests/fixtures/key.pem").unwrap();
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .unwrap()
            .unwrap();

        let mut server_config = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        server_config.enable_secret_extraction = true;

        // Start kTLS server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn server task
        compio::runtime::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();

            let acceptor = KtlsAcceptor::from(Arc::new(server_config));
            let result = acceptor.accept(stream).await.unwrap();

            match result {
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

        // Connect as client (in main task)
        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(addr).await.unwrap();

        let mut stream = connector.connect("localhost", stream).await.unwrap();

        // Send and receive
        let msg = b"Hello from client!";
        stream.write_all(msg.to_vec()).await.unwrap();
        stream.flush().await.unwrap();

        let (n, buf) = stream.read(vec![0u8; 1024]).await.unwrap();
        assert_eq!(&buf[..n], msg);

        stream.shutdown().await.ok();
    }

    /// Test full kTLS: both client and server use kTLS
    #[compio::test]
    async fn test_full_ktls_connection() {
        // Load test certificates
        let cert_pem = std::fs::read("tests/fixtures/cert.pem").unwrap();
        let key_pem = std::fs::read("tests/fixtures/key.pem").unwrap();
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .unwrap()
            .unwrap();

        let mut server_config = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        server_config.enable_secret_extraction = true;

        // Start kTLS server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn server task
        let server_handle = compio::runtime::spawn(async move {
            let acceptor = KtlsAcceptor::from(Arc::new(server_config));
            let (stream, _) = listener.accept().await.unwrap();

            match acceptor.accept(stream).await.unwrap() {
                Ok(mut ktls_stream) => {
                    // Echo large data to test kTLS performance
                    let buf = vec![0u8; 8192];
                    let (n, buf) = ktls_stream.read(buf).await.unwrap();
                    ktls_stream.write_all(buf[..n].to_vec()).await.unwrap();
                    ktls_stream.flush().await.unwrap();
                    ktls_stream.shutdown().await.ok();
                    true
                }
                Err(mut stream) => {
                    stream.shutdown().await.ok();
                    false
                }
            }
        });

        // Connect with kTLS client
        let mut client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        client_config.enable_secret_extraction = true;

        let connector = KtlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(addr).await.unwrap();

        let client_ktls = match connector.connect("localhost", stream).await.unwrap() {
            Ok(mut ktls_stream) => {
                // Send large data
                let data = vec![0x42u8; 8192];
                ktls_stream.write_all(data.clone()).await.unwrap();
                ktls_stream.flush().await.unwrap();
                let (n, buf) = ktls_stream.read(vec![0u8; 8192]).await.unwrap();
                assert_eq!(&buf[..n], &data[..]);
                ktls_stream.shutdown().await.ok();
                true
            }
            Err(stream) => {
                drop(stream);
                false
            }
        };

        let server_ktls = server_handle.await.unwrap();

        // At least one side should use kTLS
        // (or both sides if kTLS is available)
        if !client_ktls && !server_ktls {
            eprintln!("Warning: kTLS not available on this system");
        }
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
