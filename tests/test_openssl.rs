// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

#[cfg(feature = "openssl")]
mod ossl_ktls_tests {
    use std::sync::Arc;

    use compio::{
        io::{AsyncRead, AsyncWrite, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use compio_ktls::{KtlsAcceptor, KtlsConnector};
    use openssl::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};

    fn make_server_config() -> Arc<SslAcceptor> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
        builder
            .set_certificate_chain_file("tests/fixtures/cert.pem")
            .unwrap();
        builder
            .set_private_key_file("tests/fixtures/key.pem", SslFiletype::PEM)
            .unwrap();
        Arc::new(builder.build())
    }

    fn make_client_config() -> Arc<SslConnector> {
        let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        Arc::new(builder.build())
    }

    /// Test full kTLS: both client and server use OpenSSL kTLS
    #[compio::test]
    async fn test_ossl_full_ktls_connection() {
        let server_config = make_server_config();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        compio::runtime::spawn(async move {
            let acceptor = KtlsAcceptor::from(server_config);
            let (stream, _) = listener.accept().await.unwrap();

            match acceptor.accept(stream).await.unwrap() {
                Ok(mut ktls_stream) => {
                    // Echo server
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

        let client_config = make_client_config();
        let connector = KtlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();

        match connector.connect("localhost", stream).await.unwrap() {
            Ok(mut ktls_stream) => {
                let msg = b"Hello OpenSSL kTLS!";
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

    /// Test full kTLS with large data transfer
    #[compio::test]
    async fn test_ossl_full_ktls_large_data() {
        let server_config = make_server_config();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = compio::runtime::spawn(async move {
            let acceptor = KtlsAcceptor::from(server_config);
            let (stream, _) = listener.accept().await.unwrap();

            match acceptor.accept(stream).await.unwrap() {
                Ok(mut ktls_stream) => {
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

        let client_config = make_client_config();
        let connector = KtlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();

        let client_ktls = match connector.connect("localhost", stream).await.unwrap() {
            Ok(mut ktls_stream) => {
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
        if !client_ktls && !server_ktls {
            eprintln!("Warning: kTLS not available on this system");
        }
    }

    /// Test OpenSSL kTLS client split into read/write halves for concurrent I/O
    #[compio::test]
    async fn test_ossl_ktls_client_split_concurrent_io() {
        use compio::io::{AsyncReadExt, util::Splittable};

        let server_config = make_server_config();

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

        let client_config = make_client_config();
        let connector = KtlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();

        match connector.connect("localhost", stream).await.unwrap() {
            Ok(ktls_stream) => {
                let (mut reader, mut writer) = ktls_stream.split();

                // Spawn a concurrent read task
                let read_task =
                    compio::runtime::spawn(
                        async move { reader.read_to_end(vec![]).await.unwrap() },
                    );

                let msg = b"Hello split OpenSSL kTLS!";
                writer.write_all(msg.to_vec()).await.unwrap();
                writer.flush().await.unwrap();
                writer.shutdown().await.unwrap();

                let (n, buf) = read_task.await.unwrap();
                assert_eq!(&buf[..n], msg);
            }
            Err(stream) => {
                drop(stream);
                eprintln!("Warning: kTLS not available on this system");
            }
        }
    }

    /// Test full OpenSSL kTLS with both client and server using split streams
    #[compio::test]
    async fn test_ossl_full_ktls_split_both_sides() {
        use compio::io::{AsyncReadExt, util::Splittable};

        let server_config = make_server_config();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = compio::runtime::spawn(async move {
            let acceptor = KtlsAcceptor::from(server_config);
            let (stream, _) = listener.accept().await.unwrap();

            match acceptor.accept(stream).await.unwrap() {
                Ok(ktls_stream) => {
                    let (mut reader, mut writer) = ktls_stream.split();

                    let read_task =
                        compio::runtime::spawn(
                            async move { reader.read_to_end(vec![]).await.unwrap() },
                        );

                    let (n, buf) = read_task.await.unwrap();
                    writer.write_all(buf[..n].to_vec()).await.unwrap();
                    writer.flush().await.unwrap();
                    writer.shutdown().await.ok();
                    true
                }
                Err(mut stream) => {
                    stream.shutdown().await.ok();
                    false
                }
            }
        });

        let client_config = make_client_config();
        let connector = KtlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();

        let client_ktls = match connector.connect("localhost", stream).await.unwrap() {
            Ok(ktls_stream) => {
                let (mut reader, mut writer) = ktls_stream.split();

                // Spawn concurrent read
                let read_task =
                    compio::runtime::spawn(
                        async move { reader.read_to_end(vec![]).await.unwrap() },
                    );

                let data = vec![0x42u8; 8192];
                writer.write_all(data.clone()).await.unwrap();
                writer.flush().await.unwrap();
                writer.shutdown().await.unwrap();

                // Collect read result
                let (n, buf) = read_task.await.unwrap();
                assert_eq!(&buf[..n], &data[..]);
                true
            }
            Err(stream) => {
                drop(stream);
                false
            }
        };

        let server_ktls = server_handle.await.unwrap();
        if !client_ktls && !server_ktls {
            eprintln!("Warning: kTLS not available on this system");
        }
    }

    /// Test split write-only: read stays on the original task, write spawned
    #[compio::test]
    async fn test_ossl_ktls_split_write_from_spawned_task() {
        use compio::io::{AsyncReadExt, util::Splittable};

        let server_config = make_server_config();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        compio::runtime::spawn(async move {
            let acceptor = KtlsAcceptor::from(server_config);
            let (stream, _) = listener.accept().await.unwrap();

            match acceptor.accept(stream).await.unwrap() {
                Ok(mut ktls_stream) => {
                    // Echo multiple messages
                    for _ in 0..3 {
                        let buf = vec![0u8; 1024];
                        let (n, buf) = ktls_stream.read(buf).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        ktls_stream.write_all(buf[..n].to_vec()).await.unwrap();
                        ktls_stream.flush().await.unwrap();
                    }
                    ktls_stream.shutdown().await.ok();
                }
                Err(mut stream) => {
                    stream.shutdown().await.ok();
                }
            }
        })
        .detach();

        let client_config = make_client_config();
        let connector = KtlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();

        match connector.connect("localhost", stream).await.unwrap() {
            Ok(ktls_stream) => {
                let (mut reader, mut writer) = ktls_stream.split();

                // Spawn write task
                let write_task = compio::runtime::spawn(async move {
                    for i in 0..3u8 {
                        let msg = vec![i; 64];
                        writer.write_all(msg).await.unwrap();
                        writer.flush().await.unwrap();
                    }
                    writer.shutdown().await.unwrap();
                });

                // Read responses on the main task
                for i in 0..3u8 {
                    let ((), buf) = reader.read_exact(vec![0u8; 64]).await.unwrap();
                    assert!(buf.iter().all(|&b| b == i));
                }

                write_task.await.unwrap();
            }
            Err(stream) => {
                drop(stream);
                eprintln!("Warning: kTLS not available on this system");
            }
        }
    }
}
