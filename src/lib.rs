// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

//! Kernel TLS (kTLS) support for the Compio async runtime.
//!
//! This library enables Linux kernel-space TLS encryption/decryption after
//! completing the initial TLS handshake in userspace. This can improve
//! performance by offloading cryptographic operations to the kernel.
//!
//! # Example
//!
//! ```
//! # use std::sync::Arc;
//! #
//! use compio::{
//!     io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
//!     net::TcpStream,
//!     tls::TlsConnector,
//! };
//! use compio_ktls::KtlsConnector;
//!
//! # compio::runtime::Runtime::new().unwrap().block_on(async {
//! // Setup rustls config with secret extraction enabled
//! # let mut roots = rustls::RootCertStore::empty();
//! # for cert in rustls_native_certs::load_native_certs().unwrap() {
//! #     roots.add(cert).unwrap();
//! # }
//! let mut config = rustls::ClientConfig::builder()
//!     .with_root_certificates(roots)
//!     .with_no_client_auth();
//! config.enable_secret_extraction = true;
//! let config = Arc::new(config);
//! let connector = KtlsConnector::from(config.clone());
//!
//! // Connect to a TLS server
//! let hostname = "github.com";
//! let mut tcp_stream = TcpStream::connect(format!("{hostname}:443")).await.unwrap();
//!
//! // Attempt to upgrade to kTLS
//! let request = format!("GET / HTTP/1.0\r\nHost: {hostname}\r\n\r\n");
//! match connector.connect(hostname, tcp_stream).await.unwrap() {
//!     Ok(mut stream) => {
//!         // kTLS enabled successfully
//!         stream.write_all(request.as_bytes().to_vec()).await.unwrap();
//!         stream.flush().await.unwrap();
//!         let (_len, _html) = stream.read_to_end(vec![]).await.unwrap();
//!         stream.shutdown().await.unwrap();
//!     }
//!     Err(stream) => {
//!         // kTLS unavailable, fallback to original stream
//!         let connector = TlsConnector::from(config);
//!         let mut stream = connector.connect(hostname, stream).await.unwrap();
//!         stream.write_all(request.as_bytes().to_vec()).await.unwrap();
//!         stream.flush().await.unwrap();
//!         let (_len, _html) = stream.read_to_end(vec![]).await.unwrap();
//!         stream.shutdown().await.unwrap();
//!     }
//! }
//! # })
//! ```
//!
//! # Requirements
//!
//! - Linux kernel with kTLS support (version 6.6 LTS or newer recommended)
//! - Rustls with `enable_secret_extraction` enabled
//! - The `tls` kernel module must be loaded (`modprobe tls`)
//!
//! # Platform Support
//!
//! Currently only Linux is supported. On other platforms, this crate provides
//! no exports.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use self::linux::*;
