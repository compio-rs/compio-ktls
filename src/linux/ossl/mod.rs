// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{array, io, io::Read};

use compio_buf::{IoBuf, Slice, buf_try};
use compio_io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use ktls_core::{AeadKey, ConnectionTrafficSecrets};

pub use self::prober::MemmemMode;
#[cfg(feature = "openssl")]
pub(crate) use self::rust::*;
use super::{adaptor::KtlsStream, setup_ktls, stream::KtlsDuplexStream};

mod prober;
#[cfg(feature = "openssl")]
mod rust;

const MAX_WRITE_BUF_SIZE: usize = 64 * 1024 * 1024;
const UPGRADED_OR_IO_ERROR: &str = "stream was upgraded or I/O in progress";

#[derive(Copy, Clone, Debug)]
pub enum CipherKind {
    Aes128Gcm,
    Aes256Gcm,
    Aes128Ccm,
    ChaCha20Poly1305,
}

impl CipherKind {
    const fn key_size(self) -> usize {
        match self {
            Self::Aes128Gcm => libc::TLS_CIPHER_AES_GCM_128_KEY_SIZE,
            Self::Aes256Gcm => libc::TLS_CIPHER_AES_GCM_256_KEY_SIZE,
            Self::Aes128Ccm => libc::TLS_CIPHER_AES_CCM_128_KEY_SIZE,
            Self::ChaCha20Poly1305 => libc::TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE,
        }
    }

    const fn iv_size(self) -> usize {
        match self {
            Self::Aes128Gcm => libc::TLS_CIPHER_AES_GCM_128_IV_SIZE,
            Self::Aes256Gcm => libc::TLS_CIPHER_AES_GCM_256_IV_SIZE,
            Self::Aes128Ccm => libc::TLS_CIPHER_AES_CCM_128_IV_SIZE,
            Self::ChaCha20Poly1305 => libc::TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE,
        }
    }

    const fn salt_size(self) -> usize {
        match self {
            Self::Aes128Gcm => libc::TLS_CIPHER_AES_GCM_128_SALT_SIZE,
            Self::Aes256Gcm => libc::TLS_CIPHER_AES_GCM_256_SALT_SIZE,
            Self::Aes128Ccm => libc::TLS_CIPHER_AES_CCM_128_SALT_SIZE,
            Self::ChaCha20Poly1305 => libc::TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE,
        }
    }

    const fn max_size() -> usize {
        const KINDS: [CipherKind; 4] = [
            CipherKind::Aes128Gcm,
            CipherKind::Aes256Gcm,
            CipherKind::Aes128Ccm,
            CipherKind::ChaCha20Poly1305,
        ];
        let mut max = 0;
        let mut i = 0;
        while i < KINDS.len() {
            let kind = KINDS[i];
            let size = kind.key_size() + kind.iv_size() + kind.salt_size();
            if size > max {
                max = size;
            }
            i += 1;
        }
        max
    }
}

/// RecordStream is an adapted copy of [compio_io::compat::SyncStream] that only
/// reads whole TLS record from the inner stream.
struct RecordStream<S>(Option<RecordStreamInner<S>>);

struct RecordStreamInner<S> {
    stream: S,
    read_buf: Slice<Vec<u8>>,
    write_buf: Vec<u8>,
}

impl<S> RecordStream<S> {
    fn new(inner: S) -> Self {
        Self(Some(RecordStreamInner {
            stream: inner,
            read_buf: Vec::new().slice(..),
            write_buf: Vec::new(),
        }))
    }

    fn borrow_mut(&mut self) -> io::Result<&mut RecordStreamInner<S>> {
        self.0
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::ResourceBusy, UPGRADED_OR_IO_ERROR))
    }

    fn take(&mut self) -> io::Result<(S, Slice<Vec<u8>>, Vec<u8>)> {
        let RecordStreamInner {
            stream,
            read_buf,
            write_buf,
        } = self
            .0
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::ResourceBusy, UPGRADED_OR_IO_ERROR))?;
        Ok((stream, read_buf, write_buf))
    }

    fn put(&mut self, stream: S, read_buf: Slice<Vec<u8>>, write_buf: Vec<u8>) {
        self.0 = Some(RecordStreamInner {
            stream,
            read_buf,
            write_buf,
        });
    }

    fn has_pending_write(&self) -> bool {
        self.0
            .as_ref()
            .map(|inner| !inner.write_buf.is_empty())
            .unwrap_or(false)
    }
}

impl<S: AsyncRead> RecordStream<S> {
    async fn fill_read_buf(&mut self) -> io::Result<()> {
        let (mut stream, read_buf, write_buf) = self.take()?;
        let read_buf = super::read_record(&mut stream, read_buf).await?;
        self.put(stream, read_buf, write_buf);
        Ok(())
    }
}

impl<S: AsyncWrite> RecordStream<S> {
    async fn flush_write_buf(&mut self) -> io::Result<()> {
        let (mut stream, read_buf, write_buf) = self.take()?;
        let ((), mut write_buf) = buf_try!(@try stream.write_all(write_buf).await);
        write_buf.clear();
        self.put(stream, read_buf, write_buf);
        Ok(())
    }
}

impl<S> Read for RecordStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (stream, mut read_buf, write_buf) = self.take()?;
        let rv = if read_buf.is_empty() {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            let n = read_buf.as_reader().read(buf)?;
            read_buf.set_begin(read_buf.begin() + n);
            if read_buf.is_empty() {
                read_buf.set_begin(0);
                read_buf.as_inner_mut().clear();
            }
            Ok(n)
        };
        self.put(stream, read_buf, write_buf);
        rv
    }
}

impl<S> io::Write for RecordStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let write_buf = &mut self.borrow_mut()?.write_buf;
        if write_buf.len() + buf.len() > MAX_WRITE_BUF_SIZE {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        write_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct TrafficSecrets {
    cipher_kind: CipherKind,
    buf: [u8; CipherKind::max_size()],
}

impl TrafficSecrets {
    fn new(cipher_kind: CipherKind) -> Self {
        // Use adt_const_params once stabilized
        Self {
            cipher_kind,
            buf: [0; CipherKind::max_size()],
        }
    }

    fn key(&self) -> &[u8] {
        &self.buf[0..self.cipher_kind.key_size()]
    }

    fn salt(&self) -> &[u8] {
        let key_size = self.cipher_kind.key_size();
        let salt_size = self.cipher_kind.salt_size();
        &self.buf[key_size..key_size + salt_size]
    }

    fn iv(&self) -> &[u8] {
        let offset = self.cipher_kind.key_size() + self.cipher_kind.salt_size();
        let iv_size = self.cipher_kind.iv_size();
        &self.buf[offset..offset + iv_size]
    }
}

impl Drop for TrafficSecrets {
    fn drop(&mut self) {
        self.buf.fill(0);
        std::hint::black_box(&self.buf);
    }
}

impl TryFrom<&TrafficSecrets> for ConnectionTrafficSecrets {
    type Error = array::TryFromSliceError;

    fn try_from(secrets: &TrafficSecrets) -> Result<Self, Self::Error> {
        match secrets.cipher_kind {
            CipherKind::Aes128Gcm => Ok(Self::Aes128Gcm {
                key: AeadKey::new(secrets.key().try_into()?),
                iv: secrets.iv().try_into()?,
                salt: secrets.salt().try_into()?,
            }),
            CipherKind::Aes256Gcm => Ok(Self::Aes256Gcm {
                key: AeadKey::new(secrets.key().try_into()?),
                iv: secrets.iv().try_into()?,
                salt: secrets.salt().try_into()?,
            }),
            CipherKind::Aes128Ccm => Ok(Self::Aes128Ccm {
                key: AeadKey::new(secrets.key().try_into()?),
                iv: secrets.iv().try_into()?,
                salt: secrets.salt().try_into()?,
            }),
            CipherKind::ChaCha20Poly1305 => Ok(Self::Chacha20Poly1305 {
                key: AeadKey::new(secrets.key().try_into()?),
                iv: secrets.iv().try_into()?,
                salt: secrets.salt().try_into()?,
            }),
        }
    }
}

#[derive(Debug)]
struct Secrets {
    incoming_secrets: TrafficSecrets,
    outgoing_secrets: TrafficSecrets,
    tx_seq: u64,
}

impl Secrets {
    fn new(cipher_kind: CipherKind) -> Self {
        Self {
            incoming_secrets: TrafficSecrets::new(cipher_kind),
            outgoing_secrets: TrafficSecrets::new(cipher_kind),
            tx_seq: 0,
        }
    }
}

impl TryFrom<Secrets> for ktls_core::ExtractedSecrets {
    type Error = ktls_core::Error;

    fn try_from(secrets: Secrets) -> Result<Self, Self::Error> {
        let tx_secrets = (&secrets.outgoing_secrets)
            .try_into()
            .map_err(|e| ktls_core::Error::Tls(Box::new(e)))?;
        let rx_secrets = (&secrets.incoming_secrets)
            .try_into()
            .map_err(|e| ktls_core::Error::Tls(Box::new(e)))?;
        Ok(Self {
            tx: (secrets.tx_seq, tx_secrets),
            rx: (0, rx_secrets),
        })
    }
}
