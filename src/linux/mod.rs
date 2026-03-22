// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{io, os::fd::AsFd};

use compio_buf::{IntoInner, IoBufMut, buf_try};
use compio_io::{AsyncRead, AsyncReadExt};
use ktls_core::{ExtractedSecrets, TlsCryptoInfoRx, TlsCryptoInfoTx, TlsSession, setup_tls_params};

mod adaptor;
#[cfg(feature = "rustls")]
mod rtls;
mod stream;
mod tls;
mod write_ext;

pub use self::adaptor::*;

async fn read_record<S: AsyncRead, B: IoBufMut>(stream: &mut S, mut buf: B) -> io::Result<B> {
    buf.reserve(5)?;
    let offset = buf.buf_len();
    let ((), buf) = buf_try!(@try stream.read_exact(buf.slice(offset..offset + 5)).await);
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;

    let mut buf = buf.into_inner();
    buf.reserve(len)?;
    let offset = buf.buf_len();
    Ok(buf_try!(@try stream.read_exact(buf.slice(offset..offset + len)).await.into_inner()).1)
}

fn setup_ktls<S, C, K, E>(socket: &S, secrets: K, session: &C) -> Result<(), ktls_core::Error>
where
    S: AsFd,
    C: TlsSession,
    ExtractedSecrets: TryFrom<K, Error = E>,
    ktls_core::Error: From<E>,
{
    let ExtractedSecrets {
        tx: (seq_tx, secrets_tx),
        rx: (seq_rx, secrets_rx),
    } = ExtractedSecrets::try_from(secrets)?;

    let protocol_version = session.protocol_version();
    let tls_crypto_info_tx = TlsCryptoInfoTx::new(protocol_version, secrets_tx, seq_tx)?;
    let tls_crypto_info_rx = TlsCryptoInfoRx::new(protocol_version, secrets_rx, seq_rx)?;

    setup_tls_params(&socket, &tls_crypto_info_tx, &tls_crypto_info_rx)?;

    Ok(())
}
