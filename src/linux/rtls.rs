// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{io, os::fd::AsFd, slice, sync::Arc};

use compio_buf::{IoBuf, buf_try};
use compio_io::{AsyncRead, AsyncWrite, AsyncWriteExt, ancillary::AsyncWriteAncillary};
use rustls::{
    ClientConfig, ProtocolVersion, ServerConfig,
    client::UnbufferedClientConnection,
    pki_types::ServerName,
    server::UnbufferedServerConnection,
    unbuffered::{ConnectionState::*, EncodeError, UnbufferedStatus},
};

use super::{adaptor::KtlsStream, read_record, setup_ktls, stream::KtlsDuplexStream};

pub(crate) async fn connect_ktls<S>(
    config: Arc<ClientConfig>,
    domain: ServerName<'static>,
    mut stream: S,
) -> io::Result<KtlsStream<S>>
where
    S: AsyncRead + AsyncWrite + AsyncWriteAncillary + AsFd,
{
    let mut conn = UnbufferedClientConnection::new(config, domain).map_err(io::Error::other)?;
    handshake(&mut stream, &mut conn).await?;
    let alpn_protocol = conn.alpn_protocol().map(|p| p.to_vec());
    let (secrets, session) = conn
        .dangerous_into_kernel_connection()
        .map_err(io::Error::other)?;
    setup_ktls(&stream, secrets, &session)?;
    Ok(KtlsDuplexStream::new(stream, session, alpn_protocol).into())
}

pub(crate) async fn accept_ktls<S>(
    config: Arc<ServerConfig>,
    mut stream: S,
) -> io::Result<KtlsStream<S>>
where
    S: AsyncRead + AsyncWrite + AsyncWriteAncillary + AsFd,
{
    let mut conn = UnbufferedServerConnection::new(config).map_err(io::Error::other)?;
    handshake(&mut stream, &mut conn).await?;
    let alpn_protocol = conn.alpn_protocol().map(|p| p.to_vec());
    let (secrets, session) = conn
        .dangerous_into_kernel_connection()
        .map_err(io::Error::other)?;
    setup_ktls(&stream, secrets, &session)?;
    Ok(KtlsDuplexStream::new(stream, session, alpn_protocol).into())
}

trait UnbufferedConnection {
    type Data;

    fn feed<'c, 'i>(&'c mut self, buf: &'i mut [u8]) -> UnbufferedStatus<'c, 'i, Self::Data>;

    fn version(&self) -> Option<ProtocolVersion>;
}

impl UnbufferedConnection for UnbufferedClientConnection {
    type Data = rustls::client::ClientConnectionData;

    fn feed<'c, 'i>(&'c mut self, buf: &'i mut [u8]) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(buf)
    }

    fn version(&self) -> Option<ProtocolVersion> {
        self.protocol_version()
    }
}

impl UnbufferedConnection for UnbufferedServerConnection {
    type Data = rustls::server::ServerConnectionData;

    fn feed<'c, 'i>(&'c mut self, buf: &'i mut [u8]) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(buf)
    }

    fn version(&self) -> Option<ProtocolVersion> {
        self.protocol_version()
    }
}

async fn handshake<S, C>(stream: &mut S, conn: &mut C) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + AsyncWriteAncillary,
    C: UnbufferedConnection,
{
    let mut incoming_tls = Vec::new().slice(..);
    let mut outgoing_tls = Vec::new();
    let version = loop {
        let UnbufferedStatus { discard, state } = conn.feed(&mut incoming_tls);
        let mut read_more = false;
        match state.map_err(io::Error::other)? {
            BlockedHandshake => read_more = true,
            EncodeTlsData(mut data) => {
                for first in [true, false] {
                    let buf = outgoing_tls.spare_capacity_mut();
                    // SAFETY: data.encode() only writes to the buf
                    let buf =
                        unsafe { slice::from_raw_parts_mut(buf.as_mut_ptr() as _, buf.len()) };
                    match data.encode(buf) {
                        Ok(len) => {
                            unsafe { outgoing_tls.set_len(outgoing_tls.len() + len) };
                            break;
                        }
                        Err(EncodeError::InsufficientSize(e)) => {
                            if first {
                                outgoing_tls.reserve(e.required_size)
                            } else {
                                unreachable!("insufficient size after reserve()");
                            }
                        }
                        Err(EncodeError::AlreadyEncoded) => unreachable!("encoded twice"),
                    }
                }
            }
            TransmitTlsData(data) => {
                outgoing_tls = buf_try!(@try stream.write_all(outgoing_tls).await).1;
                outgoing_tls.clear();
                data.done();
            }
            WriteTraffic(_) => {
                break conn
                    .version()
                    .ok_or_else(|| io::Error::other("TLS version not negotiated"))?;
            }
            ReadEarlyData(_) => unimplemented!("Early data impl is TBD"),
            state @ (ReadTraffic(_) | PeerClosed | Closed) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unexpected {state:?} during TLS handshake"),
                ));
            }
            state => unimplemented!("Unexpected state during TLS handshake: {state:?}"),
        }
        if discard > 0 {
            incoming_tls = incoming_tls.slice(discard..).flatten();
            if incoming_tls.is_empty() {
                incoming_tls.set_begin(0);
                incoming_tls.as_inner_mut().clear();
            }
        }
        if read_more {
            incoming_tls = read_record(stream, incoming_tls).await?;
        }
    };
    match version {
        ProtocolVersion::TLSv1_3 => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported TLS version: {version:?}"),
        )),
    }
}
