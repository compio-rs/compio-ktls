// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{io, mem::MaybeUninit};

use compio_buf::{BufResult, IntoInner, IoBuf, IoBufMut, buf_try};
use compio_io::ancillary::{
    AncillaryBuf, AncillaryData, AncillaryIter, AsyncReadAncillary, AsyncWriteAncillary,
    CodecError, ancillary_space,
};

pub(crate) use self::{alert::*, handshake::*};
use super::write_ext::AsyncWriteAncillaryExt;

mod alert;
mod handshake;

pub(crate) trait Message {
    const CONTENT_TYPE: ktls_core::ContentType;
}

pub(crate) trait ReadMessage: Message + Sized {
    async fn read<S, B>(stream: &mut S, buf: B) -> BufResult<(usize, Self), B>
    where
        S: AsyncReadAncillary,
        B: IoBufMut;

    async fn fill_buffer<S, B>(stream: &mut S, buf: B, nbytes: usize) -> BufResult<(), B>
    where
        S: AsyncReadAncillary,
        B: IoBufMut,
    {
        ContentType::of::<Self>()
            .fill_buffer(stream, buf, nbytes)
            .await
    }
}

pub(crate) trait WriteMessage: Message + Sized {
    async fn write_with_ancillary<S, B>(self, stream: &mut S, control: B) -> io::Result<()>
    where
        S: AsyncWriteAncillary,
        B: IoBuf;

    async fn write<S: AsyncWriteAncillary>(self, stream: &mut S) -> io::Result<()> {
        let control = ContentType::of::<Self>().encode();
        self.write_with_ancillary(stream, control).await
    }
}

pub(crate) trait IntoMessage {
    type Message;

    fn into_message(self) -> Self::Message;
}

type TlsAncillaryBuf = AncillaryBuf<{ ancillary_space::<ContentType>() }>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ContentType(ktls_core::ContentType);

impl AncillaryData for ContentType {
    const SIZE: usize = 1;

    fn encode(&self, buffer: &mut [MaybeUninit<u8>]) -> Result<(), CodecError> {
        if buffer.is_empty() {
            return Err(CodecError::BufferTooSmall);
        }
        buffer[0].write(self.0.into());
        Ok(())
    }

    fn decode(buffer: &[u8]) -> Result<Self, CodecError> {
        if buffer.is_empty() {
            return Err(CodecError::BufferTooSmall);
        }
        Ok(Self(ktls_core::ContentType::from(buffer[0])))
    }
}

impl ContentType {
    const fn of<M: Message>() -> Self {
        Self(M::CONTENT_TYPE)
    }

    async fn read<S, B>(stream: &mut S, buf: B) -> BufResult<(usize, Option<Self>), B>
    where
        S: AsyncReadAncillary,
        B: IoBufMut,
    {
        stream
            .read_with_ancillary(buf, TlsAncillaryBuf::new())
            .await
            .and_then(|(len, clen), (buf, control)| {
                if len == 0 || clen == 0 {
                    return (Ok((len, None)), (buf, control));
                }
                // SAFETY: control is aligned by AncillaryBuf and filled by kernel
                let cmsg_vec = unsafe { AncillaryIter::new(&control[..clen]) }.collect::<Vec<_>>();
                let res = match cmsg_vec.as_slice() {
                    [] => Ok((len, None)),
                    [cmsg]
                        if cmsg.level() == libc::SOL_TLS
                            && cmsg.ty() == libc::TLS_GET_RECORD_TYPE =>
                    {
                        match cmsg.data::<Self>() {
                            Ok(rv) => Ok((len, Some(rv))),
                            Err(_) => Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Invalid control message data",
                            )),
                        }
                    }
                    [_] => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unexpected control message",
                    )),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected at most one control message",
                    )),
                };
                (res, (buf, control))
            })
            .map_buffer(|(buf, _)| buf)
    }

    async fn fill_buffer<S: AsyncReadAncillary, B: IoBufMut>(
        &self,
        stream: &mut S,
        mut buf: B,
        nbytes: usize,
    ) -> BufResult<(), B> {
        let mut offset = buf.buf_len();
        if offset >= nbytes {
            return BufResult(Ok(()), buf);
        }
        let reserve = nbytes.saturating_sub(buf.buf_capacity());
        if reserve > 0
            && let Err(e) = buf.reserve(reserve)
        {
            return BufResult(Err(e.into()), buf);
        }
        while offset < nbytes {
            let BufResult(res, b) = ContentType::read(stream, buf.slice(offset..nbytes)).await;
            let res = res.and_then(|(len, msg)| match msg {
                Some(t) if t != *self => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Content type mismatches: {msg:?}"),
                )),
                _ if len == 0 => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF while filling buffer",
                )),
                _ => {
                    offset += len;
                    Ok(())
                }
            });
            ((), buf) = buf_try!(BufResult(res, b.into_inner()));
        }
        BufResult(Ok(()), buf)
    }

    fn encode(&self) -> TlsAncillaryBuf {
        let mut control = TlsAncillaryBuf::new();
        control
            .builder()
            .push(libc::SOL_TLS, libc::TLS_SET_RECORD_TYPE, self)
            .expect("sufficient space and alignment");
        control
    }
}

pub(crate) enum TlsMessage<'a> {
    Alert(AlertMessage),
    Handshake(HandshakeMessage<'a>),
    ApplicationData,
}

impl<'a> TlsMessage<'a> {
    pub(crate) async fn read<S, B>(stream: &mut S, buf: B) -> BufResult<(usize, Self), B>
    where
        S: AsyncReadAncillary,
        B: IoBufMut + 'a,
    {
        let ((len, ty), buf) = buf_try!(ContentType::read(stream, buf).await);
        debug_assert!(buf.buf_len() == len);
        use ktls_core::ContentType::*;
        match ty {
            Some(ContentType(Handshake)) => HandshakeMessage::read(stream, buf)
                .await
                .map_res(|(len, msg)| (len, Self::Handshake(msg))),
            Some(ContentType(Alert)) => AlertMessage::read(stream, buf)
                .await
                .map_res(|(len, msg)| (len, Self::Alert(msg))),
            None | Some(ContentType(ApplicationData)) => {
                BufResult(Ok((len, Self::ApplicationData)), buf)
            }
            _ => {
                let e = io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unexpected content type: {ty:?}"),
                );
                BufResult(Err(e), buf)
            }
        }
    }
}
