// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{fmt, io, os::fd::AsFd};

use compio_buf::{BufResult, IoBuf, IoBufMut, IoVectoredBuf, IoVectoredBufMut, buf_try};
use compio_io::{
    AsyncRead, AsyncWrite,
    ancillary::{AsyncReadAncillary, AsyncWriteAncillary},
};
use ktls_core::{AlertDescription, TlsSession};

use super::{
    IntoMessage, KeyUpdateRequest, KtlsImplementation, OutgoingState, WriteMessage,
    split::{self, ReadHalf, WriteHalf},
};

pub(crate) struct KtlsDuplexStream<S, C> {
    inner: Option<S>,
    session: C,
    incoming_closed: bool,
    outgoing_state: OutgoingState,
    alpn_protocol: Option<Vec<u8>>,
}

impl<S, C> KtlsDuplexStream<S, C> {
    pub(crate) fn new(inner: S, session: C, alpn_protocol: Option<Vec<u8>>) -> Self {
        Self {
            inner: Some(inner),
            session,
            incoming_closed: false,
            outgoing_state: OutgoingState::Open,
            alpn_protocol,
        }
    }

    pub(crate) fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol.as_deref()
    }

    fn stream(&mut self) -> io::Result<&mut S> {
        self.inner
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream is closed"))
    }
}

impl<S, C> KtlsImplementation for KtlsDuplexStream<S, C>
where
    S: AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd,
    C: TlsSession,
{
    type Stream = S;
    type StreamRef<'a>
        = &'a mut S
    where
        Self: 'a;

    async fn incoming_stream(&mut self) -> io::Result<&mut S> {
        self.stream()
    }

    async fn outgoing_stream(&mut self) -> io::Result<&mut S> {
        self.stream()
    }

    fn close(&mut self) {
        self.inner.take();
    }

    fn set_incoming_closed(&mut self) {
        self.incoming_closed = true;
    }

    async fn handle_new_session_ticket(&mut self, payload: &[u8]) -> io::Result<()> {
        self.session.handle_new_session_ticket(payload)?;
        Ok(())
    }

    async fn update_incoming_secret(&mut self) -> io::Result<()> {
        self.session.update_rx_secret()?.set(self.stream()?)?;
        Ok(())
    }

    async fn update_outgoing_secret(&mut self, request_peer: bool) -> io::Result<()> {
        KeyUpdateRequest::new(request_peer)
            .into_message()
            .write(self.stream()?)
            .await?;
        self.session.update_tx_secret()?.set(self.stream()?)?;
        Ok(())
    }
}

impl<S, C> AsyncRead for KtlsDuplexStream<S, C>
where
    S: AsyncRead + AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd,
    C: TlsSession,
{
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        loop {
            if self.incoming_closed {
                break BufResult(Ok(0), buf);
            }

            let BufResult(res, b) = {
                let (stream, b) = buf_try!(self.stream(), buf);
                stream.read(b).await
            };
            match res {
                Ok(len) => break BufResult(Ok(len), b),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                    match self.handle_control_messages().await {
                        Ok(()) => buf = b,
                        Err(e) => break BufResult(self.inspect_error(e).await, b),
                    }
                }
                Err(e) => break BufResult(self.inspect_error(e).await, b),
            }
        }
    }

    async fn read_vectored<V: IoVectoredBufMut>(&mut self, mut buf: V) -> BufResult<usize, V> {
        loop {
            if self.incoming_closed {
                break BufResult(Ok(0), buf);
            }

            let BufResult(res, b) = {
                let (stream, b) = buf_try!(self.stream(), buf);
                stream.read_vectored(b).await
            };
            match res {
                Ok(len) => break BufResult(Ok(len), b),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                    match self.handle_control_messages().await {
                        Ok(()) => buf = b,
                        Err(e) => break BufResult(self.inspect_error(e).await, b),
                    }
                }
                Err(e) => break BufResult(self.inspect_error(e).await, b),
            }
        }
    }
}

impl<S, C> AsyncWrite for KtlsDuplexStream<S, C>
where
    S: AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd,
    C: TlsSession,
{
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        if self.outgoing_state.is_open() {
            let res = {
                let (stream, buf) = buf_try!(self.stream(), buf);
                stream.write(buf).await
            };
            match res {
                BufResult(Err(e), b) => BufResult(self.inspect_error(e).await, b),
                res => res,
            }
        } else {
            let e = io::Error::new(io::ErrorKind::BrokenPipe, "stream is closed");
            BufResult(Err(e), buf)
        }
    }

    async fn write_vectored<T: IoVectoredBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        if self.outgoing_state.is_open() {
            let res = {
                let (stream, buf) = buf_try!(self.stream(), buf);
                stream.write_vectored(buf).await
            };
            match res {
                BufResult(Err(e), b) => BufResult(self.inspect_error(e).await, b),
                res => res,
            }
        } else {
            let e = io::Error::new(io::ErrorKind::BrokenPipe, "stream is closed");
            BufResult(Err(e), buf)
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        if self.outgoing_state.is_open()
            && let Err(e) = self.stream()?.flush().await
        {
            self.inspect_error(e).await
        } else {
            Ok(())
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        use crate::linux::stream::OutgoingState::*;

        let res = match self.outgoing_state {
            // First, send the `close_notify` alert
            Open => match AlertDescription::CloseNotify
                .into_message()
                .write(self.stream()?)
                .await
                .map(|()| self.outgoing_state = CloseNotifySent)
            {
                // Then, attempt to flush the stream
                Ok(()) => self
                    .stream()?
                    .flush()
                    .await
                    .map(|()| self.outgoing_state = Flushed),
                Err(e) => Err(e),
            },

            // If `close_notify` was already sent, just attempt to flush the stream again
            CloseNotifySent => self
                .stream()?
                .flush()
                .await
                .map(|()| self.outgoing_state = Flushed),

            // If the stream was already flushed, continue to retry `shutdown()` below
            Flushed => Ok(()),

            // If the stream is already closed, just return Ok early.
            Closed => return Ok(()),
        };

        match res {
            // At last, attempt to shut down the stream
            Ok(()) => self
                .stream()?
                .shutdown()
                .await
                .map(|()| self.outgoing_state = Closed),

            Err(e) => match self.inspect_error(e).await {
                // inspect_error() can only return Err()
                Ok(()) => unreachable!(),

                // write() or flush() may fail with an Interrupted or WouldBlock error, in which
                // case `self.outgoing_state` is not `Closed`, and we should propagate the error to
                // the caller to retry from where it left off.
                Err(e) if self.outgoing_state != Closed => Err(e),

                // For other errors, we should still attempt to shut down the stream, but propagate
                // the error to the caller as well. This is because the stream may be left in a
                // broken state after an error, and shutting down the stream may help unblock the
                // peer and allow it to clean up its resources sooner.
                Err(e) => {
                    self.stream()?.shutdown().await.ok();
                    self.outgoing_state = Closed;
                    Err(e)
                }
            },
        }
    }
}

impl<S, C> KtlsDuplexStream<S, C>
where
    S: Clone,
{
    pub(crate) fn split(self) -> (ReadHalf<S, C>, WriteHalf<S, C>) {
        split::new(
            self.inner,
            self.session,
            self.incoming_closed,
            self.outgoing_state,
        )
    }
}

impl<S, C> fmt::Debug for KtlsDuplexStream<S, C>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KtlsDuplexStream")
            .field("socket", &self.inner)
            .finish()
    }
}
