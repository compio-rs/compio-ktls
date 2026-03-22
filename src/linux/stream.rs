// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{fmt, future::Future, io, os::fd::AsFd, pin::Pin};

use compio_buf::{BufResult, IoBuf, IoBufMut, IoVectoredBuf, IoVectoredBufMut, buf_try};
use compio_io::{
    AsyncRead, AsyncWrite,
    ancillary::{AsyncReadAncillary, AsyncWriteAncillary},
};
use ktls_core::{AlertDescription, TlsSession};

use super::tls::{
    AlertMessage, HandshakeMessage, IntoMessage, KeyUpdateRequest, ReadMessage, TlsMessage,
    WriteMessage,
};

trait KtlsImplementation: Sized {
    type Stream: AsyncWrite + AsyncWriteAncillary + AsyncReadAncillary;

    fn stream(&mut self) -> io::Result<&mut Self::Stream>;

    fn close(&mut self);

    fn set_incoming_closed(&mut self);

    async fn handle_new_session_ticket(&mut self, payload: &[u8]) -> io::Result<()>;

    async fn update_incoming_secret(&mut self) -> io::Result<()>;

    async fn update_outgoing_secret(&mut self, request_peer: bool) -> io::Result<()>;

    async fn inspect_error<T>(&mut self, err: io::Error) -> io::Result<T> {
        use io::ErrorKind::*;
        let description = match err.kind() {
            Interrupted | WouldBlock => return Err(err),
            BrokenPipe | ConnectionReset => None,
            InvalidData => Some(AlertDescription::DecodeError),
            _ => Some(AlertDescription::InternalError),
        };
        if let Some(description) = description
            && let Ok(stream) = self.stream()
            && description.into_message().write(stream).await.is_ok()
        {
            stream.flush().await.ok();
        }
        self.close();
        Err(err)
    }

    async fn handle_control_messages(&mut self) -> io::Result<()> {
        let ((len, tls_msg), buf) =
            buf_try!(@try TlsMessage::read(self.stream()?, Vec::with_capacity(1024)).await);
        match tls_msg {
            TlsMessage::Handshake(msg) => {
                self.handle_same_messages(buf, len, msg, |slf, msg| {
                    Box::pin(slf.handle_handshake_messages(msg))
                })
                .await
            }
            TlsMessage::Alert(msg) => {
                self.handle_same_messages(buf, len, msg, |slf, msg| {
                    Box::pin(slf.handle_alert_message(msg))
                })
                .await
            }
            TlsMessage::ApplicationData => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected application data record on control channel",
            )),
        }
    }

    async fn handle_same_messages<T, F>(
        &mut self,
        mut buf: Vec<u8>,
        mut len: usize,
        mut msg: T,
        mut f: F,
    ) -> io::Result<()>
    where
        T: ReadMessage,
        F: for<'a> FnMut(&'a mut Self, T) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>>,
    {
        loop {
            f(self, msg).await?;
            if len < buf.len() {
                buf.drain(..len);
                ((len, msg), buf) = buf_try!(@try T::read(self.stream()?, buf).await);
            } else {
                break Ok(());
            }
        }
    }

    async fn handle_handshake_messages(&mut self, msg: HandshakeMessage<'_>) -> io::Result<()> {
        match msg {
            HandshakeMessage::NewSessionTicket(buf) => self.handle_new_session_ticket(&buf).await,
            HandshakeMessage::KeyUpdate(req) => {
                self.update_incoming_secret().await?;
                if req.requested() {
                    self.update_outgoing_secret(false).await?;
                }
                Ok(())
            }
        }
    }

    async fn handle_alert_message(&mut self, msg: AlertMessage) -> io::Result<()> {
        use AlertDescription::*;
        match msg.into_inner().1 {
            UserCanceled => Ok(()),
            CloseNotify => {
                self.set_incoming_closed();
                Ok(())
            }
            description => {
                self.close();
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    format!("Error alert: {description:?}"),
                ))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutgoingState {
    Open,
    CloseNotifySent,
    Flushed,
    Closed,
}

impl OutgoingState {
    #[inline]
    fn is_open(&self) -> bool {
        matches!(self, Self::Open)
    }
}

pub(crate) struct KtlsDuplexStream<S, C> {
    inner: Option<S>,
    session: C,
    incoming_closed: bool,
    outgoing_state: OutgoingState,
}

impl<S, C> KtlsDuplexStream<S, C> {
    pub(crate) fn new(inner: S, session: C) -> Self {
        Self {
            inner: Some(inner),
            session,
            incoming_closed: false,
            outgoing_state: OutgoingState::Open,
        }
    }
}

impl<S, C> KtlsImplementation for KtlsDuplexStream<S, C>
where
    S: AsyncWrite + AsyncReadAncillary + AsyncWriteAncillary + AsFd,
    C: TlsSession,
{
    type Stream = S;

    fn stream(&mut self) -> io::Result<&mut Self::Stream> {
        self.inner
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream is closed"))
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

            let stream;
            (stream, buf) = buf_try!(self.stream(), buf);
            let BufResult(res, b) = stream.read(buf).await;
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

            let stream;
            (stream, buf) = buf_try!(self.stream(), buf);
            let BufResult(res, b) = stream.read_vectored(buf).await;
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
            let (stream, buf) = buf_try!(self.stream(), buf);
            let res = {
                #[cfg(not(feature = "app-write-with-empty-ancillary"))]
                {
                    stream.write(buf).await
                }
                #[cfg(feature = "app-write-with-empty-ancillary")]
                {
                    stream
                        .write_with_ancillary(buf, [])
                        .await
                        .map_buffer(|(b, _)| b)
                }
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
            let (stream, buf) = buf_try!(self.stream(), buf);
            let res = {
                #[cfg(not(feature = "app-write-with-empty-ancillary"))]
                {
                    stream.write_vectored(buf).await
                }
                #[cfg(feature = "app-write-with-empty-ancillary")]
                {
                    stream
                        .write_vectored_with_ancillary(buf, [])
                        .await
                        .map_buffer(|(b, _)| b)
                }
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
        use OutgoingState::*;

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
