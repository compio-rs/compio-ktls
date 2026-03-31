// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{io, os::fd::AsFd, sync::atomic::Ordering};

use compio_buf::{BufResult, IoBuf, IoBufMut, IoVectoredBuf, IoVectoredBufMut, buf_try};
use compio_io::{
    AsyncRead, AsyncWrite,
    ancillary::{AsyncReadAncillary, AsyncWriteAncillary},
};
use ktls_core::{AlertDescription, TlsSession};
#[cfg(feature = "sync")]
use synchrony::sync;
#[cfg(not(feature = "sync"))]
use synchrony::unsync as sync;

use super::{IntoMessage, KtlsImplementation, OutgoingState, WriteMessage};

struct KtlsSplitStream<S, C> {
    incoming_stream: Option<sync::bilock::BiLock<S>>,
    outgoing_stream: Option<sync::bilock::BiLock<S>>,
    session: sync::bilock::BiLock<C>,
    stream_closed: sync::shared::Shared<sync::atomic::AtomicBool>,
    incoming_closed: sync::shared::Shared<sync::atomic::AtomicBool>,
}

pub(super) fn new<S: Clone, C>(
    stream: Option<S>,
    session: C,
    incoming_closed: bool,
    outgoing_state: OutgoingState,
) -> (ReadHalf<S, C>, WriteHalf<S, C>) {
    let stream_closed = stream.is_none();
    let (session_r, session_w) = sync::bilock::BiLock::new(session);
    let (incoming_r, incoming_w) = stream
        .clone()
        .map(|s| {
            let (r, w) = sync::bilock::BiLock::new(s);
            (Some(r), Some(w))
        })
        .unwrap_or((None, None));
    let (outgoing_r, outgoing_w) = stream
        .map(|s| {
            let (r, w) = sync::bilock::BiLock::new(s);
            (Some(r), Some(w))
        })
        .unwrap_or((None, None));
    let stream_closed = sync::shared::Shared::new(sync::atomic::AtomicBool::new(stream_closed));
    let incoming_closed = sync::shared::Shared::new(sync::atomic::AtomicBool::new(incoming_closed));
    let reader = KtlsSplitStream {
        incoming_stream: incoming_r,
        outgoing_stream: outgoing_r,
        session: session_r,
        stream_closed: stream_closed.clone(),
        incoming_closed: incoming_closed.clone(),
    };
    let writer = KtlsSplitStream {
        incoming_stream: incoming_w,
        outgoing_stream: outgoing_w,
        session: session_w,
        stream_closed,
        incoming_closed,
    };
    (
        ReadHalf(reader),
        WriteHalf {
            inner: writer,
            outgoing_state,
        },
    )
}

impl<S, C> KtlsImplementation for KtlsSplitStream<S, C>
where
    S: AsyncWrite + AsyncWriteAncillary + AsyncReadAncillary + AsFd,
    C: TlsSession,
{
    type Stream = S;
    type StreamRef<'a>
        = sync::bilock::BiLockGuard<'a, Self::Stream>
    where
        Self: 'a;

    async fn incoming_stream(&mut self) -> io::Result<Self::StreamRef<'_>> {
        let res = match &mut self.incoming_stream {
            None => None,
            s @ Some(_) if self.stream_closed.load(Ordering::Acquire) => {
                s.take();
                self.outgoing_stream.take();
                None
            }
            Some(lock) => Some(lock.lock().await),
        };
        res.ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream is closed"))
    }

    async fn outgoing_stream(&mut self) -> io::Result<Self::StreamRef<'_>> {
        let res = match &mut self.outgoing_stream {
            None => None,
            s @ Some(_) if self.stream_closed.load(Ordering::Acquire) => {
                s.take();
                self.incoming_stream.take();
                None
            }
            Some(lock) => Some(lock.lock().await),
        };
        res.ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream is closed"))
    }

    fn close(&mut self) {
        self.stream_closed.store(true, Ordering::Release);
        self.incoming_stream.take();
        self.outgoing_stream.take();
    }

    fn set_incoming_closed(&mut self) {
        self.incoming_closed.store(true, Ordering::Release);
    }

    async fn handle_new_session_ticket(&mut self, payload: &[u8]) -> io::Result<()> {
        self.session
            .lock()
            .await
            .handle_new_session_ticket(payload)?;
        Ok(())
    }

    #[cfg(key_update)]
    async fn update_incoming_secret(&mut self) -> io::Result<()> {
        let stream = match &mut self.incoming_stream {
            None => None,
            s @ Some(_) if self.stream_closed.load(Ordering::Acquire) => {
                s.take();
                self.outgoing_stream.take();
                None
            }
            Some(lock) => Some(lock.lock().await),
        };
        let stream = stream
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream is closed"))?;
        self.session
            .lock()
            .await
            .update_rx_secret()?
            .set(&*stream)
            .map_err(super::map_key_update_error)?;
        Ok(())
    }

    #[cfg(key_update)]
    async fn update_outgoing_secret(&mut self, request_peer: bool) -> io::Result<()> {
        let stream = match &mut self.outgoing_stream {
            None => None,
            s @ Some(_) if self.stream_closed.load(Ordering::Acquire) => {
                s.take();
                self.incoming_stream.take();
                None
            }
            Some(lock) => Some(lock.lock().await),
        };
        let mut stream = stream
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream is closed"))?;
        super::super::tls::KeyUpdateRequest::new(request_peer)
            .into_message()
            .write(&mut *stream)
            .await?;
        self.session
            .lock()
            .await
            .update_tx_secret()?
            .set(&*stream)
            .map_err(super::map_key_update_error)?;
        Ok(())
    }
}

pub(crate) struct ReadHalf<S, C>(KtlsSplitStream<S, C>);

pub(crate) struct WriteHalf<S, C> {
    inner: KtlsSplitStream<S, C>,
    outgoing_state: OutgoingState,
}

impl<S, C> AsyncRead for ReadHalf<S, C>
where
    S: AsyncRead + AsyncWrite + AsyncWriteAncillary + AsyncReadAncillary + AsFd,
    C: TlsSession,
{
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        loop {
            let BufResult(res, b) = {
                let (mut stream, b) = buf_try!(self.0.incoming_stream().await, buf);
                stream.read(b).await
            };
            match res {
                Ok(len) => break BufResult(Ok(len), b),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                    match self.0.handle_control_messages().await {
                        Ok(()) => buf = b,
                        Err(e) => break BufResult(self.0.inspect_error(e).await, b),
                    }
                }
                Err(e) => break BufResult(self.0.inspect_error(e).await, b),
            }
        }
    }

    async fn read_vectored<V: IoVectoredBufMut>(&mut self, mut buf: V) -> BufResult<usize, V> {
        loop {
            let BufResult(res, b) = {
                let (mut stream, b) = buf_try!(self.0.incoming_stream().await, buf);
                stream.read_vectored(b).await
            };
            match res {
                Ok(len) => break BufResult(Ok(len), b),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                    match self.0.handle_control_messages().await {
                        Ok(()) => buf = b,
                        Err(e) => break BufResult(self.0.inspect_error(e).await, b),
                    }
                }
                Err(e) => break BufResult(self.0.inspect_error(e).await, b),
            }
        }
    }
}

impl<S, C> AsyncWrite for WriteHalf<S, C>
where
    S: AsyncWrite + AsyncWriteAncillary + AsyncReadAncillary + AsFd,
    C: TlsSession,
{
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        if self.outgoing_state.is_open() {
            let res = {
                let (mut stream, buf) = buf_try!(self.inner.outgoing_stream().await, buf);
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
                BufResult(Err(e), b) => BufResult(self.inner.inspect_error(e).await, b),
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
                let (mut stream, buf) = buf_try!(self.inner.outgoing_stream().await, buf);
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
                BufResult(Err(e), b) => BufResult(self.inner.inspect_error(e).await, b),
                res => res,
            }
        } else {
            let e = io::Error::new(io::ErrorKind::BrokenPipe, "stream is closed");
            BufResult(Err(e), buf)
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        if self.outgoing_state.is_open()
            && let Err(e) = { self.inner.outgoing_stream().await?.flush().await }
        {
            self.inner.inspect_error(e).await
        } else {
            Ok(())
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        use crate::linux::stream::OutgoingState::*;

        let res = match self.outgoing_state {
            // First, send the `close_notify` alert
            Open => match {
                AlertDescription::CloseNotify
                    .into_message()
                    .write(&mut *self.inner.outgoing_stream().await?)
                    .await
                    .map(|()| self.outgoing_state = CloseNotifySent)
            } {
                // Then, attempt to flush the stream
                Ok(()) => self
                    .inner
                    .outgoing_stream()
                    .await?
                    .flush()
                    .await
                    .map(|()| self.outgoing_state = Flushed),
                Err(e) => Err(e),
            },

            // If `close_notify` was already sent, just attempt to flush the stream again
            CloseNotifySent => self
                .inner
                .outgoing_stream()
                .await?
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
                .inner
                .outgoing_stream()
                .await?
                .shutdown()
                .await
                .map(|()| self.outgoing_state = Closed),

            Err(e) => match self.inner.inspect_error(e).await {
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
                    self.inner.outgoing_stream().await?.shutdown().await.ok();
                    self.outgoing_state = Closed;
                    Err(e)
                }
            },
        }
    }
}

impl<S, C> WriteHalf<S, C>
where
    S: AsyncWrite + AsyncWriteAncillary + AsyncReadAncillary + AsFd,
    C: TlsSession,
{
    #[cfg(key_update)]
    pub(crate) async fn key_update(&mut self, request_peer: bool) -> io::Result<()> {
        self.inner.update_outgoing_secret(request_peer).await
    }
}
