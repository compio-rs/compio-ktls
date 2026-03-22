// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{future::Future, io, ops::DerefMut, pin::Pin};

use compio_buf::buf_try;
use compio_io::{
    AsyncWrite,
    ancillary::{AsyncReadAncillary, AsyncWriteAncillary},
};
use ktls_core::AlertDescription;

pub(crate) use self::{duplex::*, split::*};
use super::tls::{
    AlertMessage, HandshakeMessage, IntoMessage, KeyUpdateRequest, ReadMessage, TlsMessage,
    WriteMessage,
};

mod duplex;
mod split;

trait KtlsImplementation: Sized {
    type Stream: AsyncWrite + AsyncWriteAncillary + AsyncReadAncillary;
    type StreamRef<'a>: DerefMut<Target = Self::Stream>
    where
        Self: 'a;

    async fn incoming_stream(&mut self) -> io::Result<Self::StreamRef<'_>>;

    async fn outgoing_stream(&mut self) -> io::Result<Self::StreamRef<'_>>;

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
            && let Ok(mut stream) = self.outgoing_stream().await
            && description.into_message().write(&mut *stream).await.is_ok()
        {
            stream.flush().await.ok();
        }
        self.close();
        Err(err)
    }

    async fn handle_control_messages(&mut self) -> io::Result<()> {
        let ((len, tls_msg), buf) = buf_try!(@try TlsMessage::read(&mut *self.incoming_stream().await?, Vec::with_capacity(1024)).await);
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
                ((len, msg), buf) =
                    buf_try!(@try T::read(&mut *self.incoming_stream().await?, buf).await);
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
