// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{fmt, io};

use compio_buf::{BufResult, IoBuf, IoBufMut, buf_try};
use compio_io::ancillary::{AsyncReadAncillary, AsyncWriteAncillary};
use ktls_core::{AlertDescription, ContentType};

use super::{AsyncWriteAncillaryExt, IntoMessage, Message, ReadMessage, WriteMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum AlertLevel {
    Warning = 1,
    Fatal   = 2,
}

impl From<u8> for AlertLevel {
    fn from(value: u8) -> Self {
        match value {
            v if v == Self::Warning as u8 => Self::Warning,
            v if v == Self::Fatal as u8 => Self::Fatal,
            _ => Self::Fatal,
        }
    }
}

pub(crate) struct AlertMessage {
    level: AlertLevel,
    description: AlertDescription,
}

impl AlertMessage {
    const SIZE: usize = 2;

    pub(crate) fn into_inner(self) -> (AlertLevel, AlertDescription) {
        (self.level, self.description)
    }
}

impl Message for AlertMessage {
    const CONTENT_TYPE: ContentType = ContentType::Alert;
}

impl ReadMessage for AlertMessage {
    async fn read<S, B>(stream: &mut S, buf: B) -> BufResult<(usize, Self), B>
    where
        S: AsyncReadAncillary,
        B: IoBufMut,
    {
        let ((), buf) = buf_try!(Self::fill_buffer(stream, buf, Self::SIZE).await);
        let level = AlertLevel::from(buf.as_init()[0]);
        let description = AlertDescription::from(buf.as_init()[1]);
        let rv = Self { level, description };
        BufResult(Ok((Self::SIZE, rv)), buf)
    }
}

impl WriteMessage for AlertMessage {
    async fn write_with_ancillary<S, B>(self, stream: &mut S, control: B) -> io::Result<()>
    where
        S: AsyncWriteAncillary,
        B: IoBuf,
    {
        let mut buf = [0; Self::SIZE];
        buf[0] = self.level as u8;
        buf[1] = self.description.into();
        stream.write_all_with_ancillary(buf, control).await.0
    }
}

impl fmt::Debug for AlertMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlertMessage")
            .field("level", &self.level)
            .field("description", &self.description)
            .finish()
    }
}

impl IntoMessage for AlertDescription {
    type Message = AlertMessage;

    fn into_message(self) -> Self::Message {
        use AlertDescription::*;
        let level = match self {
            CloseNotify | UserCanceled => AlertLevel::Warning,
            _ => AlertLevel::Fatal,
        };
        Self::Message {
            level,
            description: self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_level_from_u8() {
        assert_eq!(AlertLevel::from(1), AlertLevel::Warning);
        assert_eq!(AlertLevel::from(2), AlertLevel::Fatal);
        // Unknown values should default to Fatal
        assert_eq!(AlertLevel::from(99), AlertLevel::Fatal);
    }

    #[test]
    fn test_alert_message_into_inner() {
        use ktls_core::AlertDescription;

        let msg = AlertMessage {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        };
        let (level, desc) = msg.into_inner();
        assert_eq!(level, AlertLevel::Warning);
        assert_eq!(desc, AlertDescription::CloseNotify);
    }

    #[test]
    fn test_alert_description_into_message() {
        use ktls_core::AlertDescription;

        // Warning alerts
        let msg = AlertDescription::CloseNotify.into_message();
        assert_eq!(msg.level, AlertLevel::Warning);
        assert_eq!(msg.description, AlertDescription::CloseNotify);

        let msg = AlertDescription::UserCanceled.into_message();
        assert_eq!(msg.level, AlertLevel::Warning);

        // Fatal alerts
        let msg = AlertDescription::DecodeError.into_message();
        assert_eq!(msg.level, AlertLevel::Fatal);
        assert_eq!(msg.description, AlertDescription::DecodeError);
    }
}
