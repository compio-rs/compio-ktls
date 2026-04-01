// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{borrow::Cow, fmt, io, ops::RangeInclusive, slice};

use compio_buf::{BufResult, IoBuf, IoBufMut, buf_try};
use compio_io::ancillary::{AsyncReadAncillary, AsyncWriteAncillary};
use ktls_core::ContentType;

#[cfg(key_update)]
pub(crate) use self::key_update::KeyUpdateRequest;
use super::{AsyncWriteAncillaryExt, Message, ReadMessage, WriteMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum HandshakeType {
    NewSessionTicket = 4,
    #[cfg(key_update)]
    KeyUpdate        = 24,
}

impl TryFrom<u8> for HandshakeType {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        use HandshakeType::*;
        match value {
            v if v == NewSessionTicket as u8 => Ok(NewSessionTicket),
            #[cfg(key_update)]
            v if v == KeyUpdate as u8 => Ok(KeyUpdate),
            v => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported handshake type: {v:x}"),
            )),
        }
    }
}

impl HandshakeType {
    const fn allowed_length_range(&self) -> RangeInclusive<u32> {
        match self {
            Self::NewSessionTicket => 14..=4096,
            #[cfg(key_update)]
            Self::KeyUpdate => 1..=1,
        }
    }
}

struct HandshakeHeader {
    // Format: 1 byte for type, uint24 for length
    ty: HandshakeType,
    payload_length: u32,
}

impl HandshakeHeader {
    const SIZE: usize = 4;

    #[inline]
    fn message_length(&self) -> usize {
        Self::SIZE + self.payload_length as usize
    }

    fn encode(self) -> [u8; Self::SIZE] {
        let mut buf = self.payload_length.to_be_bytes();
        buf[0] = self.ty as u8;
        buf
    }

    fn decode(buf: &[u8]) -> io::Result<Self> {
        let mut buf: [u8; Self::SIZE] = buf.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Handshake header must be {} bytes", Self::SIZE),
            )
        })?;
        let ty: HandshakeType = buf[0].try_into()?;
        buf[0] = 0; // Clear the type byte to read the length
        let payload_length = u32::from_be_bytes(buf);
        if !ty.allowed_length_range().contains(&payload_length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid handshake message length",
            ));
        }
        Ok(Self { ty, payload_length })
    }

    async fn read<S, B>(stream: &mut S, buf: B) -> BufResult<Self, B>
    where
        S: AsyncReadAncillary,
        B: IoBufMut,
    {
        HandshakeMessage::fill_buffer(stream, buf, Self::SIZE)
            .await
            .and_then(|(), buf| (Self::decode(&buf.as_init()[..Self::SIZE]), buf))
    }

    // SAFETY: the caller must ensure that `buf` contains at least `Self::SIZE
    // + self.payload_length` bytes, and that the payload is not modified while
    // the returned slice is in use.
    unsafe fn detach_payload<'a, B: IoBuf + 'a>(&self, buf: &B) -> Cow<'a, [u8]> {
        Cow::Borrowed(unsafe {
            slice::from_raw_parts(buf.buf_ptr().add(Self::SIZE), self.payload_length as _)
        })
    }
}

pub(crate) enum HandshakeMessage<'a> {
    NewSessionTicket(Cow<'a, [u8]>),
    #[cfg(key_update)]
    KeyUpdate(KeyUpdateRequest),
}

impl Message for HandshakeMessage<'_> {
    const CONTENT_TYPE: ContentType = ContentType::Handshake;
}

impl<'a> ReadMessage for HandshakeMessage<'a> {
    async fn read<S, B>(stream: &mut S, buf: B) -> BufResult<(usize, Self), B>
    where
        S: AsyncReadAncillary,
        B: IoBufMut + 'a,
    {
        let (hdr, buf) = buf_try!(HandshakeHeader::read(stream, buf).await);
        let msg_len = hdr.message_length();
        let ((), buf) = buf_try!(Self::fill_buffer(stream, buf, msg_len).await);
        // SAFETY: `fill_buffer` ensures that `buf` contains at least `msg_len` bytes,
        // which is exactly the size of the header and payload. The payload is
        // not modified while the returned slice is in use, see also stream.rs
        // handle_control_message().
        let payload = unsafe { hdr.detach_payload(&buf) };
        let res = match hdr.ty {
            HandshakeType::NewSessionTicket => Ok(Self::NewSessionTicket(payload)),
            #[cfg(key_update)]
            HandshakeType::KeyUpdate => KeyUpdateRequest::decode(&payload).map(Self::KeyUpdate),
        };
        BufResult(res, buf).map_res(|msg| (msg_len, msg))
    }
}

impl<'a> WriteMessage for HandshakeMessage<'a> {
    async fn write_with_ancillary<S, B>(self, stream: &mut S, control: B) -> io::Result<()>
    where
        S: AsyncWriteAncillary,
        B: IoBuf,
    {
        let (mut buf, payload) = self.encode()?;
        match payload {
            Cow::Borrowed(payload) => {
                buf.extend_from_slice(payload);
                stream.write_all_with_ancillary(buf, control).await.0
            }
            Cow::Owned(payload) => {
                let buf = vec![buf, payload];
                stream
                    .write_vectored_all_with_ancillary(buf, control)
                    .await
                    .0
            }
        }
    }
}

impl<'a> HandshakeMessage<'a> {
    fn encode(self) -> io::Result<(Vec<u8>, Cow<'a, [u8]>)> {
        let (ty, payload) = match self {
            Self::NewSessionTicket(payload) => (HandshakeType::NewSessionTicket, payload),
            #[cfg(key_update)]
            Self::KeyUpdate(req) => (HandshakeType::KeyUpdate, req.encode().to_vec().into()),
        };
        let payload_length = payload.len().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Payload too large for handshake message",
            )
        })?;
        let hdr = HandshakeHeader { ty, payload_length };
        let buf = hdr.encode().to_vec();
        Ok((buf, payload))
    }

    pub(crate) fn into_tls13_inner_plaintext(self) -> io::Result<Vec<u8>> {
        // TLS 1.3 inner plaintext: TLSPlaintext (header + payload) | ContentType
        let (header, payload) = self.encode()?;
        let mut res = header;
        res.reserve(payload.len() + 1);
        res.extend_from_slice(&payload);
        res.push(Self::CONTENT_TYPE.into());
        Ok(res)
    }
}

impl fmt::Debug for HandshakeMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NewSessionTicket(ticket) => f
                .debug_tuple("HandshakeMessage::NewSessionTicket")
                .field(&format_args!("{} bytes", ticket.len()))
                .finish(),
            #[cfg(key_update)]
            Self::KeyUpdate(req) => f
                .debug_tuple("HandshakeMessage::KeyUpdate")
                .field(req)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_type_try_from() {
        assert_eq!(
            HandshakeType::try_from(4).unwrap(),
            HandshakeType::NewSessionTicket
        );
        #[cfg(key_update)]
        assert_eq!(
            HandshakeType::try_from(24).unwrap(),
            HandshakeType::KeyUpdate
        );
        assert!(HandshakeType::try_from(99).is_err());
    }

    #[test]
    fn test_handshake_type_allowed_length_range() {
        assert!(
            HandshakeType::NewSessionTicket
                .allowed_length_range()
                .contains(&100)
        );
        assert!(
            !HandshakeType::NewSessionTicket
                .allowed_length_range()
                .contains(&5000)
        );

        #[cfg(key_update)]
        assert!(HandshakeType::KeyUpdate.allowed_length_range().contains(&1));
        #[cfg(key_update)]
        assert!(!HandshakeType::KeyUpdate.allowed_length_range().contains(&2));
    }
}

#[cfg(key_update)]
mod key_update {
    use std::io;

    use super::{super::IntoMessage, *};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    enum KeyUpdateRequestInner {
        UpdateNotRequested = 0,
        UpdateRequested    = 1,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct KeyUpdateRequest(KeyUpdateRequestInner);

    impl KeyUpdateRequest {
        const SIZE: usize = 1;

        pub(crate) fn new(request_peer: bool) -> Self {
            use KeyUpdateRequestInner::*;
            if request_peer {
                Self(UpdateRequested)
            } else {
                Self(UpdateNotRequested)
            }
        }

        pub(crate) fn requested(&self) -> bool {
            matches!(self.0, KeyUpdateRequestInner::UpdateRequested)
        }

        pub(super) fn decode(buf: &[u8]) -> io::Result<Self> {
            use KeyUpdateRequestInner::*;
            match buf {
                [v] if *v == UpdateNotRequested as u8 => Ok(Self(UpdateNotRequested)),
                [v] if *v == UpdateRequested as u8 => Ok(Self(UpdateRequested)),
                [v] => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unknown key update request: {v:x}"),
                )),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid KeyUpdate message length: {}", buf.len()),
                )),
            }
        }

        pub(super) fn encode(self) -> [u8; Self::SIZE] {
            [self.0 as u8]
        }
    }

    impl IntoMessage for KeyUpdateRequest {
        type Message = HandshakeMessage<'static>;

        fn into_message(self) -> Self::Message {
            HandshakeMessage::KeyUpdate(self)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_handshake_header_encode_decode() {
            let header = HandshakeHeader {
                ty: HandshakeType::KeyUpdate,
                payload_length: 1,
            };
            let encoded = header.encode();
            assert_eq!(encoded[0], 24); // KeyUpdate type
            assert_eq!(u32::from_be_bytes(encoded) & 0x00FFFFFF, 1); // Length

            let decoded = HandshakeHeader::decode(&encoded).unwrap();
            assert_eq!(decoded.ty, HandshakeType::KeyUpdate);
            assert_eq!(decoded.payload_length, 1);
        }

        #[test]
        fn test_handshake_header_invalid_length() {
            let mut buf = [0u8; 4];
            buf[0] = 24; // KeyUpdate type
            // Payload length = 2, which is outside allowed range
            buf[1..4].copy_from_slice(&2u32.to_be_bytes()[1..4]);

            assert!(HandshakeHeader::decode(&buf).is_err());
        }

        #[test]
        fn test_key_update_request_new() {
            let req = KeyUpdateRequest::new(false);
            assert!(!req.requested());
            assert_eq!(req.0, KeyUpdateRequestInner::UpdateNotRequested);

            let req = KeyUpdateRequest::new(true);
            assert!(req.requested());
            assert_eq!(req.0, KeyUpdateRequestInner::UpdateRequested);
        }

        #[test]
        fn test_key_update_request_encode_decode() {
            let req = KeyUpdateRequest::new(false);
            let encoded = req.encode();
            assert_eq!(encoded, [0]);
            let decoded = KeyUpdateRequest::decode(&encoded).unwrap();
            assert_eq!(decoded, req);

            let req = KeyUpdateRequest::new(true);
            let encoded = req.encode();
            assert_eq!(encoded, [1]);
            let decoded = KeyUpdateRequest::decode(&encoded).unwrap();
            assert_eq!(decoded, req);
        }

        #[test]
        fn test_key_update_request_decode_invalid() {
            assert!(KeyUpdateRequest::decode(&[2]).is_err());
            assert!(KeyUpdateRequest::decode(&[0, 1]).is_err());
            assert!(KeyUpdateRequest::decode(&[]).is_err());
        }
    }
}
