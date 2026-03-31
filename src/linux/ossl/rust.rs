// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use std::{
    borrow::Cow,
    cell::RefCell,
    io::{self, Read},
    os::fd::AsFd,
    rc::Rc,
    slice,
    sync::{Arc, Mutex, OnceLock},
};

use compio_io::{AsyncRead, AsyncWrite, ancillary::AsyncWriteAncillary};
use ktls_core::{ContentType, Peer, ProtocolVersion, TlsCryptoInfoRx, TlsCryptoInfoTx};
use openssl::{
    md::{Md, MdRef},
    nid::Nid,
    pkey::{Id, PKey},
    ssl::{
        HandshakeError, Ssl, SslAcceptor, SslCipherRef, SslConnector, SslContextBuilder, SslMethod,
        SslRef, SslStream, SslVerifyMode, SslVersion,
    },
    symm,
};

use super::{
    super::tls::HandshakeMessage,
    CipherKind, KtlsDuplexStream, KtlsStream, RecordStream, Secrets, TrafficSecrets,
    prober::{MemmemMode, Tls13SecretOffsetProber},
};

pub(crate) struct KtlsSession<S> {
    ssl_stream: SslStream<RecordStream<S>>,
    protocol_version: ProtocolVersion,
    cipher_kind: CipherKind,
    md: &'static MdRef,
    outgoing_secret_offset: usize,
    incoming_secret_offset: usize,
    rx_seq: u64,
}

impl<S> KtlsSession<S> {
    fn from_ssl(ssl_stream: SslStream<RecordStream<S>>, mode: MemmemMode) -> io::Result<Self> {
        let ssl = ssl_stream.ssl();
        let protocol_version = match ssl.version2() {
            Some(SslVersion::TLS1_3) => Ok(ProtocolVersion::TLSv1_3),
            Some(ver) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported TLS version: {ver:?}"),
            )),
            None => Err(io::Error::other("unfinished handshake")),
        }?;

        // Prepare the cipher kind and the message digest algorithm
        let ssl_cipher = ssl
            .current_cipher()
            .ok_or_else(|| io::Error::other("unfinished handshake"))?;
        let md = ssl_cipher
            .handshake_digest()
            .map(|md| md.type_())
            .and_then(Md::from_nid)
            .ok_or_else(|| io::Error::other("unsupported digest type"))?;
        let cipher_kind = ssl_cipher.try_into()?;

        // Cache the secret offsets under tx/rx tags
        let (client_secret_offset, server_secret_offset) = probe_tls13_secret_offsets(mode)?;
        let (outgoing_secret_offset, incoming_secret_offset) = match ssl.is_server() {
            true => (server_secret_offset, client_secret_offset),
            false => (client_secret_offset, server_secret_offset),
        };

        Ok(Self {
            ssl_stream,
            protocol_version,
            cipher_kind,
            md,
            incoming_secret_offset,
            outgoing_secret_offset,
            rx_seq: 0,
        })
    }

    fn incoming_secret(&self) -> &[u8] {
        let ptr = self.ssl_stream.ssl() as *const _ as *const u8;
        // SAFETY: the SSL struct layout is stable in the same process
        unsafe { slice::from_raw_parts(ptr.add(self.incoming_secret_offset), self.md.size()) }
    }

    fn outgoing_secret(&self) -> &[u8] {
        let ptr = self.ssl_stream.ssl() as *const _ as *const u8;
        // SAFETY: the SSL struct layout is stable in the same process
        unsafe { slice::from_raw_parts(ptr.add(self.outgoing_secret_offset), self.md.size()) }
    }

    fn extract_tls13_secrets(&self) -> io::Result<Secrets> {
        let mut rv = Secrets::new(self.cipher_kind);
        rv.outgoing_secrets
            .tls1_3_derive_key_and_iv(self.md, self.outgoing_secret())?;
        rv.incoming_secrets
            .tls1_3_derive_key_and_iv(self.md, self.incoming_secret())?;
        if self.ssl_stream.ssl().is_server() {
            // This hack depends on OpenSSL implementation detail: each NewSessionTicket
            // message is always encrypted in one TLS record
            rv.tx_seq = self.ssl_stream.ssl().num_tickets() as _;
        }
        Ok(rv)
    }

    fn take_inner(&mut self) -> io::Result<S> {
        self.ssl_stream.get_mut().take_stream()
    }

    fn feed_message(&mut self, msg: HandshakeMessage) -> io::Result<()> {
        // Re-derive incoming traffic secrets to avoid caching them
        let mut traffic_secrets = TrafficSecrets::new(self.cipher_kind);
        traffic_secrets.tls1_3_derive_key_and_iv(self.md, self.incoming_secret())?;

        // Re-encrypt the plaintext message and feed it back to OpenSSL
        let msg = msg.into_tls13_inner_plaintext()?;
        for trunk in traffic_secrets.encrypt_tls13_record(&msg, self.rx_seq)? {
            self.ssl_stream.get_mut().feed(&trunk)?;
        }
        self.rx_seq += 1;

        // Drive the OpenSSL state machine
        let mut tmp = [0u8; 1];
        match self.ssl_stream.read(&mut tmp) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
            Ok(_) => Err(io::Error::other(
                "unexpectedly read data after feeding control message",
            )),
        }
    }

    #[cfg(key_update)]
    fn key_update(&mut self) -> io::Result<()> {
        use std::io::Write;

        use libc::{c_int, c_void};
        use openssl::error::ErrorStack;

        const SSL_KEY_UPDATE_NOT_REQUESTED: c_int = 0;

        unsafe extern "C" {
            fn SSL_key_update(ssl: *mut c_void, updatetype: c_int) -> c_int;
        }

        let ssl = self.ssl_stream.ssl() as *const _;
        if unsafe { SSL_key_update(ssl as *mut _, SSL_KEY_UPDATE_NOT_REQUESTED) } == 0 {
            return Err(ErrorStack::get().into());
        }
        let _ = self.ssl_stream.write(&[0; 1])?;
        self.ssl_stream.get_mut().take_write_buf()?;
        Ok(())
    }
}

impl<S> ktls_core::TlsSession for KtlsSession<S> {
    fn peer(&self) -> Peer {
        match self.ssl_stream.ssl().is_server() {
            true => Peer::Server,
            false => Peer::Client,
        }
    }

    fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    #[cfg(key_update)]
    fn update_tx_secret(&mut self) -> ktls_core::error::Result<TlsCryptoInfoTx> {
        self.key_update()
            .map_err(ktls_core::Error::KeyUpdateFailed)?;
        let secrets = TrafficSecrets::new(self.cipher_kind)
            .tls1_3_derive_key_and_iv(self.md, self.outgoing_secret())
            .map_err(ktls_core::Error::KeyUpdateFailed)?
            .try_into()
            .map_err(|e| ktls_core::Error::Tls(Box::new(e)))?;
        TlsCryptoInfoTx::new(self.protocol_version, secrets, 0)
    }

    #[cfg(not(key_update))]
    fn update_tx_secret(&mut self) -> ktls_core::error::Result<TlsCryptoInfoTx> {
        unreachable!("should not be called without key_update flag")
    }

    #[cfg(key_update)]
    fn update_rx_secret(&mut self) -> ktls_core::error::Result<TlsCryptoInfoRx> {
        use super::super::tls::{IntoMessage, KeyUpdateRequest};
        self.feed_message(KeyUpdateRequest::new(false).into_message())
            .map_err(ktls_core::Error::KeyUpdateFailed)?;
        self.rx_seq = 0;
        let secrets = TrafficSecrets::new(self.cipher_kind)
            .tls1_3_derive_key_and_iv(self.md, self.incoming_secret())
            .map_err(ktls_core::Error::KeyUpdateFailed)?
            .try_into()
            .map_err(|e| ktls_core::Error::Tls(Box::new(e)))?;
        TlsCryptoInfoRx::new(self.protocol_version, secrets, 0)
    }

    #[cfg(not(key_update))]
    fn update_rx_secret(&mut self) -> ktls_core::error::Result<TlsCryptoInfoRx> {
        unreachable!("should not be called without key_update flag")
    }

    fn handle_new_session_ticket(&mut self, payload: &[u8]) -> ktls_core::error::Result<()> {
        self.feed_message(HandshakeMessage::NewSessionTicket(Cow::Borrowed(payload)))
            .map_err(ktls_core::Error::HandleNewSessionTicketFailed)
    }
}

struct MemStream {
    read_buf: Rc<RefCell<Vec<u8>>>,
    write_buf: Rc<RefCell<Vec<u8>>>,
}

impl MemStream {
    fn pair() -> (Self, Self) {
        let a = Rc::new(RefCell::new(Vec::new()));
        let b = Rc::new(RefCell::new(Vec::new()));
        (
            MemStream {
                read_buf: a.clone(),
                write_buf: b.clone(),
            },
            MemStream {
                read_buf: b,
                write_buf: a,
            },
        )
    }
}

impl io::Read for MemStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut mem = self.read_buf.borrow_mut();
        let res = mem.len().min(buf.len());
        if res == 0 {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "buffer is empty"))
        } else {
            buf[..res].copy_from_slice(&mem[..res]);
            mem.drain(..res);
            Ok(res)
        }
    }
}

impl io::Write for MemStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_buf.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TryFrom<&SslCipherRef> for CipherKind {
    type Error = io::Error;

    fn try_from(cipher: &SslCipherRef) -> io::Result<CipherKind> {
        let nid = cipher
            .cipher_nid()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "unsupported cipher type"))?;
        match nid {
            Nid::AES_128_GCM => Ok(CipherKind::Aes128Gcm),
            Nid::AES_256_GCM => Ok(CipherKind::Aes256Gcm),
            Nid::AES_128_CCM => Ok(CipherKind::Aes128Ccm),
            Nid::CHACHA20_POLY1305 => Ok(CipherKind::ChaCha20Poly1305),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported cipher type",
            )),
        }
    }
}

impl From<CipherKind> for symm::Cipher {
    fn from(cipher: CipherKind) -> symm::Cipher {
        match cipher {
            CipherKind::Aes128Gcm => Self::aes_128_gcm(),
            CipherKind::Aes256Gcm => Self::aes_256_gcm(),
            CipherKind::Aes128Ccm => Self::aes_128_ccm(),
            CipherKind::ChaCha20Poly1305 => Self::chacha20_poly1305(),
        }
    }
}

impl TrafficSecrets {
    fn tls1_3_derive_key_and_iv(&mut self, md: &MdRef, secret: &[u8]) -> io::Result<&Self> {
        let key_size = self.cipher_kind.key_size();
        let salt_size = self.cipher_kind.salt_size();
        let iv_size = self.cipher_kind.iv_size();

        let out = &mut self.buf[0..key_size];
        tls13_hkdf_expand(md, secret, b"key", out)?;

        let out = &mut self.buf[key_size..key_size + salt_size + iv_size];
        tls13_hkdf_expand(md, secret, b"iv", out)?;
        Ok(self)
    }

    fn encrypt_tls13_record(&self, inner_plaintext: &[u8], seq: u64) -> io::Result<[Vec<u8>; 3]> {
        // Construct nonce = (salt || iv) XOR padded_seq
        let salt = self.salt();
        let iv = self.iv();
        let nonce_len = salt.len() + iv.len();
        let mut nonce = Vec::with_capacity(nonce_len);
        nonce.extend_from_slice(salt);
        nonce.extend_from_slice(iv);
        let seq_be = seq.to_be_bytes();
        let seq_be_len = seq_be.len();
        assert!(nonce_len >= seq_be_len);
        seq_be
            .into_iter()
            .zip(nonce.iter_mut().skip(nonce_len - seq_be_len))
            .for_each(|(s, n)| *n ^= s);

        // AAD = TLS record header
        const TAG_LEN: usize = 16;
        let encrypted_len: u16 = (inner_plaintext.len() + TAG_LEN)
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many bytes"))?;
        let mut aad = Vec::new();
        aad.push(ContentType::ApplicationData.into());
        aad.extend_from_slice(&u16::from(ProtocolVersion::TLSv1_2).to_be_bytes());
        aad.extend_from_slice(&encrypted_len.to_be_bytes());

        // AEAD-encrypt
        let mut tag = vec![0u8; TAG_LEN];
        let ciphertext = symm::encrypt_aead(
            self.cipher_kind.into(),
            self.key(),
            Some(&nonce),
            &aad,
            inner_plaintext,
            &mut tag,
        )?;

        Ok([aad, ciphertext, tag])
    }
}

pub(crate) fn probe_tls13_secret_offsets(mode: MemmemMode) -> io::Result<(usize, usize)> {
    // Cached secret offsets
    static TLS13_SECRET_OFFSETS: OnceLock<(usize, usize)> = OnceLock::new();
    if let Some(offsets) = TLS13_SECRET_OFFSETS.get() {
        return Ok(*offsets);
    }

    // Prepare the keylog callback
    let prober_idx = Ssl::new_ex_index::<Mutex<Tls13SecretOffsetProber>>()?;
    let keylog_callback = move |ssl: &SslRef, line: &str| {
        if let Some(prober) = ssl.ex_data(prober_idx)
            && let Ok(mut prober) = prober.lock()
        {
            prober.feed_keylog(line.as_bytes());
        }
    };

    // Load private key
    let pem = include_bytes!("key.pem");
    let pkey = PKey::private_key_from_pem(pem.as_ref())?;

    // Construct a short-lived self-signed certificate
    use openssl::{asn1::Asn1Time, bn::BigNum, hash::MessageDigest, x509::X509Builder};
    let mut builder = X509Builder::new()?;
    let serial = BigNum::from_u32(1)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
    builder.set_pubkey(&pkey)?;
    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = builder.build();

    // Build the server-side SslContext
    let mut builder = SslContextBuilder::new(SslMethod::tls_server())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_certificate(&cert)?;
    builder.set_private_key(&pkey)?;
    builder.set_keylog_callback(keylog_callback);
    let s_ctx = builder.build();

    // Build the client-side SslContext
    let mut builder = SslContextBuilder::new(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_keylog_callback(keylog_callback);
    let c_ctx = builder.build();

    // Now, handshake twice. Probe for the secret offsets first, then verify them.
    let mut client_offset = 0;
    let mut server_offset = 0;
    for probing in [true, false] {
        // Construct the SSLs, probe with the server while verify with the client
        let mut client = Ssl::new(&c_ctx)?;
        client.set_verify(SslVerifyMode::NONE);
        let mut server = Ssl::new(&s_ctx)?;
        (if probing { &mut server } else { &mut client }).set_ex_data(
            prober_idx,
            // SAFETY: all MemmemModes are safe with the openssl crate
            Mutex::new(unsafe { Tls13SecretOffsetProber::new(mode) }),
        );

        // Do handshake in the same thread
        use HandshakeError::*;
        let (c_stream, s_stream) = MemStream::pair();
        let mut c_res = client.connect(c_stream);
        let mut s_res = server.accept(s_stream);
        let do_handshake = |res| match res {
            Ok(s) => Ok(Ok(s)),
            Err(WouldBlock(s)) => Ok(s.handshake()),
            Err(SetupFailure(e)) => Err(e.into()),
            Err(Failure(s)) => match s.into_error().into_io_error() {
                Ok(e) => Err(e),
                Err(e) => Err(io::Error::other(e)),
            },
        };
        let (client, server) = loop {
            (c_res, s_res) = match (c_res, s_res) {
                (Ok(client), Ok(server)) => break (client, server),
                (c_res, s_res) => (do_handshake(c_res)?, do_handshake(s_res)?),
            }
        };

        // Now do probe or verify with the prober
        let ssl = (if probing { &server } else { &client }).ssl();
        let prober = ssl
            .ex_data(prober_idx)
            .expect("has prober")
            .lock()
            .expect("not poisoned");
        let ptr = ssl as *const _ as *const u8;
        if probing {
            (client_offset, server_offset) = prober.probe(ptr)?;
        } else if !prober.verify(ptr, client_offset, server_offset)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "found secret offsets but failed to verify",
            ));
        }
    }

    Ok(*TLS13_SECRET_OFFSETS.get_or_init(|| (client_offset, server_offset)))
}

fn tls13_hkdf_expand(md: &MdRef, secret: &[u8], label: &[u8], out: &mut [u8]) -> io::Result<()> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";
    let out_len: u16 = out
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "requested too large"))?;
    let label_len: u8 = (LABEL_PREFIX.len() + label.len())
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "label too long"))?;

    let mut hkdf_info = vec![];
    hkdf_info.extend_from_slice(&out_len.to_be_bytes());
    hkdf_info.push(label_len);
    hkdf_info.extend_from_slice(LABEL_PREFIX);
    hkdf_info.extend_from_slice(label);
    hkdf_info.push(0); // no data

    use openssl::pkey_ctx::{HkdfMode, PkeyCtx};
    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_mode(HkdfMode::EXPAND_ONLY)?;
    ctx.set_hkdf_md(md)?;
    ctx.set_hkdf_key(secret)?;
    ctx.add_hkdf_info(&hkdf_info)?;
    ctx.derive(Some(out))?;
    Ok(())
}

async fn handshake<S>(
    mut res: Result<SslStream<RecordStream<S>>, HandshakeError<RecordStream<S>>>,
) -> io::Result<SslStream<RecordStream<S>>>
where
    S: AsyncRead + AsyncWrite + AsyncWriteAncillary,
{
    loop {
        match res {
            Ok(mut s) => {
                let inner = s.get_mut();
                if inner.has_pending_write() {
                    inner.flush_write_buf().await?;
                }
                break Ok(s);
            }
            Err(HandshakeError::SetupFailure(e)) => break Err(io::Error::other(e)),
            Err(HandshakeError::Failure(mid_stream)) => {
                break Err(io::Error::other(mid_stream.into_error()));
            }
            Err(HandshakeError::WouldBlock(mut mid_stream)) => {
                let inner = mid_stream.get_mut();
                if inner.has_pending_write() {
                    inner.flush_write_buf().await?;
                } else {
                    inner.fill_read_buf().await?;
                }
                res = mid_stream.handshake();
            }
        }
    }
}

pub(crate) async fn connect_ktls<S>(
    config: Arc<SslConnector>,
    domain: &str,
    stream: S,
    mode: MemmemMode,
) -> io::Result<KtlsStream<S>>
where
    S: AsyncRead + AsyncWrite + AsyncWriteAncillary + AsFd,
{
    let res = config.connect(domain, RecordStream::new(stream));
    let ssl_stream = handshake(res).await?;
    let mut session = KtlsSession::from_ssl(ssl_stream, mode)?;
    let secrets = session.extract_tls13_secrets()?;
    let stream = session.take_inner()?;
    super::setup_ktls(&stream, secrets, &session).map_err(io::Error::other)?;
    Ok(KtlsDuplexStream::new(stream, session).into())
}

pub(crate) async fn accept_ktls<S>(
    config: Arc<SslAcceptor>,
    stream: S,
    mode: MemmemMode,
) -> io::Result<KtlsStream<S>>
where
    S: AsyncRead + AsyncWrite + AsyncWriteAncillary + AsFd,
{
    let res = config.accept(RecordStream::new(stream));
    let ssl_stream = handshake(res).await?;
    let mut session = KtlsSession::from_ssl(ssl_stream, mode)?;
    let secrets = session.extract_tls13_secrets()?;
    let stream = session.take_inner()?;
    super::setup_ktls(&stream, secrets, &session).map_err(io::Error::other)?;
    Ok(KtlsDuplexStream::new(stream, session).into())
}
