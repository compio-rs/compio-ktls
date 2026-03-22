// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
// Copyright 2026 Fantix King

use compio_buf::{BufResult, IntoInner, IoBuf, IoVectoredBuf};
use compio_io::ancillary::AsyncWriteAncillary;

macro_rules! loop_write_all {
    ($buf:ident, $control:ident, $len:expr, $needle:ident,loop $expr_expr:expr) => {
        let len = $len;
        let mut $needle = 0;

        while $needle < len {
            match $expr_expr.await.map_buffer(|(b, c)| (b.into_inner(), c)) {
                BufResult(Ok(0), buf) => {
                    return BufResult(
                        Err(::std::io::Error::new(
                            ::std::io::ErrorKind::WriteZero,
                            "failed to write whole buffer",
                        )),
                        buf,
                    );
                }
                BufResult(Ok(n), (b, c)) => {
                    $needle += n;
                    $buf = b;
                    $control = c;
                }
                BufResult(Err(ref e), (b, c)) if e.kind() == ::std::io::ErrorKind::Interrupted => {
                    $buf = b;
                    $control = c;
                }
                BufResult(Err(e), buf) => {
                    return BufResult(Err(e), buf);
                }
            }
        }
        return BufResult(Ok(()), ($buf, $control));
    };
}

pub(crate) trait AsyncWriteAncillaryExt: AsyncWriteAncillary {
    async fn write_all_with_ancillary<B: IoBuf, C: IoBuf>(
        &mut self,
        mut buf: B,
        mut control: C,
    ) -> BufResult<(), (B, C)> {
        loop_write_all!(
            buf,
            control,
            buf.buf_len(),
            needle,
            loop self.write_with_ancillary(buf.slice(needle..), control)
        );
    }

    async fn write_vectored_all_with_ancillary<B: IoVectoredBuf, C: IoBuf>(
        &mut self,
        mut buf: B,
        mut control: C,
    ) -> BufResult<(), (B, C)> {
        loop_write_all!(
            buf,
            control,
            buf.total_len(),
            needle,
            loop self.write_vectored_with_ancillary(buf.slice(needle), control)
        );
    }
}

impl<A: AsyncWriteAncillary + ?Sized> AsyncWriteAncillaryExt for A {}
