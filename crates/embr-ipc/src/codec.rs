//! Line framing: one UTF-8 JSON object per `\n`-terminated line, bounded in size.
//!
//! The reader never buffers more than `max` bytes of a line, so an attacker cannot make us
//! allocate unboundedly by never sending a newline.

use std::io::{self, BufRead, Write};

use serde::Serialize;

/// Framing errors.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// The line exceeded the limit.
    #[error("line too long")]
    TooLong,
    /// The stream ended in the middle of a line.
    #[error("connection closed mid-line")]
    Truncated,
    /// The line is not valid UTF-8.
    #[error("invalid UTF-8")]
    InvalidUtf8,
    /// The line contains a NUL byte.
    #[error("NUL byte in line")]
    NulByte,
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// A value could not be serialised.
    #[error("cannot serialise message")]
    Serialize,
}

fn finish(mut buf: Vec<u8>) -> Result<String, CodecError> {
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    if buf.contains(&0) {
        return Err(CodecError::NulByte);
    }
    String::from_utf8(buf).map_err(|_| CodecError::InvalidUtf8)
}

/// Reads one line (without the terminator). `Ok(None)` on clean end of stream.
pub fn read_line<R: BufRead + ?Sized>(r: &mut R, max: usize) -> Result<Option<String>, CodecError> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = r.fill_buf()?;
        if available.is_empty() {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(CodecError::Truncated)
            };
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(i) => {
                if buf.len() + i > max {
                    return Err(CodecError::TooLong);
                }
                buf.extend_from_slice(available.get(..i).unwrap_or_default());
                r.consume(i + 1);
                return finish(buf).map(Some);
            }
            None => {
                let n = available.len();
                if buf.len() + n > max {
                    return Err(CodecError::TooLong);
                }
                buf.extend_from_slice(available);
                r.consume(n);
            }
        }
    }
}

/// Serialises `value` as one line, enforcing the size limit, and flushes.
pub fn write_line<W: Write + ?Sized, T: Serialize + ?Sized>(
    w: &mut W,
    value: &T,
    max: usize,
) -> Result<(), CodecError> {
    let mut bytes = encode_line(value, max)?;
    bytes.push(b'\n');
    w.write_all(&bytes)?;
    w.flush()?;
    Ok(())
}

/// Serialises `value` to JSON bytes (no newline), enforcing the size limit.
pub fn encode_line<T: Serialize + ?Sized>(value: &T, max: usize) -> Result<Vec<u8>, CodecError> {
    let bytes = serde_json::to_vec(value).map_err(|_| CodecError::Serialize)?;
    if bytes.len() > max {
        return Err(CodecError::TooLong);
    }
    Ok(bytes)
}

#[cfg(feature = "tokio")]
mod async_io {
    use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

    use super::{CodecError, finish};

    /// Async counterpart of [`super::read_line`].
    pub async fn read_line_async<R: AsyncBufRead + Unpin>(
        r: &mut R,
        max: usize,
    ) -> Result<Option<String>, CodecError> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let available = r.fill_buf().await?;
            if available.is_empty() {
                return if buf.is_empty() {
                    Ok(None)
                } else {
                    Err(CodecError::Truncated)
                };
            }
            match available.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    if buf.len() + i > max {
                        return Err(CodecError::TooLong);
                    }
                    buf.extend_from_slice(available.get(..i).unwrap_or_default());
                    r.consume(i + 1);
                    return finish(buf).map(Some);
                }
                None => {
                    let n = available.len();
                    if buf.len() + n > max {
                        return Err(CodecError::TooLong);
                    }
                    buf.extend_from_slice(available);
                    r.consume(n);
                }
            }
        }
    }

    /// Writes pre-encoded JSON bytes plus a newline and flushes.
    pub async fn write_bytes_async<W: AsyncWrite + Unpin>(
        w: &mut W,
        mut bytes: Vec<u8>,
    ) -> Result<(), CodecError> {
        bytes.push(b'\n');
        w.write_all(&bytes).await?;
        w.flush().await?;
        Ok(())
    }
}

#[cfg(feature = "tokio")]
pub use async_io::{read_line_async, write_bytes_async};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;

    fn rd(bytes: &[u8], max: usize) -> Result<Option<String>, CodecError> {
        read_line(
            &mut BufReader::with_capacity(7, Cursor::new(bytes.to_vec())),
            max,
        )
    }

    #[test]
    fn reads_lines_across_small_buffers() {
        let mut r =
            BufReader::with_capacity(3, Cursor::new(b"{\"a\":1}\n{\"b\":2}\r\n\nlast\n".to_vec()));
        assert_eq!(read_line(&mut r, 100).unwrap().unwrap(), "{\"a\":1}");
        assert_eq!(
            read_line(&mut r, 100).unwrap().unwrap(),
            "{\"b\":2}",
            "CRLF tolerated"
        );
        assert_eq!(read_line(&mut r, 100).unwrap().unwrap(), "", "empty line");
        assert_eq!(read_line(&mut r, 100).unwrap().unwrap(), "last");
        assert!(read_line(&mut r, 100).unwrap().is_none());
    }

    #[test]
    fn limit_is_exact() {
        assert_eq!(rd(b"12345\n", 5).unwrap().unwrap(), "12345");
        assert!(matches!(rd(b"123456\n", 5), Err(CodecError::TooLong)));
        // No newline at all: must fail at the limit, not buffer forever.
        assert!(matches!(rd(&[b'a'; 1000], 10), Err(CodecError::TooLong)));
    }

    #[test]
    fn truncated_utf8_and_nul_are_rejected() {
        assert!(matches!(rd(b"{\"a\":", 100), Err(CodecError::Truncated)));
        assert!(matches!(
            rd(b"\xff\xfe\n", 100),
            Err(CodecError::InvalidUtf8)
        ));
        assert!(matches!(rd(b"ab\0cd\n", 100), Err(CodecError::NulByte)));
    }

    #[test]
    fn write_enforces_limit_and_terminates() {
        let mut out = Vec::new();
        write_line(&mut out, &serde_json::json!({"a": 1}), 100).unwrap();
        assert_eq!(out, b"{\"a\":1}\n");
        assert!(matches!(
            write_line(&mut out, &serde_json::json!({"a": "x".repeat(200)}), 100),
            Err(CodecError::TooLong)
        ));
    }

    #[tokio::test]
    #[cfg(feature = "tokio")]
    async fn async_reader_matches_sync_behaviour() {
        let data = b"one\ntwo\n".to_vec();
        let mut r = tokio::io::BufReader::with_capacity(2, &data[..]);
        assert_eq!(read_line_async(&mut r, 10).await.unwrap().unwrap(), "one");
        assert_eq!(read_line_async(&mut r, 10).await.unwrap().unwrap(), "two");
        assert!(read_line_async(&mut r, 10).await.unwrap().is_none());
        let mut r = tokio::io::BufReader::new(&b"toolongline\n"[..]);
        assert!(matches!(
            read_line_async(&mut r, 4).await,
            Err(CodecError::TooLong)
        ));
    }
}
