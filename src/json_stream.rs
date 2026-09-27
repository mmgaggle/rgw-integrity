//! Streaming the JSON arrays radosgw-admin prints, one element at a time, so a
//! large listing never has to fit in memory.

use std::fmt;
use std::io::{self, Read};
use std::marker::PhantomData;

use serde::de::{DeserializeOwned, Error as _, SeqAccess, Visitor};
use serde::Deserializer as _;

/// Passes valid UTF-8 through, and replaces invalid bytes with U+FFFD:
/// `bi list` prints index keys with raw 0x80 bytes, which serde_json refuses.
pub struct LossyUtf8<R> {
    inner: R,
    out: Vec<u8>,
    pos: usize,
    carry: Vec<u8>,
    eof: bool,
}

impl<R: Read> LossyUtf8<R> {
    pub fn new(inner: R) -> Self {
        LossyUtf8 { inner, out: Vec::new(), pos: 0, carry: Vec::new(), eof: false }
    }

    fn refill(&mut self) -> io::Result<()> {
        let mut chunk = vec![0u8; 1 << 16];
        let n = self.inner.read(&mut chunk)?;
        let mut data = std::mem::take(&mut self.carry);
        data.extend_from_slice(&chunk[..n]);
        self.out.clear();
        self.pos = 0;
        if n == 0 {
            self.eof = true;
            self.out.extend_from_slice(String::from_utf8_lossy(&data).as_bytes());
            return Ok(());
        }
        let mut rest = &data[..];
        loop {
            match std::str::from_utf8(rest) {
                Ok(s) => {
                    self.out.extend_from_slice(s.as_bytes());
                    break;
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    self.out.extend_from_slice(&rest[..valid]);
                    match e.error_len() {
                        Some(len) => {
                            self.out.extend_from_slice("\u{FFFD}".as_bytes());
                            rest = &rest[valid + len..];
                        }
                        None => {
                            // a sequence the next chunk completes
                            self.carry = rest[valid..].to_vec();
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for LossyUtf8<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.out.len() {
            if self.eof {
                return Ok(0);
            }
            self.refill()?;
        }
        let n = buf.len().min(self.out.len() - self.pos);
        buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

struct Each<T, F>(F, PhantomData<T>);

impl<'de, T, F> Visitor<'de> for Each<T, F>
where
    T: DeserializeOwned,
    F: FnMut(T) -> anyhow::Result<()>,
{
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON array")
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
        while let Some(item) = seq.next_element::<T>()? {
            (self.0)(item).map_err(|e| A::Error::custom(format!("{e:#}")))?;
        }
        Ok(())
    }
}

/// Call `f` with each element of the JSON array `reader` holds.  Empty input
/// is an empty array.
pub fn for_each<R, T, F>(reader: R, f: F) -> anyhow::Result<()>
where
    R: Read,
    T: DeserializeOwned,
    F: FnMut(T) -> anyhow::Result<()>,
{
    let mut reader = io::BufReader::with_capacity(1 << 20, LossyUtf8::new(reader));
    // treat empty input as an empty array
    let mut first = [0u8; 1];
    loop {
        match reader.read(&mut first)? {
            0 => return Ok(()),
            _ if first[0].is_ascii_whitespace() => continue,
            _ => break,
        }
    }
    let chained = io::Cursor::new(first).chain(reader);
    let mut de = serde_json::Deserializer::from_reader(chained);
    de.deserialize_seq(Each(f, PhantomData))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream() {
        let items: Vec<serde_json::Value> =
            (0..200).map(|i| serde_json::json!({"a": i, "s": "x".repeat(i * 7)})).collect();
        let text = serde_json::to_string_pretty(&items).unwrap();
        let mut got = Vec::new();
        for_each(text.as_bytes(), |v: serde_json::Value| {
            got.push(v);
            Ok(())
        })
        .unwrap();
        assert_eq!(got, items);
        let mut n = 0;
        for_each("  []".as_bytes(), |_: serde_json::Value| {
            n += 1;
            Ok(())
        })
        .unwrap();
        for_each("".as_bytes(), |_: serde_json::Value| {
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn lossy() {
        let raw = b"[{\"idx\": \"\x801000_obj\", \"name\": \"\xc3\xa9t\xc3\xa9\"}]";
        let mut got = Vec::new();
        for_each(&raw[..], |v: serde_json::Value| {
            got.push(v);
            Ok(())
        })
        .unwrap();
        assert_eq!(got[0]["idx"], "\u{FFFD}1000_obj");
        assert_eq!(got[0]["name"], "été");
        // a multibyte sequence split across reads
        let mut r = LossyUtf8::new(io::Cursor::new(b"\xc3".to_vec()).chain(io::Cursor::new(b"\xa9".to_vec())));
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "é");
    }
}
