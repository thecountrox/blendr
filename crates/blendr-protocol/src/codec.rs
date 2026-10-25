//! Fixed-shape CBOR, with minimal integer/length encodings checked as read.
//! No generic CBOR tree or allocation based on an untrusted declared length.
use crate::{Error, Result};
use blendr_identity::IdentityDocument;

pub(crate) struct Writer(minicbor::Encoder<Vec<u8>>);
impl Writer {
    pub fn new() -> Self {
        Self(minicbor::Encoder::new(Vec::new()))
    }
    pub fn array(&mut self, n: u64) {
        self.0.array(n).expect("Vec encoding");
    }
    pub fn uint(&mut self, n: u64) {
        self.0.u64(n).expect("Vec encoding");
    }
    pub fn text(&mut self, s: &str) {
        self.0.str(s).expect("Vec encoding");
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.0.bytes(b).expect("Vec encoding");
    }
    pub fn boolean(&mut self, b: bool) {
        self.0.bool(b).expect("Vec encoding");
    }
    pub fn finish(self) -> Vec<u8> {
        self.0.into_writer()
    }
    pub fn document(&mut self, d: &IdentityDocument) {
        self.array(8);
        self.text(&d.bid);
        self.text(&d.display_name);
        self.uint(d.version);
        self.uint(d.encryption_epoch);
        self.bytes(&d.signing_public_key);
        self.bytes(&d.encryption_public_key);
        self.bytes(&d.signature);
        self.text("bis:1");
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], max: usize) -> Result<Self> {
        if bytes.len() > max {
            return Err(Error::Limit);
        }
        Ok(Self { bytes, pos: 0 })
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Malformed)?;
        let result = self.bytes.get(self.pos..end).ok_or(Error::Malformed)?;
        self.pos = end;
        Ok(result)
    }
    fn head(&mut self, major: u8) -> Result<u64> {
        let byte = self.take(1)?[0];
        if byte >> 5 != major {
            return Err(Error::Malformed);
        }
        let (n, minimum) = match byte & 31 {
            n @ 0..=23 => return Ok(u64::from(n)),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => (
                u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().map_err(|_| Error::Malformed)?,
                )),
                256,
            ),
            26 => (
                u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().map_err(|_| Error::Malformed)?,
                )),
                65536,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Error::Malformed)?),
                1u64 << 32,
            ),
            _ => return Err(Error::Malformed),
        };
        if n < minimum {
            return Err(Error::Malformed);
        }
        Ok(n)
    }
    pub fn array(&mut self, n: u64) -> Result<()> {
        if self.head(4)? != n {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub fn uint(&mut self) -> Result<u64> {
        self.head(0)
    }
    pub fn u32(&mut self) -> Result<u32> {
        self.uint()?.try_into().map_err(|_| Error::Limit)
    }
    pub fn timestamp(&mut self) -> Result<i64> {
        self.uint()?.try_into().map_err(|_| Error::Malformed)
    }
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n: usize = self.head(2)?.try_into().map_err(|_| Error::Limit)?;
        if n > max {
            return Err(Error::Limit);
        }
        self.take(n)
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes(N)?.try_into().map_err(|_| Error::Malformed)
    }
    pub fn text(&mut self, max: usize) -> Result<&'a str> {
        let n: usize = self.head(3)?.try_into().map_err(|_| Error::Limit)?;
        if n > max {
            return Err(Error::Limit);
        }
        std::str::from_utf8(self.take(n)?).map_err(|_| Error::Malformed)
    }
    pub fn literal(&mut self, expected: &str) -> Result<()> {
        if self.text(expected.len())? != expected {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    pub fn boolean(&mut self) -> Result<bool> {
        match self.take(1)?[0] {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(Error::Malformed),
        }
    }
    pub fn finish(self) -> Result<()> {
        if self.pos != self.bytes.len() {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub fn document(&mut self) -> Result<IdentityDocument> {
        self.array(8)?;
        let doc = IdentityDocument {
            bid: self.text(52)?.to_owned(),
            display_name: self.text(256)?.to_owned(),
            version: self.uint()?,
            encryption_epoch: self.uint()?,
            signing_public_key: self.fixed()?,
            encryption_public_key: self.fixed()?,
            signature: self.fixed::<64>()?.to_vec(),
        };
        self.literal("bis:1")?;
        Ok(doc)
    }
}
