//! `abi` — a minimal, dependency-light ABI codec for the *static* READ calls
//! the node agent makes.
//!
//! SELL-S1 only needs to encode a handful of `eth_call` argument lists
//! (`address`, `uint256`) and decode ABI tuples of fixed-size words
//! (`uint256`, `address`, `bool`, `enum`→`uint8`). That is all static head
//! data — every value occupies exactly one 32-byte word — so we don't need a
//! general dynamic-type (`bytes`/`string`/array) decoder here. The marketplace
//! `Job.inputHash` is `bytes` (dynamic) and is *not* part of the S1 READ
//! surface; the structs we decode use only static fields.
//!
//! All integers are big-endian, matching the EVM word layout.

/// A single 32-byte ABI word, big-endian.
pub type Word = [u8; 32];

/// An EVM address (20 bytes).
pub type Address = [u8; 20];

/// Errors decoding ABI return data.
#[derive(Debug, PartialEq, Eq)]
pub enum AbiError {
    /// Return data was shorter than the expected number of words.
    TooShort { need: usize, got: usize },
    /// A `uint256` word didn't fit in the requested narrower integer.
    Overflow,
    /// A `bool` word was neither 0 nor 1.
    BadBool,
    /// An `address` word had non-zero bytes in the top 12 (left) bytes.
    BadAddress,
    /// A hex string was malformed (bad prefix, odd length, non-hex digit).
    BadHex,
}

impl core::fmt::Display for AbiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AbiError::TooShort { need, got } => {
                write!(f, "ABI data too short: need {need} words, got {got}")
            }
            AbiError::Overflow => write!(f, "uint256 overflows target integer width"),
            AbiError::BadBool => write!(f, "bool word is neither 0 nor 1"),
            AbiError::BadAddress => write!(f, "address has dirty high bytes"),
            AbiError::BadHex => write!(f, "malformed hex"),
        }
    }
}

impl std::error::Error for AbiError {}

/// Left-pad a `u128` into a 32-byte big-endian `uint256` word.
pub fn word_from_u128(v: u128) -> Word {
    let mut w = [0u8; 32];
    w[16..32].copy_from_slice(&v.to_be_bytes());
    w
}

/// Left-pad a 20-byte address into a 32-byte word (12 zero bytes + address).
pub fn word_from_address(a: Address) -> Word {
    let mut w = [0u8; 32];
    w[12..32].copy_from_slice(&a);
    w
}

/// Encode a function call: 4-byte `selector` followed by the `args` words.
pub fn encode_call(selector: [u8; 4], args: &[Word]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * args.len());
    out.extend_from_slice(&selector);
    for w in args {
        out.extend_from_slice(w);
    }
    out
}

/// Encode the *tail* of a dynamic `bytes` value: a 32-byte big-endian length
/// word followed by the data right-padded with zeros to a 32-byte boundary.
///
/// The *head* offset word that points at this tail is written by the caller
/// (it depends on how many other head words/tails precede it). This is the one
/// piece of dynamic ABI encoding the agent needs — for `submitResult`'s two
/// `bytes` arguments — so it lives here rather than pulling in a full codec.
pub fn encode_bytes_tail(bytes: &[u8]) -> Vec<u8> {
    let padded = bytes.len().div_ceil(32) * 32;
    let mut out = Vec::with_capacity(32 + padded);
    out.extend_from_slice(&word_from_u128(bytes.len() as u128));
    out.extend_from_slice(bytes);
    out.resize(32 + padded, 0);
    out
}

/// A cursor over ABI return data, reading 32-byte words left to right.
pub struct Decoder<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    /// Wrap raw return data (already hex-decoded bytes).
    pub fn new(data: &'a [u8]) -> Self {
        Decoder { data, offset: 0 }
    }

    /// Read the next raw 32-byte word.
    pub fn word(&mut self) -> Result<Word, AbiError> {
        let end = self.offset + 32;
        if end > self.data.len() {
            return Err(AbiError::TooShort {
                need: end.div_ceil(32),
                got: self.data.len() / 32,
            });
        }
        let mut w = [0u8; 32];
        w.copy_from_slice(&self.data[self.offset..end]);
        self.offset = end;
        Ok(w)
    }

    /// Read a `uint256` as a `u128` (fails if the value exceeds 128 bits).
    pub fn u128(&mut self) -> Result<u128, AbiError> {
        let w = self.word()?;
        if w[0..16].iter().any(|&b| b != 0) {
            return Err(AbiError::Overflow);
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&w[16..32]);
        Ok(u128::from_be_bytes(buf))
    }

    /// Read a `uint256` as a full 32-byte big-endian word (no narrowing).
    pub fn u256_word(&mut self) -> Result<Word, AbiError> {
        self.word()
    }

    /// Read a `bool` (must be exactly 0 or 1).
    pub fn bool(&mut self) -> Result<bool, AbiError> {
        let w = self.word()?;
        if w[0..31].iter().any(|&b| b != 0) {
            return Err(AbiError::BadBool);
        }
        match w[31] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AbiError::BadBool),
        }
    }

    /// Read an `address` (20 bytes; the high 12 bytes must be zero).
    pub fn address(&mut self) -> Result<Address, AbiError> {
        let w = self.word()?;
        if w[0..12].iter().any(|&b| b != 0) {
            return Err(AbiError::BadAddress);
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&w[12..32]);
        Ok(a)
    }

    /// Read an `enum` value (a `uint8` packed in a word; must fit in a byte).
    pub fn u8_enum(&mut self) -> Result<u8, AbiError> {
        let w = self.word()?;
        if w[0..31].iter().any(|&b| b != 0) {
            return Err(AbiError::Overflow);
        }
        Ok(w[31])
    }
}

/// Parse a `0x`-prefixed hex string into bytes.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, AbiError> {
    let s = s.strip_prefix("0x").ok_or(AbiError::BadHex)?;
    if s.len() % 2 != 0 {
        return Err(AbiError::BadHex);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let nib = |c: u8| -> Result<u8, AbiError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(AbiError::BadHex),
        }
    };
    for pair in bytes.chunks(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Ok(out)
}

/// Encode bytes to a `0x`-prefixed lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Parse a `0x`-prefixed 40-hex-digit address string into an [`Address`].
pub fn address_from_hex(s: &str) -> Result<Address, AbiError> {
    let bytes = hex_decode(s)?;
    if bytes.len() != 20 {
        return Err(AbiError::BadHex);
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&bytes);
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u128_round_trips_through_word() {
        for v in [0u128, 1, 1_000_000_000_000_000_000, u128::MAX] {
            let w = word_from_u128(v);
            let mut d = Decoder::new(&w);
            assert_eq!(d.u128().unwrap(), v);
        }
    }

    #[test]
    fn u128_overflow_is_detected() {
        // A word with a 1 in the top half cannot be a u128.
        let mut w = [0u8; 32];
        w[0] = 1;
        let mut d = Decoder::new(&w);
        assert_eq!(d.u128(), Err(AbiError::Overflow));
    }

    #[test]
    fn address_round_trips() {
        let a: Address = [
            0xf3, 0xf9, 0xf7, 0x2e, 0xa2, 0xbb, 0x3f, 0x76, 0x3b, 0x07, 0x39, 0x0b, 0x72, 0x57,
            0xda, 0x64, 0x3b, 0x8e, 0xe9, 0xb6,
        ];
        let w = word_from_address(a);
        let mut d = Decoder::new(&w);
        assert_eq!(d.address().unwrap(), a);
    }

    #[test]
    fn dirty_high_byte_address_rejected() {
        let mut w = word_from_address([0x11; 20]);
        w[0] = 0xaa; // dirt in the padding
        let mut d = Decoder::new(&w);
        assert_eq!(d.address(), Err(AbiError::BadAddress));
    }

    #[test]
    fn bool_decodes_and_validates() {
        let mut t = [0u8; 32];
        t[31] = 1;
        assert!(Decoder::new(&t).bool().unwrap());
        let f = [0u8; 32];
        assert!(!Decoder::new(&f).bool().unwrap());
        let mut bad = [0u8; 32];
        bad[31] = 2;
        assert_eq!(Decoder::new(&bad).bool(), Err(AbiError::BadBool));
    }

    #[test]
    fn enum_decodes_small_int() {
        let mut w = [0u8; 32];
        w[31] = 5; // JobState::Completed
        let mut d = Decoder::new(&w);
        assert_eq!(d.u8_enum().unwrap(), 5);
    }

    #[test]
    fn too_short_data_errors() {
        let data = [0u8; 16];
        let mut d = Decoder::new(&data);
        assert!(matches!(d.u128(), Err(AbiError::TooShort { .. })));
    }

    #[test]
    fn encode_call_lays_out_selector_then_args() {
        let sel = [0xaa, 0xbb, 0xcc, 0xdd];
        let arg = word_from_u128(7);
        let call = encode_call(sel, &[arg]);
        assert_eq!(call.len(), 4 + 32);
        assert_eq!(&call[0..4], &sel);
        assert_eq!(call[4 + 31], 7);
    }

    #[test]
    fn encode_bytes_tail_lengths_and_padding() {
        // Empty: just a zero length word.
        assert_eq!(encode_bytes_tail(&[]), vec![0u8; 32]);
        // 5 bytes → length word(=5) + 32-byte padded data block.
        let t = encode_bytes_tail(b"hello");
        assert_eq!(t.len(), 64);
        assert_eq!(t[31], 5); // length
        assert_eq!(&t[32..37], b"hello");
        assert!(t[37..64].iter().all(|&b| b == 0)); // zero-padded tail
        // Exactly 32 bytes → no extra padding word.
        let t32 = encode_bytes_tail(&[0xab; 32]);
        assert_eq!(t32.len(), 64);
        assert_eq!(t32[31], 32);
        assert_eq!(&t32[32..64], &[0xab; 32]);
        // 33 bytes → padded to 64.
        assert_eq!(encode_bytes_tail(&[0u8; 33]).len(), 32 + 64);
    }

    #[test]
    fn hex_round_trips() {
        let bytes = vec![0x00, 0x0f, 0xf0, 0xff];
        let s = hex_encode(&bytes);
        assert_eq!(s, "0x000ff0ff");
        assert_eq!(hex_decode(&s).unwrap(), bytes);
    }

    #[test]
    fn hex_decode_rejects_bad_input() {
        assert_eq!(hex_decode("000f"), Err(AbiError::BadHex)); // no 0x
        assert_eq!(hex_decode("0x0"), Err(AbiError::BadHex)); // odd length
        assert_eq!(hex_decode("0xzz"), Err(AbiError::BadHex)); // non-hex
    }

    #[test]
    fn address_from_hex_parses_canonical() {
        let a = address_from_hex("0xf3f9f72ea2bb3f763b07390b7257da643b8ee9b6").unwrap();
        assert_eq!(a[0], 0xf3);
        assert_eq!(a[19], 0xb6);
        assert_eq!(
            address_from_hex("0x1234"), // wrong length
            Err(AbiError::BadHex)
        );
    }

    #[test]
    fn sequential_decode_advances_cursor() {
        // Two packed words: uint256(9) then address(...).
        let a: Address = [0x22; 20];
        let mut data = Vec::new();
        data.extend_from_slice(&word_from_u128(9));
        data.extend_from_slice(&word_from_address(a));
        let mut d = Decoder::new(&data);
        assert_eq!(d.u128().unwrap(), 9);
        assert_eq!(d.address().unwrap(), a);
    }
}
