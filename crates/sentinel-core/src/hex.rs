//! Lowercase hexadecimal encoding for digests.
//!
//! `sha2` 0.11 returns a `hybrid_array::Array`, which implements no `LowerHex`,
//! so `format!("{digest:x}")` no longer compiles. Encoding here rather than
//! taking a hex dependency keeps the encoding under our own tests, which matters
//! because these digests are load-bearing: they appear in condition identifiers
//! that latches are keyed on, and in the state schema checksum that every
//! existing database is validated against. A change in encoding would reset
//! every latch and reject every database.

/// Lowercase hex, two characters per byte, no separators or prefix. Byte for
/// byte what `digest`'s `LowerHex` produced through `sha2` 0.10.
pub fn encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String is infallible.
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::encode;

    /// Pins the encoding against published SHA-256 vectors, so no dependency
    /// upgrade can silently change how a digest is spelled.
    #[test]
    fn matches_published_sha256_vectors() {
        assert_eq!(
            encode(&Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            encode(&Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn pads_every_byte_to_two_lowercase_characters() {
        assert_eq!(encode(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(encode(&[]), "");
    }
}
