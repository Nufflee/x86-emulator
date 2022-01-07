use core::convert::TryInto;

/// Trait for converting an array of bytes ([u8]'s) to an object (`Self`) in little endian byte order.
pub trait FromLeBytes {
    fn from_le_bytes(bytes: &[u8]) -> Self;
}

impl FromLeBytes for u8 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            1,
            "from_le_bytes for u8 expects 1 byte, but gotten {}",
            bytes.len()
        );

        bytes[0]
    }
}

impl FromLeBytes for u16 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            2,
            "from_le_bytes for u16 expects 2 bytes, but gotten {}",
            bytes.len()
        );

        u16::from_le_bytes(bytes.try_into().unwrap())
    }
}

impl FromLeBytes for u32 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            4,
            "from_le_bytes for u32 expects 4 bytes, but gotten {}",
            bytes.len()
        );

        u32::from_le_bytes(bytes.try_into().unwrap())
    }
}
