mod from_le_bytes;

use core::mem;
use from_le_bytes::FromLeBytes;

/// A stateful _little-endian_ byte reader. It can operate on and read out of the byte stream any type that
/// implements [FromLeBytes].  
pub struct ByteReader<'a> {
    data: &'a [u8],
    index: usize,
}

// TODO: Error generation
impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, index: 0 }
    }

    /// Reads the next `T` from the byte stream and advances the index by its size in bytes.
    pub fn next<T: FromLeBytes>(&mut self) -> T {
        let value = self.peek::<T>();

        self.advance(mem::size_of::<T>());

        value
    }

    /// Peeks at and returns the next `T` in the byte stream without advancing the index.
    pub fn peek<T: FromLeBytes>(&mut self) -> T {
        let size = mem::size_of::<T>();

        assert!(
            self.index + size <= self.data.len(),
            "cannot read past the end of a BinaryReader"
        );

        T::from_le_bytes(&self.data[self.index..self.index + mem::size_of::<T>()])
    }

    // Advance the stream by `amount` bytes without returning any value.
    pub fn advance(&mut self, amount: usize) {
        self.index += amount;
    }

    /// Returns `true` if the next `T` in the byte stream matches `value` and advances the index, otherwise returns
    /// `false` without advancing the index  
    pub fn match_value<T: FromLeBytes + PartialEq>(&mut self, value: T) -> bool {
        if self.peek::<T>() == value {
            self.advance(mem::size_of::<T>());
            true
        } else {
            false
        }
    }

    /// Resets teh byte index to 0, i.e. the start of the binary stream
    pub fn reset(&mut self) {
        self.index = 0;
    }

    /// Returns the current byte index (address) of the [ByteReader]
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn is_at_end(&self) -> bool {
        self.index == self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_32() {
        let mut nexter = ByteReader::new(&[0x42, 0x69, 0x11, 0x22]);

        assert_eq!(nexter.next::<u32>(), 0x22116942);
        assert!(nexter.is_at_end());

        nexter.reset();

        assert_eq!(nexter.next::<u32>(), 0x22116942);
        assert!(nexter.is_at_end());
    }

    #[test]
    fn next_16() {
        let mut nexter = ByteReader::new(&[0x42, 0x69, 0x11, 0x22]);

        assert_eq!(nexter.next::<u16>(), 0x6942);
        assert_eq!(nexter.index(), 2);
        assert_eq!(nexter.next::<u16>(), 0x2211);
        assert!(nexter.is_at_end());
    }

    #[test]
    fn next_8() {
        let mut nexter = ByteReader::new(&[0x42, 0x69, 0x11, 0x22]);

        assert_eq!(nexter.next::<u8>(), 0x42);
        assert_eq!(nexter.index(), 1);
        assert_eq!(nexter.next::<u8>(), 0x69);
        assert_eq!(nexter.index(), 2);
        assert_eq!(nexter.next::<u8>(), 0x11);
        assert_eq!(nexter.index(), 3);
        assert_eq!(nexter.next::<u8>(), 0x22);
        assert!(nexter.is_at_end());
    }

    #[test]
    fn peek_32() {
        let mut nexter = ByteReader::new(&[0x42, 0x69, 0x11, 0x22]);

        assert_eq!(nexter.peek::<u32>(), 0x22116942);
        assert_eq!(nexter.index(), 0);
    }
}
