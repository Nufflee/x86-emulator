use std::convert::TryInto;

// This is required for #![no_std]
use alloc::vec::Vec;

pub struct Stack {
    vec: Vec<u8>,
}

impl Stack {
    pub fn new(capacity: u32) -> Self {
        Self {
            vec: Vec::with_capacity(capacity as usize),
        }
    }

    // TODO: Genericize these using a custom trait that wraps `to_le_bytes`
    pub fn push8(&mut self, value: u8) {
        if self.vec.len() + 1 > self.vec.capacity() {
            panic!("stack overflow");
        }

        self.vec.push(value);
    }

    pub fn push32(&mut self, value: u32) {
        if self.vec.len() + 4 > self.vec.capacity() {
            panic!("stack overflow");
        }

        self.vec.append(&mut value.to_le_bytes().to_vec());
    }

    pub fn pop8(&mut self) -> u8 {
        match self.vec.pop() {
            Some(value) => value,
            None => panic!("stack underflow"),
        }
    }

    pub fn pop32(&mut self) -> u32 {
        let final_length = self.vec.len() - 4;

        let value = u32::from_le_bytes(self.vec.split_off(final_length).try_into().unwrap());

        self.vec.truncate(final_length);

        value
    }

    pub fn get_underlaying_vec(&self) -> &Vec<u8> {
        &self.vec
    }

    pub fn dump(&self) {
        println!("stack:");

        for value in &self.vec {
            println!("\t{}", value);
        }
    }

    pub fn get_size(&self) -> u32 {
        self.vec.capacity() as u32
    }
}

#[cfg(test)]
mod tests {
    use crate::stack::Stack;

    #[test]
    fn test_stack() {
        let mut stack = Stack::new(12);

        stack.push32(69);
        stack.push32(420);
        stack.push32(42069);

        assert_eq!(stack.pop32(), 42069);
        assert_eq!(stack.pop32(), 420);
        assert_eq!(stack.pop32(), 69);
    }
}
