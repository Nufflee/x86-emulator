extern crate alloc;

mod byte_reader;
mod cpu;
mod instruction;
mod instruction_decoder;
mod stack;

use core::panic;
use std::{collections::HashMap, fs};

// This is required for #![no_std]
use alloc::vec::Vec;

use cpu::CPU;
use instruction::InstructionKind;
use instruction_decoder::InstructionDecoder;
use stack::Stack;

const STACK_SIZE: u32 = 256;

fn main() {
    // Troolee no_std.
    // let mut binary = include_bytes!("../hello_world.bin").to_vec();
    let mut binary = fs::read("hello_world.bin").unwrap();

    // TODO: is there a better data structure for this?
    let mut instructions = HashMap::new();

    let mut ret_hit = false;

    let mut decoder = InstructionDecoder::new(&binary);

    while decoder.address() < binary.len() {
        let instruction_address = decoder.address();
        let instruction = decoder.decode_next();

        instructions.insert(instruction_address, instruction);

        if instruction.kind == InstructionKind::UD0 {
            ret_hit = true;
            break;
        }
    }

    if !ret_hit {
        panic!("end of program (`ud0`) hasn't been found");
    }

    let memory_base = decoder.address();

    let mut sorted_keys = instructions.keys().collect::<Vec<_>>();

    sorted_keys.sort();

    for key in sorted_keys {
        println!("[{:#x}]\t {:?}", key, instructions[key]);
    }

    let mut stack = Stack::new(STACK_SIZE);
    let mut cpu = CPU::new(&mut stack);

    cpu.execute(
        &instructions,
        memory_base as u32,
        binary.split_off(memory_base as usize),
    );
}
