// TODO: Use conditional compilation in order to make the project compilable on stable
#![feature(asm)]

extern crate alloc;

mod cpu;
mod instruction;
mod stack;

use core::{
    convert::{TryFrom, TryInto},
    panic,
};
use std::{collections::HashMap, fs};

// This is required for #![no_std]
use alloc::vec::Vec;

use cpu::CPU;
use instruction::{
    opcode::*, Instruction, InstructionDestination, InstructionKind, InstructionSource, Register32,
    RegisterLow8,
};
use stack::Stack;

const STACK_SIZE: u32 = 256;

fn main() {
    // Troolee no_std.
    // let mut binary = include_bytes!("../hello_world.bin").to_vec();
    let mut binary = fs::read("hello_world.bin").unwrap();

    let mut instructions = HashMap::new();

    let mut address = 0;
    let mut ret_hit = false;

    let parse_sib = |byte, is_8bit, offset| -> InstructionSource {
        let sib_base = byte & 0b111;
        let sib_index = (byte >> 3) & 0b111_u8;
        let sib_scale: u8 = (byte >> 6) & 0b11_u8;

        let scale = match sib_scale {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => unreachable!(),
        };

        let index_register = if sib_index == 0b100_u8 {
            None
        } else {
            Some(Register32::try_from(sib_index).unwrap())
        };

        InstructionSource::SIB {
            base: Register32::try_from(sib_base).unwrap(),
            index: index_register,
            scale,
            is_8bit,
            offset,
        }
    };

    while address < binary.len() {
        let has_16bit_prefix = binary[address] == 0x66;

        if has_16bit_prefix {
            address += 1;
        }

        let opcode = binary[address];

        // x86 Manual, Table 2-2., p. 532
        let modrm_byte = binary[address + 1];

        let rm_field = modrm_byte & 0b111;
        let reg_field = (modrm_byte >> 3) & 0b111;
        let mod_field = modrm_byte >> 6;

        let disassembled_instruction;
        let instruction_address = address;

        if (opcode & !0b111) == MOV_REG_IMM32 {
            let destination = Register32::try_from(opcode & 0b111).unwrap();

            let immediate =
                u32::from_le_bytes(binary[address + 1..address + 5].try_into().unwrap());

            disassembled_instruction = InstructionKind::Mov(
                InstructionDestination::Register32(destination),
                InstructionSource::Immediate32(immediate),
            );

            address += 4;

            address += 1;
        } else if opcode == MOV_REG_IMM8 {
            let destination = RegisterLow8::try_from(reg_field).unwrap();

            address += 1;

            disassembled_instruction = InstructionKind::Mov(
                InstructionDestination::RegisterLow8(destination),
                InstructionSource::Immediate8(binary[address]),
            );

            address += 1;
        } else if opcode == MOV_REG_OR_MEM_REG {
            let destination = Register32::try_from(reg_field).unwrap();

            address += 2;

            // disp32
            if mod_field == 0 && rm_field == 0b101 {
                disassembled_instruction = InstructionKind::Mov(
                    InstructionDestination::Register32(destination),
                    InstructionSource::Memory32(u32::from_le_bytes(
                        binary[address..address + 4].try_into().unwrap(),
                    )),
                );

                address += 4;
            }
            // SIB32
            else if mod_field == 0 && rm_field == 0b100 {
                let sib = parse_sib(binary[address], false, 0);

                address += 1;

                disassembled_instruction =
                    InstructionKind::Mov(InstructionDestination::Register32(destination), sib)
            } else if mod_field == 1 && rm_field == 0b100 {
                let sib = parse_sib(binary[address], false, binary[address + 1] as u32);

                address += 2;

                disassembled_instruction =
                    InstructionKind::Mov(InstructionDestination::Register32(destination), sib)
            } else {
                todo!("mod_field = {:#b}, rm_field = {:#b}", mod_field, rm_field)
            }
        } else if opcode == MOV_REG8_MEM8 {
            let destination = RegisterLow8::try_from(reg_field).unwrap();

            address += 2;

            // disp32
            if mod_field == 0 && rm_field == 0b101 {
                disassembled_instruction = InstructionKind::Mov(
                    InstructionDestination::RegisterLow8(destination),
                    InstructionSource::Memory8(u32::from_le_bytes(
                        binary[address..address + 4].try_into().unwrap(),
                    )),
                );

                address += 4;
            }
            // SIB
            else if mod_field == 0 && rm_field == 0b100 {
                let sib = parse_sib(binary[address], true, 0);

                address += 1;

                disassembled_instruction =
                    InstructionKind::Mov(InstructionDestination::RegisterLow8(destination), sib)
            } else {
                todo!("mod_field = {:#b}, rm_field = {:#b}", mod_field, rm_field)
            }
        } else if opcode == MOV_REG_REG {
            // TODO: This can also be used for 16-bit.

            let source = Register32::try_from(reg_field).unwrap();
            let destination = Register32::try_from(rm_field).unwrap();

            if mod_field != 0b11 {
                todo!()
            }

            disassembled_instruction = InstructionKind::Mov(
                InstructionDestination::Register32(destination),
                InstructionSource::Register32(source),
            );

            address += 2;
        } else if opcode == PUSH_IMM {
            // TODO: This opcode can be used with imm16 too.
            address += 1;

            disassembled_instruction = InstructionKind::Push(InstructionSource::Immediate32(
                u32::from_le_bytes(binary[address..address + 4].try_into().unwrap()),
            ));

            address += 4;
        } else if (POP_REG..POP_REG + 8).contains(&opcode) {
            // TODO: This opcode can be used for reg8 and reg16.
            let register = Register32::try_from(opcode - POP_REG).unwrap();

            disassembled_instruction =
                InstructionKind::Pop(InstructionDestination::Register32(register));

            address += 1;
        } else if opcode == ADD_REG_IMM {
            // TODO: This opcode can be used for imm16 + reg16 too.
            let destination = Register32::try_from(rm_field).unwrap();

            address += 2;

            disassembled_instruction = InstructionKind::Add(
                InstructionDestination::Register32(destination),
                InstructionSource::Immediate32(u32::from_le_bytes(
                    binary[address..address + 4].try_into().unwrap(),
                )),
                false,
            );

            address += 4;
        } else if opcode == ADD_REG_IMM8_EXTEND && reg_field == 0 {
            // TODO: The same opcode may be used for reg8 and reg16, how to differentiate?
            let destination = Register32::try_from(rm_field).unwrap();

            address += 2;

            disassembled_instruction = InstructionKind::Add(
                InstructionDestination::Register32(destination),
                InstructionSource::Immediate8(binary[address]),
                true,
            );

            address += 1;
        } else if opcode == XOR_REG_OR_MEM_REG {
            // TODO: How to handle the mem case?
            let destination = Register32::try_from(rm_field).unwrap();
            let other = Register32::try_from(reg_field).unwrap();

            address += 2;

            disassembled_instruction = InstructionKind::Xor(
                InstructionDestination::Register32(destination),
                InstructionSource::Register32(other),
            )
        } else if opcode == JMP_REL8 {
            address += 1;

            let displacement = binary[address];

            address += 1;

            disassembled_instruction =
                InstructionKind::JumpRelative(InstructionSource::Immediate8(displacement));
        } else if opcode == JMP_REL8_IF_EQ {
            address += 1;

            let displacement = binary[address];

            address += 1;

            disassembled_instruction =
                InstructionKind::JumpRelativeIfEqual(InstructionSource::Immediate8(displacement))
        } else if opcode == CMP_REG_IMM8 && reg_field == 7 {
            address += 2;

            disassembled_instruction = InstructionKind::Compare(
                InstructionSource::Register32(Register32::try_from(rm_field).unwrap()),
                InstructionSource::Immediate8(binary[address]),
            );

            address += 1;
        } else if opcode == CMP_REG8_IMM8 && reg_field == 7 {
            address += 2;

            disassembled_instruction = InstructionKind::Compare(
                InstructionSource::RegisterLow8(RegisterLow8::try_from(rm_field).unwrap()),
                InstructionSource::Immediate8(binary[address]),
            );

            address += 1;
        } else if opcode == CALL_REL {
            address += 1;

            let displacement = u32::from_le_bytes(binary[address..address + 4].try_into().unwrap());

            address += 4;

            disassembled_instruction =
                InstructionKind::CallRelative(InstructionSource::Immediate32(displacement));
        } else if u16::from_le_bytes(binary[address..address + 2].try_into().unwrap()) == SYSCALL {
            disassembled_instruction = InstructionKind::Syscall;

            address += 2;
        } else if opcode == RET {
            disassembled_instruction = InstructionKind::Ret;

            address += 1;
        } else if u16::from_le_bytes(binary[address..address + 2].try_into().unwrap()) == UD0 {
            ret_hit = true;

            address += 2;

            break;
        } else {
            panic!(
                "unknown opcode `{:#x}` with reg_field = `{:#b}`",
                opcode, reg_field
            );
        }

        instructions.insert(
            instruction_address,
            Instruction {
                kind: disassembled_instruction,
                size: (address - instruction_address) as u32,
            },
        );
    }

    if !ret_hit {
        panic!("end of program (`ret`) hasn't been found");
    }

    let memory_base = address as u32;

    let mut sorted_keys = instructions.keys().collect::<Vec<_>>();

    sorted_keys.sort();

    for key in sorted_keys {
        println!("[{:#x}]\t {:?}", key, instructions[key]);
    }

    let mut stack = Stack::new(STACK_SIZE);
    let mut cpu = CPU::new(&mut stack);

    cpu.execute(
        &instructions,
        memory_base,
        binary.split_off(memory_base as usize),
    );
}
