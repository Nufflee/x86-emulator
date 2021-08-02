use std::cmp::max;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::mem::size_of;
use std::ops::{BitAnd, BitOr, Not, Shl, Shr};
use std::slice::Iter;

use crate::instruction::{
    Instruction, InstructionDestination, InstructionKind, InstructionSource, Register32,
};
use crate::stack::Stack;
use num_enum::TryFromPrimitive;

// https://en.wikipedia.org/wiki/FLAGS_register#FLAGS
#[derive(Clone, Copy)]
enum Flag {
    Carry = 1 << 0,
    Parity = 1 << 2,
    AuxiliaryCarry = 1 << 4,
    Zero = 1 << 6,
    Negative = 1 << 7,
    InterruptEnable = 1 << 9,
    Overflow = 1 << 11,
}

impl Flag {
    fn get_short_name(&self) -> &str {
        match self {
            Flag::Carry => "CF",
            Flag::Parity => "PF",
            Flag::AuxiliaryCarry => "AF",
            Flag::Zero => "ZF",
            Flag::Negative => "SF",
            Flag::InterruptEnable => "IF",
            Flag::Overflow => "OF",
        }
    }

    // TODO: Do this using a macro or something instead
    fn iter() -> Iter<'static, Self> {
        use Flag::*;

        const VALUES: [Flag; 6] = [Carry, Parity, AuxiliaryCarry, Zero, Negative, Overflow];

        VALUES.iter()
    }
}

#[derive(TryFromPrimitive)]
#[repr(u32)]
enum Syscall {
    Write = 1,
    Exit = 60,
}

#[allow(clippy::upper_case_acronyms)]
pub struct CPU<'a> {
    registers: [u32; 8],
    flag_register: u32,
    memory: Vec<u8>,
    memory_base: u32,
    stack: &'a mut Stack,
    stack_base: u32,
}

impl<'a> CPU<'a> {
    pub fn new(stack: &'a mut Stack) -> Self {
        let mut instance = Self {
            registers: [0; 8],
            flag_register: 0,
            memory_base: 0,
            memory: vec![],
            stack,
            stack_base: 0,
        };

        instance.initialize();

        instance
    }

    fn initialize(&mut self) {
        // Set default flags

        self.set_flag(Flag::InterruptEnable, true);
        // Reserved, always 1
        self.set_flag_mask(1 << 1, true);
    }

    fn get_register(&self, register: Register32) -> u32 {
        self.registers[register as usize]
    }

    fn set_register(&mut self, register: Register32, value: u32) {
        self.registers[register as usize] = value
    }

    fn modify_register(&mut self, register: Register32, func: impl Fn(u32) -> u32) {
        self.set_register(register, func(self.get_register(register)))
    }

    fn get_flag(&self, flag: Flag) -> bool {
        (self.flag_register & flag as u32) > 0
    }

    fn set_flag_mask(&mut self, mask: u32, value: bool) {
        // TODO: Is there a way to do this branchlessly?
        if value {
            self.flag_register |= mask as u32;
        } else {
            self.flag_register &= !(mask as u32);
        }
    }

    fn set_flag(&mut self, flag: Flag, value: bool) {
        self.set_flag_mask(flag as u32, value);
    }

    fn set_simple_arithmetic_flags(&mut self, result: u32) {
        self.set_flag(Flag::Negative, sign_of(result));
        self.set_flag(Flag::Parity, result.count_ones() % 2 == 0);
        self.set_flag(Flag::Zero, result == 0);
    }

    pub(crate) fn set_additive_flags(&mut self, lhs: u32, rhs: u32, result: u32) {
        // Carry flags signifies a regular, unsigned overflow.
        // TODO: Is it correct to just compare against one of the operands?
        self.set_flag(Flag::Carry, result < lhs);

        // TODO: Test this against CPU
        // Overflow flag signifies a signed overflow, where the overflow "clobbers" the sign bit.
        // We know that adding two numbers with the same sign cannot result in a number of a
        // different sign, so when that happens, we know we have a signed overflow.
        self.set_flag(
            Flag::Overflow,
            !(sign_of(lhs) ^ sign_of(rhs)) && (sign_of(lhs) ^ sign_of(result)),
        );

        self.set_flag(Flag::AuxiliaryCarry, (lhs & 0xF) + (rhs & 0xF) > 0xF);

        self.set_simple_arithmetic_flags(result);
    }

    pub(crate) fn set_subtractive_flags(&mut self, lhs: u32, rhs: u32, result: u32) {
        // Carry flags signifies a regular, unsigned overflow.
        // TODO: Is it correct to just compare against one of the operands?
        self.set_flag(Flag::Carry, result > lhs);

        // Overflow flag signifies a signed overflow, where the overflow "clobbers" the sign bit.
        // Subtracting two numbers of different signs must result in a number with the same sign as
        // the first operand (lhs).
        // If that is not the case, a signed overflow is indicated.
        self.set_flag(
            Flag::Overflow,
            (sign_of(lhs) ^ sign_of(rhs)) && (sign_of(lhs) ^ sign_of(result)),
        );

        self.set_flag(
            Flag::AuxiliaryCarry,
            (((lhs & 0xF) as i8) - ((rhs & 0xF) as i8)) < 0,
        );

        self.set_simple_arithmetic_flags(result);
    }

    fn get_source_value(
        &self,
        source: InstructionSource,
        sign_extend: bool,
        is_destination_8bit: bool,
    ) -> u32 {
        match source {
            InstructionSource::RegisterLow8(register) => {
                self.get_register(Register32::from(register))
            }
            InstructionSource::Register32(register) => self.get_register(register),
            InstructionSource::Immediate8(value) => {
                if sign_extend {
                    sign_extend32(value)
                } else {
                    value as u32
                }
            }
            InstructionSource::Immediate32(value) => value,
            InstructionSource::Memory8(address) => self.get_memory_u8(address) as u32,
            InstructionSource::Memory32(address) => self.get_memory_u32(address),
            InstructionSource::SIB { .. } => {
                let address = self.get_effective_address(source);

                if is_destination_8bit {
                    self.get_memory_u8(address) as u32
                } else {
                    self.get_memory_u32(address) as u32
                }
            }
            InstructionSource::DerefRegister32(register) => {
                let address = self.get_register(register);

                if is_destination_8bit {
                    self.get_memory_u8(address) as u32
                } else {
                    self.get_memory_u32(address)
                }
            }
        }
    }

    fn get_effective_address(&self, source: InstructionSource) -> u32 {
        match source {
            InstructionSource::SIB {
                base,
                index,
                scale,
                displacement: offset,
            } => {
                let index_value = if let Some(index_register) = index {
                    self.get_register(index_register)
                } else {
                    0
                };

                self.get_register(base) + index_value * scale as u32 + offset
            }
            _ => todo!(),
        }
    }

    // TODO: Maybe this could use const generics?
    fn get_memory_u32(&self, address: u32) -> u32 {
        u32::from_le_bytes(self.get_memory_bytes_at(address, 4).try_into().unwrap())
    }

    // TODO: Maybe this could use const generics?
    fn get_memory_u8(&self, address: u32) -> u8 {
        self.get_memory_bytes_at(address, 1)[0]
    }

    fn get_memory_bytes_at(&self, address: u32, count: u32) -> &[u8] {
        if address < self.memory_base {
            panic!("tried to read non-readable memory at {:#x}", address);
        }

        if address >= self.stack_base && address <= self.stack_base + self.stack.get_size() {
            let stack_start = address - self.stack_base - self.stack.get_size();
            let stack_end = address + count - self.stack_base - self.stack.get_size();

            return &self.stack.get_underlaying_vec()[stack_start as usize..stack_end as usize];
        }

        let memory_start = address - self.memory_base;
        let memory_end = memory_start + count;

        if memory_end > self.memory.len() as u32 {
            // If memory_start is within
            let faulting_address = max(memory_start, self.memory.len() as u32);

            panic!(
                "tried to read unmapped memory at {:#x} (starting at {:#x})",
                self.memory_base + faulting_address as u32,
                address
            );
        }

        if address % 4 != 0 {
            println!("lmao unaligned memory read at {:#x}", address);
        }

        &self.memory[memory_start as usize..memory_end as usize]
    }

    pub fn execute(
        &mut self,
        instructions: &HashMap<usize, Instruction>,
        memory_base: u32,
        memory: Vec<u8>,
    ) {
        const DUMP_REGISTERS: bool = false;

        self.stack_base = memory_base + memory.len() as u32;
        self.memory = memory;
        self.memory_base = memory_base;

        self.set_register(Register32::ESP, self.stack_base + self.stack.get_size());

        let mut pc: u32 = 0;

        loop {
            println!("-----------------------------------------------");

            let instruction = &instructions[&(pc as usize)];

            println!("Executing: {:?}, pc = {:#x}", instruction, pc);

            match instruction.kind {
                InstructionKind::Mov(destination, source) => match destination {
                    // TODO: This should probably only set the lowest 8 bits and leave the top 24 as is.
                    InstructionDestination::RegisterLow8(register) => self.set_register(
                        Register32::from(register),
                        self.get_source_value(source, false, true),
                    ),
                    InstructionDestination::Register32(register) => {
                        self.set_register(register, self.get_source_value(source, false, false))
                    }
                },
                InstructionKind::LoadEffectiveAddr(destination, source) => match destination {
                    InstructionDestination::Register32(register) => {
                        self.set_register(register, self.get_effective_address(source))
                    }
                    _ => todo!(),
                },
                InstructionKind::Add(destination, source, should_sign_extend) => {
                    match destination {
                        InstructionDestination::Register32(register) => {
                            let register_value = self.get_register(register);
                            let other_value =
                                self.get_source_value(source, should_sign_extend, false);

                            let result = register_value.wrapping_add(other_value);

                            self.set_additive_flags(register_value, other_value, result);

                            self.set_register(register, result);

                            self.dump_flags();
                        }
                        InstructionDestination::RegisterLow8(_) => todo!(),
                    }
                }
                InstructionKind::Xor(destination, source) => {
                    self.set_flag(Flag::Overflow, false);
                    self.set_flag(Flag::Carry, false);

                    match destination {
                        InstructionDestination::Register32(register) => {
                            let other_value = self.get_source_value(source, false, false);
                            let result = self.get_register(register) ^ other_value;

                            self.set_register(register, result);

                            self.set_simple_arithmetic_flags(result);

                            self.dump_flags()
                        }
                        _ => todo!(),
                    }
                }
                InstructionKind::Push(source) => {
                    if matches!(source, InstructionSource::Immediate8(_)) {
                        todo!();
                    }

                    self.stack
                        .push32(self.get_source_value(source, false, false));

                    let size = match source {
                        InstructionSource::Immediate8(_) => 1,
                        InstructionSource::Immediate32(_) => 4,
                        _ => todo!(),
                    };

                    self.modify_register(Register32::ESP, |value| value - size);
                }
                InstructionKind::Pop(destination) => match destination {
                    InstructionDestination::Register32(register) => {
                        self.stack.dump();

                        let value = self.stack.pop32();

                        self.set_register(register, value);
                    }
                    _ => todo!(),
                },
                InstructionKind::JumpRelative(displacement) => {
                    pc = pc.wrapping_add(self.get_source_value(displacement, true, false));
                }
                InstructionKind::JumpRelativeIfEqual(displacement) => {
                    self.dump_flags();

                    if self.get_flag(Flag::Zero) {
                        pc = pc.wrapping_add(self.get_source_value(displacement, true, false));
                    }
                }
                InstructionKind::CallRelative(displacement) => {
                    // TODO: Push pc to the stack
                    self.stack.push32((pc + instruction.size) as u32);

                    // Displacement is relative to *next* instruction
                    pc = pc.wrapping_add(self.get_source_value(displacement, true, false));
                }
                InstructionKind::Compare(source1, source2) => {
                    let lhs = self.get_source_value(source1, false, false);
                    let rhs = self.get_source_value(source2, false, false);

                    let result = lhs.wrapping_sub(rhs);

                    self.set_subtractive_flags(lhs, rhs, result);

                    self.dump_flags();
                }
                InstructionKind::Syscall => {
                    let syscall_number = self.get_register(Register32::EAX);

                    let syscall = match Syscall::try_from(syscall_number) {
                        Ok(syscall) => syscall,
                        Err(_) => todo!("unsupported syscall number `{}`", syscall_number),
                    };

                    match syscall {
                        Syscall::Write => {
                            let fd = self.get_register(Register32::EDI);

                            const STDOUT: u32 = 1;

                            if fd == STDOUT {
                                let base_address = self.get_register(Register32::ESI);
                                let length = self.get_register(Register32::EDX);

                                let buffer = self.get_memory_bytes_at(base_address, length);

                                println!(
                                    "SYS_WRITE says: {:?}",
                                    String::from_utf8(buffer.to_vec()).unwrap()
                                );
                            } else {
                                todo!("unsupported file descriptor `{}` in SYS_WRITE", fd);
                            }
                        }
                        Syscall::Exit => {
                            let exit_code = self.get_register(Register32::EDI) as i32;

                            println!("Process exited with code {}", exit_code);
                            break;
                        }
                    }
                }
                InstructionKind::Ret => {
                    pc = self.stack.pop32();
                    continue;
                }
            }

            if DUMP_REGISTERS {
                for i in 0..self.registers.len() {
                    let register = Register32::try_from(i as u8).unwrap();

                    println!("{:?} = {}", register, self.get_register(register));
                }
            }

            pc += instruction.size;
        }
    }

    fn dump_flags(&self) {
        // TODO: Use a stack allocated vector here, like smallvec (or is that just a microoptimization?)
        let mut flags = Vec::with_capacity(Flag::iter().count());

        for flag in Flag::iter() {
            flags.push(format!(
                "{} = {}",
                flag.get_short_name(),
                self.get_flag(*flag)
            ));
        }

        println!("{}", flags.join(", "))
    }
}

// Returns true if negative
fn sign_of<T>(value: T) -> bool
where
    T: Shr<usize, Output = T> + Default + PartialEq,
{
    let bits = core::mem::size_of::<T>() * 8;

    // T::default() is 0
    (value >> (bits - 1)) != T::default()
}

fn sign_extend<TFrom, TTo>(value: TFrom) -> TTo
where
    TFrom: Into<TTo> + Shr<usize, Output = TFrom> + Default + PartialEq + Copy,
    TTo: Shr<usize, Output = TTo>
        + From<TFrom>
        + Default
        + Not<Output = TTo>
        + Shl<usize, Output = TTo>
        + TryFrom<i8>
        + BitAnd<Output = TTo>
        + BitOr<Output = TTo>,
    <TTo as TryFrom<i8>>::Error: std::fmt::Debug,
{
    let from_bits = size_of::<TFrom>() * 8;

    /* This one is angy because i* cannot be try_into()'d into u*, but branchless approach would be ideal.
    let msb_thing: TTo = (0 - sign_of(value) as i8).try_into().unwrap();
    let mask: TTo = (!TTo::default()) << (from_bits - 1);

    (msb_thing & mask) | (value.into())
    */

    let mask: TTo = (!TTo::default()) << (from_bits - 1);

    if sign_of(value) {
        return mask | value.into();
    }

    value.into()
}

fn sign_extend32<TFrom>(value: TFrom) -> u32
where
    TFrom: Shl<usize, Output = TFrom>
        + Copy
        + Into<u32>
        + Shr<usize, Output = TFrom>
        + Default
        + PartialEq,
    u32: From<TFrom>,
{
    let from_bits = size_of::<TFrom>() * 8;

    ((0 - sign_of(value) as i8) as u32 & (!0 << (from_bits - 1))) | (value.into())
}

#[cfg(test)]
mod tests {
    use crate::cpu::{sign_extend, sign_extend32, sign_of};
    use crate::{cpu::CPU, stack::Stack};

    const STACK_SIZE: u32 = 256;

    #[test]
    fn test_sign_of() {
        assert_eq!(sign_of(1), false);
        assert_eq!(sign_of(-1), true);

        assert_eq!(sign_of(1_i64), false);
        assert_eq!(sign_of(-1_i64), true);
        assert_eq!(sign_of(1_u64), false);

        assert_eq!(sign_of(1_i128), false);
        assert_eq!(sign_of(-1_i128), true);
        assert_eq!(sign_of(1_u128), false);

        assert_eq!(sign_of(-1_i8), true);
        assert_eq!(sign_of(1_i8), false);

        assert_eq!(sign_of(1 << 31), true);
        assert_eq!(sign_of((1 << 31) as u32), true);
        assert_eq!(sign_of(1 << 30), false);

        assert_eq!(sign_of(1_u128 << 127), true);
        assert_eq!(sign_of(1_u128 << 126), false);
    }

    #[test]
    fn test_sign_extend32() {
        assert_eq!(sign_extend32::<u8>(255), -1_i32 as u32);
        assert_eq!(sign_extend32::<u16>(6969), 6969_u32);

        assert_eq!(sign_extend32::<u16>(1 << 15), !0 << 15);
        assert_eq!(sign_extend32::<u8>(1 << 7), !0 << 7);
    }

    #[test]
    fn test_sign_extend() {
        assert_eq!(sign_extend::<u8, i32>(255), -1_i32);
        assert_eq!(sign_extend::<u16, i32>(6969), 6969_i32);

        assert_eq!(sign_extend::<u16, u32>(1 << 15), !0 << 15);
        assert_eq!(sign_extend::<u8, u32>(1 << 7), !0 << 7);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_feature))]
    fn test_additive_flags() {
        let mut stack = Stack::new(STACK_SIZE);
        let mut cpu = CPU::new(&mut stack);
        cpu.initialize();

        unsafe {
            for x in 0..=255_u8 {
                for y in 0..=255_u8 {
                    let mut cpu_result: u8;
                    let mut cpu_flags: u16;

                    asm!(
                      "mov {0}, {1}",
                      "add {0}, {2}",
                      "pushf",
                      "mov {3:x}, [rsp]",
                      "add rsp, 8", // We need to restore the stack pointer
                      out(reg_byte) cpu_result, in(reg_byte) x, in(reg_byte) y, out(reg) cpu_flags
                    );

                    let emulator_result = x.wrapping_add(y);

                    cpu.set_additive_flags(sign_extend(x), sign_extend(y), sign_extend(cpu_result));

                    let emulator_flags = cpu.flag_register;

                    assert_eq!(cpu_result, emulator_result);
                    assert_eq!(cpu_flags as u32 & 0x7FF, emulator_flags & 0x7FF);
                }
            }
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_subtractive_flags() {
        let mut stack = Stack::new(STACK_SIZE);
        let mut cpu = CPU::new(&mut stack);
        cpu.initialize();

        unsafe {
            for x in 0..=255_u8 {
                for y in 0..=255_u8 {
                    let mut cpu_result: u8;
                    let mut cpu_flags: u16;

                    asm!(
                      "mov {0}, {1}",
                      "sub {0}, {2}",
                      "pushf",
                      "mov {3:x}, [rsp]",
                      "add rsp, 8", // We need to restore the stack pointer
                      out(reg_byte) cpu_result, in(reg_byte) x, in(reg_byte) y, out(reg) cpu_flags
                    );

                    let emulator_result = x.wrapping_sub(y);

                    cpu.set_subtractive_flags(
                        sign_extend(x),
                        sign_extend(y),
                        sign_extend(cpu_result),
                    );

                    let emulator_flags = cpu.flag_register;

                    assert_eq!(cpu_result, emulator_result);
                    assert_eq!(cpu_flags as u32 & 0x7FF, emulator_flags & 0x7FF);
                }
            }
        }
    }
}
