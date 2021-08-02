use std::convert::TryFrom;

use num_enum::TryFromPrimitive;

pub mod opcode {
    pub const MOV_REG8_MEM8: u8 = 0x8A;
    pub const MOV_REG_OR_MEM_REG: u8 = 0x8B;
    pub const MOV_REG_IMM8: u8 = 0xB0;
    pub const MOV_REG_IMM32: u8 = 0xB8;
    pub const MOV_REG_REG: u8 = 0x89;

    pub const LEA_REG_MEM: u8 = 0x8D;

    pub const PUSH_IMM: u8 = 0x68;
    pub const POP_REG: u8 = 0x58;

    pub const ADD_REG_IMM: u8 = 0x81;
    pub const ADD_REG_IMM8_EXTEND: u8 = 0x83;

    pub const XOR_REG_OR_MEM_REG: u8 = 0x31;

    pub const CMP_REG8_IMM8: u8 = 0x80;
    pub const CMP_REG_IMM8: u8 = 0x83;

    pub const JMP_REL8: u8 = 0xEB;
    pub const JMP_REL8_IF_EQ: u8 = 0x74;

    pub const CALL_REL: u8 = 0xE8;
    pub const RET: u8 = 0xC3;

    // TODO: Multi-byte opcodes are always prefixed with 0x0F, so this doesn't have to be here
    pub const SYSCALL: u16 = 0x050F;
    pub const UD0: u16 = 0xFF0F;
}

#[derive(Debug)]
pub struct Instruction {
    pub size: u32,
    pub kind: InstructionKind,
}

#[derive(Debug)]
pub enum InstructionKind {
    Mov(InstructionDestination, InstructionSource),
    LoadEffectiveAddr(InstructionDestination, InstructionSource),
    Push(InstructionSource),
    Pop(InstructionDestination),
    Add(InstructionDestination, InstructionSource, bool),
    Xor(InstructionDestination, InstructionSource),
    JumpRelative(InstructionSource),
    JumpRelativeIfEqual(InstructionSource),
    Compare(InstructionSource, InstructionSource),
    CallRelative(InstructionSource),
    Syscall,
    Ret,
}

// TODO: Custom formatter that formats Memory operands as hex
#[derive(Debug, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum InstructionSource {
    RegisterLow8(RegisterLow8),
    Register32(Register32),
    IndirectRegister32(Register32),
    Immediate8(u8),
    Immediate32(u32),
    Memory8(u32),
    Memory32(u32),
    SIB {
        base: Register32,
        index: Option<Register32>,
        scale: u8,
        displacement: u32,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum InstructionDestination {
    RegisterLow8(RegisterLow8),
    Register32(Register32),
}

// TODO: Conversion between different parts of the registers is janky
#[derive(TryFromPrimitive, Debug, Clone, Copy)]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
pub enum Register32 {
    EAX = 0,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
}

#[derive(TryFromPrimitive, Debug, Clone, Copy)]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
pub enum RegisterLow8 {
    AL = 0,
    CL,
    DL,
    BL,
}

impl From<RegisterLow8> for Register32 {
    fn from(register: RegisterLow8) -> Self {
        Register32::try_from(register as u8).unwrap()
    }
}
