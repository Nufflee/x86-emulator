use core::convert::TryFrom;

use crate::byte_reader::ByteReader;
use crate::instruction::{
    opcode::*, Instruction, InstructionDestination, InstructionKind, InstructionSource, Register32,
    RegisterLow8,
};

pub struct InstructionDecoder<'a> {
    reader: ByteReader<'a>,
}

struct ModRM {
    rm_field: u8,
    reg_field: u8,
    mod_field: u8,
}

impl<'a> InstructionDecoder<'a> {
    pub fn new(binary: &'a [u8]) -> Self {
        Self {
            reader: ByteReader::new(binary),
        }
    }

    pub fn decode_next(&mut self) -> Instruction {
        let has_16bit_prefix = self.reader.match_value(0x66u8);

        let instruction_address = self.reader.index();
        let opcode = self.reader.next::<u8>();

        let disassembled_instruction;

        if (opcode & !0b111) == MOV_REG_IMM {
            // TODO: This opcode is also used for r16/imm16
            // 0xB8+ rd id (OI)
            let destination = Register32::try_from(opcode & 0b111).unwrap();
            let immediate = self.reader.next();

            disassembled_instruction = InstructionKind::Mov(
                InstructionDestination::Register32(destination),
                InstructionSource::Immediate32(immediate),
            );
        } else if (opcode & !0b111) == MOV_REG_IMM8 {
            // 0xB0+ rb ib (OI)
            let destination = RegisterLow8::try_from(opcode & 0b111).unwrap();
            let immediate = self.reader.next();

            disassembled_instruction = InstructionKind::Mov(
                InstructionDestination::RegisterLow8(destination),
                InstructionSource::Immediate8(immediate),
            );
        } else if opcode == MOV_REG_OR_MEM_REG {
            // TODO: Also used for 8- and 64-bit
            // 0x8B /r (RM)
            let modrm = parse_modrm(self.reader.next());
            let destination = Register32::try_from(modrm.reg_field).unwrap();

            // disp32
            if modrm.mod_field == 0 && modrm.rm_field == 0b101 {
                let source = self.reader.next();

                disassembled_instruction = InstructionKind::Mov(
                    InstructionDestination::Register32(destination),
                    InstructionSource::Memory32(source),
                );
            }
            // SIB
            else if modrm.mod_field == 0 && modrm.rm_field == 0b100 {
                let sib = parse_sib(self.reader.next(), 0);

                disassembled_instruction =
                    InstructionKind::Mov(InstructionDestination::Register32(destination), sib);
            // SIB + disp8
            } else if modrm.mod_field == 1 && modrm.rm_field == 0b100 {
                let sib = parse_sib(self.reader.next(), self.reader.next::<u8>() as u32);

                disassembled_instruction =
                    InstructionKind::Mov(InstructionDestination::Register32(destination), sib)
            } else {
                todo!(
                    "mod_field = {:#b}, rm_field = {:#b}",
                    modrm.mod_field,
                    modrm.rm_field
                )
            }
        } else if opcode == MOV_REG8_MEM8 {
            // TODO: Can have REX prefix
            // 0x8A /r (RM)
            let modrm = parse_modrm(self.reader.next());
            let destination = RegisterLow8::try_from(modrm.reg_field).unwrap();

            // disp32
            if modrm.mod_field == 0 && modrm.rm_field == 0b101 {
                let source = self.reader.next();

                disassembled_instruction = InstructionKind::Mov(
                    InstructionDestination::RegisterLow8(destination),
                    InstructionSource::Memory8(source),
                );
            }
            // SIB
            else if modrm.mod_field == 0 && modrm.rm_field == 0b100 {
                let sib = parse_sib(self.reader.next(), 0);

                disassembled_instruction =
                    InstructionKind::Mov(InstructionDestination::RegisterLow8(destination), sib);
            // Indirect reg32
            } else if modrm.mod_field == 0 {
                // We've exhausted the SIB and disp32 cases so we know this is an indirect register operand
                let source = Register32::try_from(modrm.rm_field).unwrap();

                disassembled_instruction = InstructionKind::Mov(
                    InstructionDestination::RegisterLow8(destination),
                    InstructionSource::IndirectRegister32(source),
                );
            } else {
                todo!(
                    "mod_field = {:#b}, rm_field = {:#b}",
                    modrm.mod_field,
                    modrm.rm_field
                )
            }
        } else if opcode == MOV_REG_REG {
            // TODO: This can also be used for 16- and 64-bit.
            // 0x89 /r (MR)
            let modrm = parse_modrm(self.reader.next());
            let source = Register32::try_from(modrm.reg_field).unwrap();
            let destination = Register32::try_from(modrm.rm_field).unwrap();

            if modrm.mod_field != 0b11 {
                todo!()
            }

            disassembled_instruction = InstructionKind::Mov(
                InstructionDestination::Register32(destination),
                InstructionSource::Register32(source),
            );
        } else if opcode == LEA_REG_MEM {
            // TODO: reg16 and reg64
            // 0x8D /r (RM)
            let modrm = parse_modrm(self.reader.next());
            let destination = Register32::try_from(modrm.reg_field).unwrap();

            // SIB
            if modrm.mod_field == 0b00 && modrm.rm_field == 0b100 {
                let sib = parse_sib(self.reader.next(), 0);

                disassembled_instruction = InstructionKind::LoadEffectiveAddr(
                    InstructionDestination::Register32(destination),
                    sib,
                );
            } else {
                todo!(
                    "mod_field = {:#b}, rm_field = {:#b}",
                    modrm.mod_field,
                    modrm.rm_field
                )
            }
        } else if opcode == PUSH_IMM {
            // TODO: This opcode can be used with imm8 and imm16 too.
            // 0x68 id (I)
            let immediate = self.reader.next();

            disassembled_instruction =
                InstructionKind::Push(InstructionSource::Immediate32(immediate));
        } else if (opcode & !0b111) == POP_REG {
            // TODO: This opcode can be used for reg16 and reg64.
            // 0x58 +rd (O)
            let register = Register32::try_from(opcode & 0b111).unwrap();

            disassembled_instruction =
                InstructionKind::Pop(InstructionDestination::Register32(register));
        } else if opcode == ADD_REG_IMM {
            let modrm = parse_modrm(self.reader.next());

            if modrm.reg_field == 0 {
                // 0x81 /0 id (MI)
                // TODO: This opcode can be used for 16- and 64-bit too.
                let destination = Register32::try_from(modrm.rm_field).unwrap();
                let immediate = self.reader.next();

                disassembled_instruction = InstructionKind::Add(
                    InstructionDestination::Register32(destination),
                    InstructionSource::Immediate32(immediate),
                    false,
                );
            } else {
                todo!("reg_field != 0 (reg_field = {:#b})", modrm.reg_field);
            }
        } else if opcode == ADD_REG_IMM8_EXTEND {
            let modrm = parse_modrm(self.reader.next());

            if modrm.reg_field == 0 {
                // 0x83 /0 ib (MI)
                // TODO: The same opcode may be used for reg16 and reg64, how to differentiate?
                let destination = Register32::try_from(modrm.rm_field).unwrap();
                let immediate = self.reader.next();

                disassembled_instruction = InstructionKind::Add(
                    InstructionDestination::Register32(destination),
                    InstructionSource::Immediate8(immediate),
                    true,
                );
            } else {
                todo!("reg_field != 0 (reg_field = {:#b})", modrm.reg_field);
            }
        } else if opcode == XOR_REG_OR_MEM_REG {
            // 0x31 /r (MR)
            // TODO: How to handle the mem case?
            // TODO: This opcode can also be used for 16- and 64-bit.
            let modrm = parse_modrm(self.reader.next());

            let destination = Register32::try_from(modrm.rm_field).unwrap();
            let other = Register32::try_from(modrm.reg_field).unwrap();

            disassembled_instruction = InstructionKind::Xor(
                InstructionDestination::Register32(destination),
                InstructionSource::Register32(other),
            )
        } else if opcode == JMP_REL8 {
            let displacement = self.reader.next();

            disassembled_instruction =
                InstructionKind::JumpRelative(InstructionSource::Immediate8(displacement));
        } else if opcode == JMP_REL8_IF_EQ {
            let displacement = self.reader.next();

            disassembled_instruction =
                InstructionKind::JumpRelativeIfEqual(InstructionSource::Immediate8(displacement));
        } else if opcode == CMP_REG_IMM8 {
            let modrm = parse_modrm(self.reader.next());

            if modrm.reg_field == 7 {
                // TODO: This opcode can also be used for 16- and 64-bit.
                // 0x83 /7 ib (MI)
                let immediate = self.reader.next();

                disassembled_instruction = InstructionKind::Compare(
                    InstructionSource::Register32(Register32::try_from(modrm.rm_field).unwrap()),
                    InstructionSource::Immediate8(immediate),
                );
            } else {
                todo!("reg_field != 7 (reg_field = {:#b})", modrm.reg_field);
            }
        } else if opcode == CMP_REG8_IMM8 {
            let modrm = parse_modrm(self.reader.next());

            if modrm.reg_field == 7 {
                // 0x80 /7 ib (MI)
                let immediate = self.reader.next();

                disassembled_instruction = InstructionKind::Compare(
                    InstructionSource::RegisterLow8(
                        RegisterLow8::try_from(modrm.rm_field).unwrap(),
                    ),
                    InstructionSource::Immediate8(immediate),
                );
            } else {
                todo!("reg_field != 7 (reg_field = {:#b})", modrm.reg_field);
            }
        } else if opcode == CALL_REL {
            // TODO: This opcode is also used with rel16
            // 0xE8 cd (D)
            let displacement = self.reader.next();

            disassembled_instruction =
                InstructionKind::CallRelative(InstructionSource::Immediate32(displacement));
        } else if opcode == 0x0F {
            match self.reader.next() {
                SYSCALL => disassembled_instruction = InstructionKind::Syscall,
                UD0 => disassembled_instruction = InstructionKind::UD0,
                opcode => panic!("unknown opcode `0x0f{:x}`", opcode),
            }
        } else if opcode == RET {
            disassembled_instruction = InstructionKind::Ret;
        } else {
            let modrm = parse_modrm(self.reader.peek());

            panic!(
                "unknown opcode `{:#x}` with reg_field = `{:#b}` @ byte {:#x}",
                opcode,
                modrm.reg_field,
                self.reader.index()
            );
        }

        Instruction {
            kind: disassembled_instruction,
            size: (self.reader.index() - instruction_address) as u32,
        }
    }

    pub fn address(&self) -> usize {
        self.reader.index()
    }
}

fn parse_modrm(modrm_byte: u8) -> ModRM {
    // Intel SDM, Table 2-2., p. 532
    let rm_field = modrm_byte & 0b111;
    let reg_field = (modrm_byte >> 3) & 0b111;
    let mod_field = modrm_byte >> 6;

    ModRM {
        rm_field,
        reg_field,
        mod_field,
    }
}

fn parse_sib(byte: u8, displacement: u32) -> InstructionSource {
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
        displacement,
    }
}
