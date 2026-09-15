//! Frida-shaped AArch64 code writer (`Arm64Writer`).

use crate::decoder::Cond;
use crate::encode::{
    encode_abs_branch, encode_add_imm, encode_adr, encode_b_cond, encode_cbz, encode_tbz,
    try_encode_b,
};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    #[error("{0}")]
    Msg(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexMode {
    PostAdjust,
    SignedOffset,
    PreAdjust,
}

impl IndexMode {
    pub fn parse(s: &str) -> Result<Self, WriterError> {
        match s {
            "post-adjust" | "post" => Ok(Self::PostAdjust),
            "signed-offset" | "offset" => Ok(Self::SignedOffset),
            "pre-adjust" | "pre" => Ok(Self::PreAdjust),
            other => Err(WriterError::Msg(format!("bad IndexMode: {other}"))),
        }
    }

    fn encoding(self) -> u32 {
        match self {
            Self::PostAdjust => 0b01,
            Self::SignedOffset => 0b10,
            Self::PreAdjust => 0b11,
        }
    }
}

/// GP / vector register id 0..31 (31 = SP/ZR depending on context).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reg {
    pub n: u8,
    pub is64: bool,
    /// `true` for Qn (128-bit SIMD/FP).
    pub is_vec: bool,
}

impl Reg {
    pub fn x(n: u8) -> Self {
        Self {
            n,
            is64: true,
            is_vec: false,
        }
    }
    pub fn w(n: u8) -> Self {
        Self {
            n,
            is64: false,
            is_vec: false,
        }
    }
    pub fn q(n: u8) -> Self {
        Self {
            n,
            is64: true,
            is_vec: true,
        }
    }

    pub fn parse(s: &str) -> Result<Self, WriterError> {
        let s = s.trim().to_ascii_lowercase();
        let (is64, n, is_vec) = match s.as_str() {
            "sp" | "wsp" => (s != "wsp", 31, false),
            "lr" | "x30" => (true, 30, false),
            "fp" | "x29" => (true, 29, false),
            "xzr" | "wzr" => (s.starts_with('x'), 31, false),
            "ip0" | "x16" => (true, 16, false),
            "ip1" | "x17" => (true, 17, false),
            "nzcv" => {
                return Err(WriterError::Msg(
                    "nzcv is not a GPR; use putMovNzcvReg / putMovRegNzcv".into(),
                ))
            }
            _ => {
                if let Some(rest) = s.strip_prefix('q') {
                    let n: u8 = rest
                        .parse()
                        .map_err(|_| WriterError::Msg(format!("bad reg: {s}")))?;
                    if n > 31 {
                        return Err(WriterError::Msg(format!("bad q reg: {s}")));
                    }
                    (true, n, true)
                } else if let Some(rest) = s.strip_prefix('x') {
                    let n: u8 = rest
                        .parse()
                        .map_err(|_| WriterError::Msg(format!("bad reg: {s}")))?;
                    if n > 30 {
                        return Err(WriterError::Msg(format!("bad x reg: {s}")));
                    }
                    (true, n, false)
                } else if let Some(rest) = s.strip_prefix('w') {
                    let n: u8 = rest
                        .parse()
                        .map_err(|_| WriterError::Msg(format!("bad reg: {s}")))?;
                    if n > 30 {
                        return Err(WriterError::Msg(format!("bad w reg: {s}")));
                    }
                    (false, n, false)
                } else {
                    return Err(WriterError::Msg(format!("bad reg: {s}")));
                }
            }
        };
        Ok(Self { n, is64, is_vec })
    }

    fn width_bytes(self) -> usize {
        if self.is_vec {
            16
        } else if self.is64 {
            8
        } else {
            4
        }
    }
}

pub fn parse_cond(s: &str) -> Result<Cond, WriterError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "eq" => Ok(Cond::Eq),
        "ne" => Ok(Cond::Ne),
        "hs" | "cs" => Ok(Cond::Cs),
        "lo" | "cc" => Ok(Cond::Cc),
        "mi" => Ok(Cond::Mi),
        "pl" => Ok(Cond::Pl),
        "vs" => Ok(Cond::Vs),
        "vc" => Ok(Cond::Vc),
        "hi" => Ok(Cond::Hi),
        "ls" => Ok(Cond::Ls),
        "ge" => Ok(Cond::Ge),
        "lt" => Ok(Cond::Lt),
        "gt" => Ok(Cond::Gt),
        "le" => Ok(Cond::Le),
        "al" => Ok(Cond::Al),
        "nv" => Ok(Cond::Nv),
        other => Err(WriterError::Msg(format!("bad ConditionCode: {other}"))),
    }
}

/// Argument for `put_call_*_with_arguments` (Frida `GumArgument`).
#[derive(Debug, Clone, Copy)]
pub enum CallArg {
    Address(u64),
    Register(Reg),
}

/// Encode a logical immediate for AND/ORR/EOR/ANDS (N:immr:imms in low 13 bits).
/// Covers contiguous runs of 1-bits (possibly rotated) that tile the register width.
fn try_encode_logical_imm(imm: u64, width: u32) -> Option<u32> {
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let imm = imm & mask;
    if imm == 0 || imm == mask {
        return None;
    }
    for e_size in [2u32, 4, 8, 16, 32, 64] {
        if e_size > width || width % e_size != 0 {
            continue;
        }
        let e_mask = if e_size == 64 {
            u64::MAX
        } else {
            (1u64 << e_size) - 1
        };
        let elem = imm & e_mask;
        let mut ok = true;
        let mut v = imm;
        for _ in 0..(width / e_size) {
            if (v & e_mask) != elem {
                ok = false;
                break;
            }
            v >>= e_size;
        }
        if !ok {
            continue;
        }
        for len in 1..e_size {
            let ones = (1u64 << len) - 1;
            for rot in 0..e_size {
                let candidate = if rot == 0 {
                    ones
                } else {
                    ((ones << (e_size - rot)) | (ones >> rot)) & e_mask
                };
                if candidate == elem {
                    let n = u32::from(e_size == 64);
                    // imms: length field — see ARM bitmask encoding
                    let imms = ((!(e_size * 2 - 1)) & 0x3F) | (len - 1);
                    let immr = rot & 0x3F;
                    return Some((n << 12) | ((immr as u32) << 6) | imms);
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
enum FixupKind {
    B,
    Bl,
    BCond(Cond),
    Cbz { reg: Reg, nonzero: bool },
    Tbz { reg: Reg, bit: u8, nonzero: bool },
}

#[derive(Debug, Clone)]
struct Fixup {
    offset: usize,
    label: String,
    kind: FixupKind,
}

/// In-memory AArch64 emitter (Frida `Arm64Writer` subset).
pub struct Arm64Writer {
    base: u64,
    /// Logical PC for the next emitted instruction (may differ from `code` when
    /// generating into a scratch buffer via `pc` option).
    pc: u64,
    buf: Vec<u8>,
    labels: HashMap<String, usize>,
    fixups: Vec<Fixup>,
}

impl Arm64Writer {
    pub fn new(code_address: u64, pc: Option<u64>) -> Self {
        Self {
            base: code_address,
            pc: pc.unwrap_or(code_address),
            buf: Vec::new(),
            labels: HashMap::new(),
            fixups: Vec::new(),
        }
    }

    pub fn reset(&mut self, code_address: u64, pc: Option<u64>) {
        *self = Self::new(code_address, pc);
    }

    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn code(&self) -> u64 {
        self.base + self.buf.len() as u64
    }
    pub fn pc(&self) -> u64 {
        self.pc + self.buf.len() as u64
    }
    pub fn offset(&self) -> usize {
        self.buf.len()
    }

    pub fn skip(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }

    pub fn put_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn put_instruction(&mut self, insn: u32) {
        self.buf.extend_from_slice(&insn.to_le_bytes());
    }

    pub fn put_label(&mut self, id: &str) {
        self.labels.insert(id.to_string(), self.buf.len());
    }

    fn emit_pc(&self) -> u64 {
        self.pc + self.buf.len() as u64
    }

    pub fn put_nop(&mut self) {
        self.put_instruction(0xD503_201F);
    }

    pub fn put_brk_imm(&mut self, imm: u16) {
        self.put_instruction(0xD420_0000 | ((imm as u32) << 5));
    }

    pub fn put_ret(&mut self) {
        self.put_instruction(0xD65F_03C0); // RET
    }

    pub fn put_ret_reg(&mut self, reg: Reg) -> Result<(), WriterError> {
        // RET Xn
        self.put_instruction(0xD65F_0000 | ((reg.n as u32) << 5));
        Ok(())
    }

    pub fn put_br_reg(&mut self, reg: Reg) -> Result<(), WriterError> {
        self.put_instruction(0xD61F_0000 | ((reg.n as u32) << 5));
        Ok(())
    }

    pub fn put_blr_reg(&mut self, reg: Reg) -> Result<(), WriterError> {
        self.put_instruction(0xD63F_0000 | ((reg.n as u32) << 5));
        Ok(())
    }

    pub fn can_branch_directly_between(from: u64, to: u64) -> bool {
        try_encode_b(from, to).is_some()
    }

    pub fn put_b_imm(&mut self, address: u64) -> Result<(), WriterError> {
        let pc = self.emit_pc();
        if let Some(word) = try_encode_b(pc, address) {
            self.put_instruction(word);
            Ok(())
        } else {
            Err(WriterError::Msg("B target out of range".into()))
        }
    }

    pub fn put_bl_imm(&mut self, address: u64) -> Result<(), WriterError> {
        let pc = self.emit_pc();
        let imm = ((address as i64 - pc as i64) >> 2) as i64;
        if !(-(1 << 25)..(1 << 25)).contains(&imm) {
            return Err(WriterError::Msg("BL target out of range".into()));
        }
        self.put_instruction(0x9400_0000 | ((imm as u32) & 0x03FF_FFFF));
        Ok(())
    }

    pub fn put_branch_address(&mut self, address: u64) {
        self.put_bytes(&encode_abs_branch(address));
    }

    pub fn put_b_label(&mut self, label: &str) {
        let off = self.buf.len();
        self.put_instruction(0x1400_0000); // placeholder B #0
        self.fixups.push(Fixup {
            offset: off,
            label: label.to_string(),
            kind: FixupKind::B,
        });
    }

    pub fn put_bl_label(&mut self, label: &str) {
        let off = self.buf.len();
        self.put_instruction(0x9400_0000);
        self.fixups.push(Fixup {
            offset: off,
            label: label.to_string(),
            kind: FixupKind::Bl,
        });
    }

    pub fn put_b_cond_label(&mut self, cc: Cond, label: &str) {
        let off = self.buf.len();
        self.put_instruction(0x5400_0000 | (cc as u32 & 0xF));
        self.fixups.push(Fixup {
            offset: off,
            label: label.to_string(),
            kind: FixupKind::BCond(cc),
        });
    }

    pub fn put_cbz_reg_imm(&mut self, reg: Reg, target: u64, nonzero: bool) -> Result<(), WriterError> {
        let pc = self.emit_pc();
        self.put_instruction(encode_cbz(reg.n, nonzero, reg.is64, pc, target));
        Ok(())
    }

    pub fn put_cbz_reg_label(&mut self, reg: Reg, label: &str, nonzero: bool) {
        let off = self.buf.len();
        self.put_instruction(0x3400_0000); // placeholder
        self.fixups.push(Fixup {
            offset: off,
            label: label.to_string(),
            kind: FixupKind::Cbz { reg, nonzero },
        });
    }

    pub fn put_tbz_reg_imm_imm(
        &mut self,
        reg: Reg,
        bit: u8,
        target: u64,
        nonzero: bool,
    ) -> Result<(), WriterError> {
        let pc = self.emit_pc();
        self.put_instruction(encode_tbz(reg.n, bit, nonzero, pc, target));
        Ok(())
    }

    pub fn put_tbz_reg_imm_label(&mut self, reg: Reg, bit: u8, label: &str, nonzero: bool) {
        let off = self.buf.len();
        self.put_instruction(0x3600_0000);
        self.fixups.push(Fixup {
            offset: off,
            label: label.to_string(),
            kind: FixupKind::Tbz { reg, bit, nonzero },
        });
    }

    pub fn put_mov_reg_reg(&mut self, dst: Reg, src: Reg) -> Result<(), WriterError> {
        // ORR Xd, XZR, Xm  / ORR Wd, WZR, Wm
        let sf = if dst.is64 { 1u32 << 31 } else { 0 };
        let insn = sf
            | 0x2A00_0000
            | ((src.n as u32 & 31) << 16)
            | (31 << 5)
            | (dst.n as u32 & 31);
        self.put_instruction(insn);
        Ok(())
    }

    pub fn put_add_reg_reg_imm(&mut self, dst: Reg, left: Reg, imm: u32) -> Result<(), WriterError> {
        self.put_instruction(encode_add_imm(dst.n, left.n, imm & 0xFFF, dst.is64));
        Ok(())
    }

    pub fn put_sub_reg_reg_imm(&mut self, dst: Reg, left: Reg, imm: u32) -> Result<(), WriterError> {
        let sf = if dst.is64 { 1u32 << 31 } else { 0 };
        let insn = sf
            | 0x5100_0000
            | ((imm & 0xFFF) << 10)
            | ((left.n as u32 & 31) << 5)
            | (dst.n as u32 & 31);
        self.put_instruction(insn);
        Ok(())
    }

    pub fn put_add_reg_reg_reg(&mut self, dst: Reg, a: Reg, b: Reg) -> Result<(), WriterError> {
        let sf = if dst.is64 { 1u32 << 31 } else { 0 };
        let insn = sf
            | 0x0B00_0000
            | ((b.n as u32 & 31) << 16)
            | ((a.n as u32 & 31) << 5)
            | (dst.n as u32 & 31);
        self.put_instruction(insn);
        Ok(())
    }

    pub fn put_sub_reg_reg_reg(&mut self, dst: Reg, a: Reg, b: Reg) -> Result<(), WriterError> {
        let sf = if dst.is64 { 1u32 << 31 } else { 0 };
        let insn = sf
            | 0x4B00_0000
            | ((b.n as u32 & 31) << 16)
            | ((a.n as u32 & 31) << 5)
            | (dst.n as u32 & 31);
        self.put_instruction(insn);
        Ok(())
    }

    pub fn put_cmp_reg_reg(&mut self, a: Reg, b: Reg) -> Result<(), WriterError> {
        // SUBS XZR, Xa, Xb
        let sf = if a.is64 { 1u32 << 31 } else { 0 };
        let insn = sf
            | 0x6B00_0000
            | ((b.n as u32 & 31) << 16)
            | ((a.n as u32 & 31) << 5)
            | 31;
        self.put_instruction(insn);
        Ok(())
    }

    pub fn put_and_reg_reg_imm(&mut self, dst: Reg, left: Reg, imm: u64) -> Result<(), WriterError> {
        // Simplified: only handle imm that fits bitmask encoding poorly — use AND with
        // MOVZ/MOVK + AND register for general immediates when needed. For common
        // small masks use N=0 bitmask if possible; else emit MOVZ temp path via X16.
        let _ = imm;
        // Fallback: AND Xd, Xn, Xn (no-op-ish) is wrong. Emit AND with imm12-style via
        // BIC not available. Use: MOVZ X16,#lo; MOVK…; AND Xd,Xn,X16
        self.put_ldr_reg_u64(Reg::x(16), imm)?;
        let sf = if dst.is64 { 1u32 << 31 } else { 0 };
        let insn = sf
            | 0x0A00_0000
            | (16u32 << 16)
            | ((left.n as u32 & 31) << 5)
            | (dst.n as u32 & 31);
        self.put_instruction(insn);
        Ok(())
    }

    pub fn put_eor_reg_reg_reg(&mut self, dst: Reg, a: Reg, b: Reg) -> Result<(), WriterError> {
        let sf = if dst.is64 { 1u32 << 31 } else { 0 };
        let insn = sf
            | 0x4A00_0000
            | ((b.n as u32 & 31) << 16)
            | ((a.n as u32 & 31) << 5)
            | (dst.n as u32 & 31);
        self.put_instruction(insn);
        Ok(())
    }

    pub fn put_ldr_reg_u64(&mut self, reg: Reg, val: u64) -> Result<(), WriterError> {
        // LDR Xt, #8; B #12; <u64>
        let rt = reg.n as u32 & 31;
        let ldr = 0x5800_0000u32 | (2 << 5) | rt; // imm19=2 → +8
        self.put_instruction(ldr);
        self.put_instruction(0x1400_0003); // B #12
        self.put_bytes(&val.to_le_bytes());
        Ok(())
    }

    pub fn put_ldr_reg_u32(&mut self, reg: Reg, val: u32) -> Result<(), WriterError> {
        self.put_ldr_reg_u64(reg, val as u64)
    }

    pub fn put_ldr_reg_address(&mut self, reg: Reg, address: u64) -> Result<(), WriterError> {
        self.put_ldr_reg_u64(reg, address)
    }

    pub fn put_adrp_reg_address(&mut self, reg: Reg, address: u64) -> Result<(), WriterError> {
        let pc = self.emit_pc();
        let page_pc = pc & !0xFFF;
        let page_tgt = address & !0xFFF;
        let page_imm = ((page_tgt as i64 - page_pc as i64) >> 12) as i64;
        let immhi = ((page_imm as u32) >> 2) & 0x7_FFFF;
        let immlo = (page_imm as u32) & 0x3;
        let adrp = 0x9000_0000 | (immlo << 29) | (immhi << 5) | (reg.n as u32 & 31);
        self.put_instruction(adrp);
        Ok(())
    }

    pub fn put_ldr_reg_reg_offset(
        &mut self,
        dst: Reg,
        src: Reg,
        offset: i32,
        mode: IndexMode,
    ) -> Result<(), WriterError> {
        // LDR Xt, [Xn, #imm] signed-offset (unscaled if needed)
        match mode {
            IndexMode::SignedOffset => {
                if offset >= 0 && (offset as u32) % (if dst.is64 { 8 } else { 4 }) == 0 {
                    let imm = (offset as u32)
                        / if dst.is64 { 8 } else { 4 };
                    if imm <= 0xFFF {
                        let insn = if dst.is64 {
                            0xF940_0000
                                | ((imm & 0xFFF) << 10)
                                | ((src.n as u32 & 31) << 5)
                                | (dst.n as u32 & 31)
                        } else {
                            0xB940_0000
                                | ((imm & 0xFFF) << 10)
                                | ((src.n as u32 & 31) << 5)
                                | (dst.n as u32 & 31)
                        };
                        self.put_instruction(insn);
                        return Ok(());
                    }
                }
                // LDUR
                let imm9 = (offset as u32) & 0x1FF;
                let insn = if dst.is64 {
                    0xF840_0000 | (imm9 << 12) | ((src.n as u32 & 31) << 5) | (dst.n as u32 & 31)
                } else {
                    0xB840_0000 | (imm9 << 12) | ((src.n as u32 & 31) << 5) | (dst.n as u32 & 31)
                };
                self.put_instruction(insn);
            }
            IndexMode::PreAdjust | IndexMode::PostAdjust => {
                let imm9 = (offset as u32) & 0x1FF;
                let enc = mode.encoding();
                let insn = if dst.is64 {
                    0xF800_0000
                        | (imm9 << 12)
                        | (enc << 10)
                        | ((src.n as u32 & 31) << 5)
                        | (dst.n as u32 & 31)
                } else {
                    0xB800_0000
                        | (imm9 << 12)
                        | (enc << 10)
                        | ((src.n as u32 & 31) << 5)
                        | (dst.n as u32 & 31)
                };
                self.put_instruction(insn);
            }
        }
        Ok(())
    }

    pub fn put_str_reg_reg_offset(
        &mut self,
        src: Reg,
        dst: Reg,
        offset: i32,
        mode: IndexMode,
    ) -> Result<(), WriterError> {
        match mode {
            IndexMode::SignedOffset => {
                if offset >= 0 && (offset as u32) % (if src.is64 { 8 } else { 4 }) == 0 {
                    let imm = (offset as u32) / if src.is64 { 8 } else { 4 };
                    if imm <= 0xFFF {
                        let insn = if src.is64 {
                            0xF900_0000
                                | ((imm & 0xFFF) << 10)
                                | ((dst.n as u32 & 31) << 5)
                                | (src.n as u32 & 31)
                        } else {
                            0xB900_0000
                                | ((imm & 0xFFF) << 10)
                                | ((dst.n as u32 & 31) << 5)
                                | (src.n as u32 & 31)
                        };
                        self.put_instruction(insn);
                        return Ok(());
                    }
                }
                let imm9 = (offset as u32) & 0x1FF;
                let insn = if src.is64 {
                    0xF800_0000 | (imm9 << 12) | ((dst.n as u32 & 31) << 5) | (src.n as u32 & 31)
                } else {
                    0xB800_0000 | (imm9 << 12) | ((dst.n as u32 & 31) << 5) | (src.n as u32 & 31)
                };
                self.put_instruction(insn);
            }
            IndexMode::PreAdjust | IndexMode::PostAdjust => {
                let imm9 = (offset as u32) & 0x1FF;
                let enc = mode.encoding();
                let insn = if src.is64 {
                    0xF800_0000
                        | (imm9 << 12)
                        | (enc << 10)
                        | ((dst.n as u32 & 31) << 5)
                        | (src.n as u32 & 31)
                } else {
                    0xB800_0000
                        | (imm9 << 12)
                        | (enc << 10)
                        | ((dst.n as u32 & 31) << 5)
                        | (src.n as u32 & 31)
                };
                self.put_instruction(insn);
            }
        }
        Ok(())
    }

    pub fn put_ldr_reg_reg(&mut self, dst: Reg, src: Reg) -> Result<(), WriterError> {
        self.put_ldr_reg_reg_offset(dst, src, 0, IndexMode::SignedOffset)
    }

    pub fn put_str_reg_reg(&mut self, src: Reg, dst: Reg) -> Result<(), WriterError> {
        self.put_str_reg_reg_offset(src, dst, 0, IndexMode::SignedOffset)
    }

    /// STP Ra, Rb, [Rn, #imm]! / [Rn, #imm] / [Rn], #imm
    pub fn put_stp_reg_reg_reg_offset(
        &mut self,
        a: Reg,
        b: Reg,
        dst: Reg,
        offset: i32,
        mode: IndexMode,
    ) -> Result<(), WriterError> {
        if a.is_vec != b.is_vec || a.is64 != b.is64 {
            return Err(WriterError::Msg("STP register width mismatch".into()));
        }
        self.put_load_store_pair(false, a, b, dst, offset, mode)
    }

    pub fn put_ldp_reg_reg_reg_offset(
        &mut self,
        a: Reg,
        b: Reg,
        src: Reg,
        offset: i32,
        mode: IndexMode,
    ) -> Result<(), WriterError> {
        if a.is_vec != b.is_vec || a.is64 != b.is64 {
            return Err(WriterError::Msg("LDP register width mismatch".into()));
        }
        self.put_load_store_pair(true, a, b, src, offset, mode)
    }

    fn put_load_store_pair(
        &mut self,
        is_load: bool,
        a: Reg,
        b: Reg,
        base: Reg,
        offset: i32,
        mode: IndexMode,
    ) -> Result<(), WriterError> {
        let (opc, is_vector, shift) = if a.is_vec {
            (2u32, 1u32, 4u32) // Q128
        } else if a.is64 {
            (2u32, 0u32, 3u32) // I64
        } else {
            (0u32, 0u32, 2u32) // I32
        };
        let scale = 1i32 << shift;
        if offset % scale != 0 {
            return Err(WriterError::Msg("pair offset not aligned".into()));
        }
        let imm7 = offset / scale;
        if !(-64..64).contains(&imm7) {
            return Err(WriterError::Msg("pair offset out of range".into()));
        }
        let mode_bits = mode.encoding();
        let op = if is_load { 1u32 } else { 0u32 };
        let insn = (opc << 30)
            | (5 << 27)
            | (is_vector << 26)
            | (mode_bits << 23)
            | (op << 22)
            | (((imm7 as u32) & 0x7F) << 15)
            | ((b.n as u32 & 31) << 10)
            | ((base.n as u32 & 31) << 5)
            | (a.n as u32 & 31);
        self.put_instruction(insn);
        Ok(())
    }

    pub fn put_push_reg_reg(&mut self, a: Reg, b: Reg) -> Result<(), WriterError> {
        let bytes = a.width_bytes() as i32;
        self.put_stp_reg_reg_reg_offset(a, b, Reg::x(31), -(2 * bytes), IndexMode::PreAdjust)
    }

    pub fn put_pop_reg_reg(&mut self, a: Reg, b: Reg) -> Result<(), WriterError> {
        let bytes = a.width_bytes() as i32;
        self.put_ldp_reg_reg_reg_offset(a, b, Reg::x(31), 2 * bytes, IndexMode::PostAdjust)
    }

    pub fn put_push_all_x_registers(&mut self) -> Result<(), WriterError> {
        for i in (0..30).step_by(2) {
            self.put_push_reg_reg(Reg::x(i), Reg::x(i + 1))?;
        }
        self.put_mov_reg_nzcv(Reg::x(15))?;
        self.put_push_reg_reg(Reg::x(30), Reg::x(15))?;
        Ok(())
    }

    pub fn put_pop_all_x_registers(&mut self) -> Result<(), WriterError> {
        self.put_pop_reg_reg(Reg::x(30), Reg::x(15))?;
        self.put_mov_nzcv_reg(Reg::x(15))?;
        // Frida order: (28,29), (26,27), ... (0,1)
        let mut i = 28i8;
        while i >= 0 {
            self.put_pop_reg_reg(Reg::x(i as u8), Reg::x((i + 1) as u8))?;
            i -= 2;
        }
        Ok(())
    }

    pub fn put_push_all_q_registers(&mut self) -> Result<(), WriterError> {
        for i in (0..32).step_by(2) {
            self.put_push_reg_reg(Reg::q(i), Reg::q(i + 1))?;
        }
        Ok(())
    }

    pub fn put_pop_all_q_registers(&mut self) -> Result<(), WriterError> {
        let mut i = 30i8;
        while i >= 0 {
            self.put_pop_reg_reg(Reg::q(i as u8), Reg::q((i + 1) as u8))?;
            i -= 2;
        }
        Ok(())
    }

    pub fn put_mov_reg_nzcv(&mut self, reg: Reg) -> Result<(), WriterError> {
        // MRS Xt, NZCV
        self.put_instruction(0xD53B_4200 | (reg.n as u32 & 31));
        Ok(())
    }

    pub fn put_mov_nzcv_reg(&mut self, reg: Reg) -> Result<(), WriterError> {
        // MSR NZCV, Xt
        self.put_instruction(0xD51B_4200 | (reg.n as u32 & 31));
        Ok(())
    }

    pub fn put_movk_reg_imm(&mut self, reg: Reg, imm: u16, shift: u8) -> Result<(), WriterError> {
        let hw = (shift / 16) as u32;
        let sf = if reg.is64 { 1u32 << 31 } else { 0 };
        let insn = sf
            | 0x7280_0000
            | (hw << 21)
            | ((imm as u32) << 5)
            | (reg.n as u32 & 31);
        self.put_instruction(insn);
        Ok(())
    }

    pub fn put_ubfm(
        &mut self,
        dst: Reg,
        src: Reg,
        immr: u8,
        imms: u8,
    ) -> Result<(), WriterError> {
        if dst.is64 != src.is64 {
            return Err(WriterError::Msg("UBFM width mismatch".into()));
        }
        let sf = if dst.is64 { 0x8040_0000u32 } else { 0 };
        let insn = sf
            | 0x5300_0000
            | ((immr as u32) << 16)
            | ((imms as u32) << 10)
            | ((src.n as u32 & 31) << 5)
            | (dst.n as u32 & 31);
        self.put_instruction(insn);
        Ok(())
    }

    pub fn put_lsl_reg_imm(&mut self, dst: Reg, src: Reg, shift: u8) -> Result<(), WriterError> {
        let size = if dst.is64 { 64u8 } else { 32u8 };
        if shift >= size {
            return Err(WriterError::Msg("LSL shift out of range".into()));
        }
        let immr = (size - shift) % size;
        let imms = size - 1 - shift;
        self.put_ubfm(dst, src, immr, imms)
    }

    pub fn put_lsr_reg_imm(&mut self, dst: Reg, src: Reg, shift: u8) -> Result<(), WriterError> {
        let size = if dst.is64 { 64u8 } else { 32u8 };
        if shift >= size {
            return Err(WriterError::Msg("LSR shift out of range".into()));
        }
        self.put_ubfm(dst, src, shift, size - 1)
    }

    pub fn put_uxtw_reg_reg(&mut self, dst: Reg, src: Reg) -> Result<(), WriterError> {
        // UXTW Xd, Wn  ≡  UBFM Xd, Xn, #0, #31
        if !dst.is64 {
            return Err(WriterError::Msg("UXTW dst must be X reg".into()));
        }
        self.put_instruction(0xD340_7C00 | ((src.n as u32 & 31) << 5) | (dst.n as u32 & 31));
        Ok(())
    }

    pub fn put_ldrsw_reg_reg_offset(
        &mut self,
        dst: Reg,
        src: Reg,
        offset: u32,
    ) -> Result<(), WriterError> {
        if !dst.is64 || !src.is64 {
            return Err(WriterError::Msg("LDRSW needs X regs".into()));
        }
        if offset % 4 != 0 || (offset / 4) > 0xFFF {
            return Err(WriterError::Msg("LDRSW offset out of range".into()));
        }
        let imm = offset / 4;
        self.put_instruction(
            0xB980_0000 | (imm << 10) | ((src.n as u32 & 31) << 5) | (dst.n as u32 & 31),
        );
        Ok(())
    }

    pub fn put_ldr_reg_pcrel(&mut self, reg: Reg, src_address: Option<u64>) -> Result<(), WriterError> {
        let imm19 = if let Some(addr) = src_address {
            let distance = addr as i64 - self.emit_pc() as i64;
            if distance % 4 != 0 {
                return Err(WriterError::Msg("LDR pcrel not aligned".into()));
            }
            let imm = distance / 4;
            if !(-(1 << 18)..(1 << 18)).contains(&imm) {
                return Err(WriterError::Msg("LDR pcrel out of range".into()));
            }
            imm as u32
        } else {
            0
        };
        // LDR (literal): 0x58000000 (64) / 0x18000000 (32)
        let base = if reg.is64 { 0x5800_0000u32 } else { 0x1800_0000u32 };
        self.put_instruction(base | ((imm19 & 0x7_FFFF) << 5) | (reg.n as u32 & 31));
        Ok(())
    }

    pub fn put_ldr_reg_u32_ptr(&mut self, reg: Reg, src_address: u64) -> Result<(), WriterError> {
        if reg.is64 {
            return Err(WriterError::Msg("putLdrRegU32Ptr needs W reg".into()));
        }
        self.put_ldr_reg_pcrel(reg, Some(src_address))
    }

    pub fn put_ldr_reg_u64_ptr(&mut self, reg: Reg, src_address: u64) -> Result<(), WriterError> {
        if !reg.is64 {
            return Err(WriterError::Msg("putLdrRegU64Ptr needs X reg".into()));
        }
        self.put_ldr_reg_pcrel(reg, Some(src_address))
    }

    /// Emit LDR literal with dangling ref; returns byte offset of the LDR.
    pub fn put_ldr_reg_ref(&mut self, reg: Reg) -> Result<u32, WriterError> {
        let ref_off = self.buf.len() as u32;
        self.put_ldr_reg_pcrel(reg, None)?;
        Ok(ref_off)
    }

    /// Patch a previous `put_ldr_reg_ref` and append the 8-byte literal value.
    pub fn put_ldr_reg_value(&mut self, ref_off: u32, value: u64) -> Result<(), WriterError> {
        let ref_off = ref_off as usize;
        if ref_off + 4 > self.buf.len() {
            return Err(WriterError::Msg("bad LDR ref".into()));
        }
        let distance = (self.buf.len() - ref_off) as u32;
        if distance % 4 != 0 {
            return Err(WriterError::Msg("LDR ref misaligned".into()));
        }
        let imm19 = (distance / 4) & 0x7_FFFF;
        let mut word = u32::from_le_bytes(self.buf[ref_off..ref_off + 4].try_into().unwrap());
        word = (word & !(0x7_FFFF << 5)) | (imm19 << 5);
        self.buf[ref_off..ref_off + 4].copy_from_slice(&word.to_le_bytes());
        self.put_bytes(&value.to_le_bytes());
        Ok(())
    }

    pub fn put_tst_reg_imm(&mut self, reg: Reg, imm: u64) -> Result<(), WriterError> {
        if let Some(enc) = try_encode_logical_imm(imm, if reg.is64 { 64 } else { 32 }) {
            let sf = if reg.is64 { 1u32 << 31 } else { 0 };
            // ANDS XZR, Xn, #imm
            self.put_instruction(
                sf | 0x7200_001F | ((reg.n as u32 & 31) << 5) | ((enc & 0x1FFF) << 10),
            );
            Ok(())
        } else {
            // Fallback: materialize imm then ANDS XZR, Xn, X16
            self.put_ldr_reg_u64(Reg::x(16), imm)?;
            let sf = if reg.is64 { 1u32 << 31 } else { 0 };
            self.put_instruction(
                sf | 0x6A00_001F | (16 << 16) | ((reg.n as u32 & 31) << 5),
            );
            Ok(())
        }
    }

    pub fn put_xpaci_reg(&mut self, reg: Reg) -> Result<(), WriterError> {
        if !reg.is64 {
            return Err(WriterError::Msg("XPACI needs X reg".into()));
        }
        self.put_instruction(0xDAC1_43E0 | (reg.n as u32 & 31));
        Ok(())
    }

    pub fn put_pacia_reg_reg(&mut self, dst: Reg, mod_reg: Reg) -> Result<(), WriterError> {
        if !dst.is64 || !mod_reg.is64 {
            return Err(WriterError::Msg("PACIA needs X regs".into()));
        }
        self.put_instruction(
            0xDAC1_0000 | (dst.n as u32 & 31) | ((mod_reg.n as u32 & 31) << 5),
        );
        Ok(())
    }

    pub fn put_mrs(&mut self, dst: Reg, system_reg: u16) -> Result<(), WriterError> {
        if !dst.is64 || (system_reg & 0x8000) != 0 {
            return Err(WriterError::Msg("bad MRS args".into()));
        }
        self.put_instruction(0xD530_0000 | ((system_reg as u32) << 5) | (dst.n as u32 & 31));
        Ok(())
    }

    /// Android/Linux: identity (no PAC signing). Matches Frida when ptrauth unsupported.
    pub fn sign(&self, value: u64) -> u64 {
        value
    }

    /// Call `func` with args: each is either a register name or an immediate address/value.
    pub fn put_call_address_with_arguments(
        &mut self,
        func: u64,
        args: &[CallArg],
    ) -> Result<(), WriterError> {
        self.put_argument_list_setup(args)?;
        let pc = self.emit_pc();
        if Self::can_branch_directly_between(pc, func) {
            self.put_bl_imm(func)?;
        } else {
            let target = Reg::x(args.len() as u8);
            self.put_ldr_reg_address(target, func)?;
            self.put_blr_reg(target)?;
        }
        Ok(())
    }

    pub fn put_call_reg_with_arguments(
        &mut self,
        reg: Reg,
        args: &[CallArg],
    ) -> Result<(), WriterError> {
        self.put_argument_list_setup(args)?;
        self.put_blr_reg(reg)?;
        Ok(())
    }

    fn put_argument_list_setup(&mut self, args: &[CallArg]) -> Result<(), WriterError> {
        for (i, arg) in args.iter().enumerate().rev() {
            let dst = Reg::x(i as u8);
            match arg {
                CallArg::Address(addr) => {
                    self.put_ldr_reg_address(dst, *addr)?;
                }
                CallArg::Register(src) => {
                    if src.is64 {
                        if src.n != dst.n {
                            self.put_mov_reg_reg(dst, *src)?;
                        }
                    } else {
                        self.put_uxtw_reg_reg(dst, *src)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), WriterError> {
        self.flush_to_memory()
    }

    pub fn flush_to_memory(&mut self) -> Result<(), WriterError> {
        self.resolve_fixups()?;
        if self.base == 0 {
            return Ok(());
        }
        unsafe {
            let dst = self.base as *mut u8;
            std::ptr::copy_nonoverlapping(self.buf.as_ptr(), dst, self.buf.len());
            crate::icache::clear_icache(self.base as *const u8, self.buf.len());
        }
        Ok(())
    }

    /// Bytes that would be written (after resolving labels).
    pub fn take_bytes(&mut self) -> Result<Vec<u8>, WriterError> {
        self.resolve_fixups()?;
        Ok(std::mem::take(&mut self.buf))
    }

    fn resolve_fixups(&mut self) -> Result<(), WriterError> {
        let fixups = std::mem::take(&mut self.fixups);
        for f in fixups {
            let Some(&lab_off) = self.labels.get(&f.label) else {
                return Err(WriterError::Msg(format!("undefined label: {}", f.label)));
            };
            let pc = self.pc + f.offset as u64;
            let target = self.pc + lab_off as u64;
            let word = match f.kind {
                FixupKind::B => try_encode_b(pc, target)
                    .ok_or_else(|| WriterError::Msg("B label out of range".into()))?,
                FixupKind::Bl => {
                    let imm = ((target as i64 - pc as i64) >> 2) as i64;
                    if !(-(1 << 25)..(1 << 25)).contains(&imm) {
                        return Err(WriterError::Msg("BL label out of range".into()));
                    }
                    0x9400_0000 | ((imm as u32) & 0x03FF_FFFF)
                }
                FixupKind::BCond(cc) => encode_b_cond(cc, pc, target),
                FixupKind::Cbz { reg, nonzero } => {
                    encode_cbz(reg.n, nonzero, reg.is64, pc, target)
                }
                FixupKind::Tbz { reg, bit, nonzero } => {
                    encode_tbz(reg.n, bit, nonzero, pc, target)
                }
            };
            self.buf[f.offset..f.offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        Ok(())
    }

    /// Append raw relocated instruction bytes (used by Arm64Relocator).
    pub fn put_raw(&mut self, bytes: &[u8]) {
        self.put_bytes(bytes);
    }

    pub fn put_adr_reg_address(&mut self, reg: Reg, address: u64) -> Result<(), WriterError> {
        let pc = self.emit_pc();
        let delta = address as i64 - pc as i64;
        if (-1_048_576..1_048_576).contains(&delta) {
            self.put_instruction(encode_adr(reg.n, pc, address));
            Ok(())
        } else {
            Err(WriterError::Msg("ADR out of range".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nop_ret_flush_buf() {
        let mut w = Arm64Writer::new(0x1000, None);
        w.put_nop();
        w.put_ret();
        let b = w.take_bytes().unwrap();
        assert_eq!(b.len(), 8);
        assert_eq!(&b[0..4], &0xD503_201Fu32.to_le_bytes());
        assert_eq!(&b[4..8], &0xD65F_03C0u32.to_le_bytes());
    }

    #[test]
    fn label_branch() {
        let mut w = Arm64Writer::new(0x2000, None);
        w.put_b_label("done");
        w.put_nop();
        w.put_label("done");
        w.put_ret();
        let b = w.take_bytes().unwrap();
        assert_eq!(b.len(), 12);
        // B #8 → imm26 = 2
        assert_eq!(&b[0..4], &0x1400_0002u32.to_le_bytes());
    }

    #[test]
    fn parse_regs() {
        assert_eq!(Reg::parse("x0").unwrap().n, 0);
        assert_eq!(Reg::parse("lr").unwrap().n, 30);
        assert_eq!(Reg::parse("sp").unwrap().n, 31);
        assert_eq!(Reg::parse("w2").unwrap().is64, false);
        assert!(Reg::parse("q3").unwrap().is_vec);
    }

    #[test]
    fn push_pop_all_x_roundtrip_size() {
        let mut w = Arm64Writer::new(0x1000, None);
        w.put_push_all_x_registers().unwrap();
        let mid = w.offset();
        w.put_pop_all_x_registers().unwrap();
        // 16 push pairs + 16 pop pairs = 32 STP/LDP (+ MRS/MSR folded into push/pop)
        // push: 15 STP for x0-x29 + MRS + 1 STP = 16 mem ops + 1 mrs = 17 insns
        // pop: 1 LDP + MSR + 15 LDP = 17
        assert_eq!(mid, 17 * 4);
        assert_eq!(w.offset(), 34 * 4);
    }

    #[test]
    fn ldr_ref_value() {
        let mut w = Arm64Writer::new(0x3000, None);
        let r = w.put_ldr_reg_ref(Reg::x(0)).unwrap();
        w.put_nop();
        w.put_ldr_reg_value(r, 0x1122_3344_5566_7788).unwrap();
        let b = w.take_bytes().unwrap();
        // LDR at 0, NOP at 4, literal at 8
        assert_eq!(b.len(), 16);
        let ldr = u32::from_le_bytes(b[0..4].try_into().unwrap());
        // imm19 = 2 (distance 8 bytes)
        assert_eq!(ldr & 0xFFFF_FFE0, 0x5800_0040); // base + imm19=2 at bits [23:5]
    }

    #[test]
    fn call_with_imm_arg() {
        let mut w = Arm64Writer::new(0x4000, None);
        w.put_call_address_with_arguments(0x4000 + 64, &[CallArg::Address(7)])
            .unwrap();
        assert!(w.offset() > 4);
    }
}
