//! AArch64 instruction encoders used by the relocator and patch stubs.

use crate::decoder::Cond;

/// Absolute branch: `LDR X17, #8; BR X17; <u64 target>` = 16 bytes.
pub fn encode_abs_branch(target: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    // LDR X17, #8  — 0x58000051
    out[0..4].copy_from_slice(&0x5800_0051u32.to_le_bytes());
    // BR X17       — 0xD61F0220
    out[4..8].copy_from_slice(&0xD61F_0220u32.to_le_bytes());
    out[8..16].copy_from_slice(&target.to_le_bytes());
    out
}

/// Absolute call that preserves LR: `ADR LR, resume; LDR X17,#8; BR X17; <target>`
/// where resume is the address immediately after this 20-byte sequence.
///
/// Layout (20 bytes + 0 padding — caller places this and knows resume = emit_pc + 20):
/// ```text
/// ADR X30, #20     ; resume after sequence
/// LDR X17, #8
/// BR  X17
/// <u64 target>
/// ```
/// Note: ADR LR,#20 from the ADR's PC points to emit_pc+20.
pub fn encode_abs_call(emit_pc: u64, target: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    // ADR X30, #20 — imm = 20, encoding below
    out.extend_from_slice(&encode_adr(30, emit_pc, emit_pc.wrapping_add(20)).to_le_bytes());
    out.extend_from_slice(&0x5800_0051u32.to_le_bytes()); // LDR X17, #8
    out.extend_from_slice(&0xD61F_0220u32.to_le_bytes()); // BR X17
    out.extend_from_slice(&target.to_le_bytes());
    out
}

/// ADR Xd, target — returns None if out of ±1MB range.
pub fn encode_adr(rd: u8, pc: u64, target: u64) -> u32 {
    let imm = target as i64 - pc as i64;
    debug_assert!((-1_048_576..1_048_576).contains(&imm) && imm % 4 == 0 || imm.abs() < 1_048_576);
    let imm21 = (imm as u32) & 0x1F_FFFF;
    let immlo = imm21 & 0x3;
    let immhi = (imm21 >> 2) & 0x7_FFFF;
    0x1000_0000 | (immlo << 29) | (immhi << 5) | (rd as u32 & 31)
}

/// Try ADR; if out of range, emit ADRP+ADD (8 bytes).
pub fn encode_pc_rel_addr(rd: u8, emit_pc: u64, target: u64) -> Vec<u8> {
    let delta = target as i64 - emit_pc as i64;
    if (-1_048_576..1_048_576).contains(&delta) {
        return encode_adr(rd, emit_pc, target).to_le_bytes().to_vec();
    }
    // ADRP Xd, page(target); ADD Xd, Xd, #pageoff
    let page_pc = emit_pc & !0xFFF;
    let page_tgt = target & !0xFFF;
    let page_imm = ((page_tgt as i64 - page_pc as i64) >> 12) as i64;
    let immhi = ((page_imm as u32) >> 2) & 0x7_FFFF;
    let immlo = (page_imm as u32) & 0x3;
    let adrp = 0x9000_0000 | (immlo << 29) | (immhi << 5) | (rd as u32 & 31);
    let pageoff = (target & 0xFFF) as u32;
    let add = encode_add_imm(rd, rd, pageoff, true);
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&adrp.to_le_bytes());
    out.extend_from_slice(&add.to_le_bytes());
    out
}

/// ADD Xd, Xn, #imm12 (shift 0).
pub fn encode_add_imm(rd: u8, rn: u8, imm12: u32, is64: bool) -> u32 {
    let sf = if is64 { 1u32 << 31 } else { 0 };
    sf | 0x1100_0000 | ((imm12 & 0xFFF) << 10) | ((rn as u32 & 31) << 5) | (rd as u32 & 31)
}

/// B.cond with 19-bit imm (PC-relative, ±1MB).
pub fn encode_b_cond(cond: Cond, pc: u64, target: u64) -> u32 {
    let imm = ((target as i64 - pc as i64) >> 2) as i32;
    let imm19 = (imm as u32) & 0x7_FFFF;
    0x5400_0000 | (imm19 << 5) | (cond as u32 & 0xF)
}

/// CBZ / CBNZ
pub fn encode_cbz(reg: u8, nonzero: bool, is64: bool, pc: u64, target: u64) -> u32 {
    let imm = ((target as i64 - pc as i64) >> 2) as i32;
    let imm19 = (imm as u32) & 0x7_FFFF;
    let sf = if is64 { 1u32 << 31 } else { 0 };
    let op = if nonzero { 1u32 << 24 } else { 0 };
    sf | 0x3400_0000 | op | (imm19 << 5) | (reg as u32 & 31)
}

/// TBZ / TBNZ
pub fn encode_tbz(reg: u8, bit: u8, nonzero: bool, pc: u64, target: u64) -> u32 {
    let imm = ((target as i64 - pc as i64) >> 2) as i32;
    let imm14 = (imm as u32) & 0x3FFF;
    let b5 = ((bit as u32) >> 5) & 1;
    let b40 = (bit as u32) & 0x1F;
    let op = if nonzero { 1u32 << 24 } else { 0 };
    (b5 << 31) | 0x3600_0000 | op | (b40 << 19) | (imm14 << 5) | (reg as u32 & 31)
}

/// Unconditional B (26-bit, ±128MB). Returns None if out of range.
pub fn try_encode_b(pc: u64, target: u64) -> Option<u32> {
    let imm = ((target as i64 - pc as i64) >> 2) as i64;
    if !(-(1 << 25)..(1 << 25)).contains(&imm) {
        return None;
    }
    Some(0x1400_0000 | ((imm as u32) & 0x03FF_FFFF))
}

/// LDR (literal) Xt, label — 19-bit PC-relative. Returns None if out of range.
pub fn try_encode_ldr_lit(rt: u8, is64: bool, pc: u64, target: u64) -> Option<u32> {
    let imm = ((target as i64 - pc as i64) >> 2) as i64;
    if !(-(1 << 18)..(1 << 18)).contains(&imm) {
        return None;
    }
    let opc = if is64 { 0b01u32 } else { 0b00 };
    Some(0x1800_0000 | (opc << 30) | (((imm as u32) & 0x7_FFFF) << 5) | (rt as u32 & 31))
}

/// Expand literal LDR that is out of range:
/// `LDR Xt, [PC,#8]; B #12; <8-byte literal>` — actually:
/// ```text
/// LDR Xt, #8
/// B   #12        ; skip literal
/// <u64 data>     ; at LDR_pc+8
/// ```
pub fn encode_ldr_lit_expanded(rt: u8, is64: bool, literal: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    // LDR Xt, #8 from current PC
    let ldr = if is64 {
        0x5800_0000u32 | (rt as u32 & 31) // LDR Xt, #0 with imm19=1 → offset 8? 
        // Encoding: opc=01, imm19=1 → offset = 1*4 = 4... wait we need offset 8 = imm19=2
        // Actually LDR lit #8 means imm19 = 2 (offset = imm19*4 = 8)
    } else {
        0x1800_0000u32 | (rt as u32 & 31)
    };
    // Fix: imm19 = 2 for +8
    let ldr = (ldr & !0x00FF_FFE0) | (2u32 << 5);
    out.extend_from_slice(&ldr.to_le_bytes());
    // B #12 — skip 8-byte literal + land on next insn; from B's PC, +12 means imm26=3
    out.extend_from_slice(&0x1400_0003u32.to_le_bytes());
    out.extend_from_slice(&literal.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_branch_layout() {
        let b = encode_abs_branch(0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(&b[0..4], &0x5800_0051u32.to_le_bytes());
        assert_eq!(&b[4..8], &0xD61F_0220u32.to_le_bytes());
        assert_eq!(&b[8..16], &0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
    }

    #[test]
    fn adr_round_near() {
        let pc = 0x1000u64;
        let target = 0x1010u64;
        let word = encode_adr(0, pc, target);
        // Decode with disassembler
        let insn = arm_disassembler::decode_raw(pc, word);
        assert_eq!(insn.near_branch_target, target);
    }
}
