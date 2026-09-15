//! Relocate displaced instructions into a trampoline (§4.3).

use crate::decoder::{Arm64Decoder, Cond, DecodedInsn, DisasmAdapter, InsnKind};
use crate::encode::{
    encode_abs_branch, encode_abs_call, encode_b_cond, encode_cbz, encode_ldr_lit_expanded,
    encode_pc_rel_addr, encode_tbz, try_encode_ldr_lit,
};
use crate::ABS_BRANCH_LEN;

/// Minimum number of instructions overwritten by the absolute patch stub.
pub const MIN_PATCH_INSNS: usize = ABS_BRANCH_LEN / 4; // 4

#[derive(Debug, Clone)]
pub struct RelocatedBlock {
    /// Bytes of the trampoline body (relocated insns + final abs jump back).
    pub code: Vec<u8>,
    /// Original instructions that were displaced (for unhook / diagnostics).
    pub displaced: Vec<DecodedInsn>,
    /// Byte length covered at the original site (always ≥ 16, multiple of 4).
    pub patch_len: usize,
    /// Address of the first untouched instruction after the patch.
    pub resume_addr: u64,
}

/// Accumulate whole instructions until ≥16 bytes are covered.
///
/// If relocating any of those requires expansion that would leave a mid-instruction
/// boundary (arm64 fixed 4B — not an issue for length, but conditional expansions
/// may need extra following insns to keep control-flow sensible), keep pulling until
/// we have a clean block. For the initial implementation we always take exactly 4
/// instructions then relocate; expansions live only in the trampoline.
pub fn compute_patch_insns(
    decoder: &impl Arm64Decoder,
    target: u64,
    code: &[u8],
) -> Result<Vec<DecodedInsn>, RelocError> {
    if code.len() < ABS_BRANCH_LEN {
        return Err(RelocError::TruncatedCode);
    }
    let mut out = Vec::with_capacity(MIN_PATCH_INSNS);
    let mut off = 0usize;
    while out.len() < MIN_PATCH_INSNS {
        if off + 4 > code.len() {
            return Err(RelocError::TruncatedCode);
        }
        let word = u32::from_le_bytes(code[off..off + 4].try_into().unwrap());
        let addr = target + off as u64;
        out.push(decoder.decode(addr, word));
        off += 4;
    }
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum RelocError {
    #[error("not enough code bytes to cover a 16-byte patch")]
    TruncatedCode,
    #[error("address out of range / unreadable")]
    OutOfRange,
    #[error("relocation failed: {0}")]
    Failed(String),
}

/// Build a trampoline containing relocated displaced instructions, ending with an
/// absolute jump to `target + patch_len`.
pub fn build_trampoline(
    decoder: &impl Arm64Decoder,
    target: u64,
    code: &[u8],
    trampoline_base: u64,
) -> Result<RelocatedBlock, RelocError> {
    let displaced = compute_patch_insns(decoder, target, code)?;
    let patch_len = displaced.len() * 4;
    let resume_addr = target + patch_len as u64;

    let mut code_out = Vec::new();
    let mut emit_pc = trampoline_base;

    for insn in &displaced {
        let chunk = relocate_one(insn, emit_pc)?;
        emit_pc += chunk.len() as u64;
        code_out.extend_from_slice(&chunk);
    }

    // Absolute jump back to the first untouched instruction.
    let back = encode_abs_branch(resume_addr);
    code_out.extend_from_slice(&back);

    Ok(RelocatedBlock {
        code: code_out,
        displaced,
        patch_len,
        resume_addr,
    })
}

/// Relocate a single decoded instruction for emission at `emit_pc`.
pub fn relocate_one(insn: &DecodedInsn, emit_pc: u64) -> Result<Vec<u8>, RelocError> {
    match &insn.kind {
        InsnKind::PcIndependent | InsnKind::BranchReg { .. } => {
            Ok(insn.raw.to_le_bytes().to_vec())
        }
        InsnKind::Branch { target, link: false } => {
            Ok(encode_abs_branch(*target).to_vec())
        }
        InsnKind::Branch { target, link: true } => Ok(encode_abs_call(emit_pc, *target)),
        InsnKind::BranchCond { target, cond } => {
            // Invert cond to branch over an abs jump; fall through otherwise.
            Ok(rewrite_cond_branch(
                emit_pc,
                *cond,
                *target,
                CondBranchKind::BCond,
                0,
                false,
                false,
                0,
            ))
        }
        InsnKind::CompareBranch {
            target,
            reg,
            nonzero,
            is64,
        } => Ok(rewrite_cond_branch(
            emit_pc,
            Cond::Al, // unused
            *target,
            CondBranchKind::Cbz {
                reg: *reg,
                nonzero: *nonzero,
                is64: *is64,
            },
            *reg,
            *nonzero,
            *is64,
            0,
        )),
        InsnKind::TestBranch {
            target,
            reg,
            bit,
            nonzero,
        } => Ok(rewrite_cond_branch(
            emit_pc,
            Cond::Al,
            *target,
            CondBranchKind::Tbz {
                reg: *reg,
                bit: *bit,
                nonzero: *nonzero,
            },
            *reg,
            *nonzero,
            false,
            *bit,
        )),
        InsnKind::PcRelAddr { rd, target, .. } => {
            Ok(encode_pc_rel_addr(*rd, emit_pc, *target))
        }
        InsnKind::PcRelLoad {
            rt,
            target,
            is64,
            is_simd: _,
        } => {
            // Prefer re-encoding if still in range; else expand with local literal.
            // We don't have the literal value here — load from original target address
            // by materializing an absolute address load:
            //   LDR Xt, #8; B #12; <u64 absolute address of literal pool>
            // then a second LDR from that address — too heavy.
            // Spec: expand to LDR Xt,[PC,#8]; B #12; <8-byte literal>.
            // Since we can't read process memory in this pure function, emit an absolute
            // address materialization + LDR [Xn]:
            //   ADRP/ADD to load address of original literal, then LDR Xt, [Xd].
            // Simpler approach matching the spec when literal still reachable:
            if let Some(word) = try_encode_ldr_lit(*rt, *is64, emit_pc, *target) {
                return Ok(word.to_le_bytes().to_vec());
            }
            // Out of range: emit abs address of literal pool into a local slot, then
            // LDR from register. Sequence:
            //   LDR X17, #8 ; B #12 ; <target addr>
            //   LDR Xt, [X17]
            // But that clobbers X17. Use the expanded form that embeds the *address*
            // and loads from it — for correctness without clobbering, use X17 as scratch
            // (same as abs branch convention).
            let mut out = encode_abs_addr_into_x17(emit_pc, *target);
            // LDR Xt, [X17]  — unsigned offset 0
            let ldr = if *is64 {
                0xF940_0000u32 | ((17u32) << 5) | (*rt as u32 & 31)
            } else {
                0xB940_0000u32 | ((17u32) << 5) | (*rt as u32 & 31)
            };
            out.extend_from_slice(&ldr.to_le_bytes());
            let _ = encode_ldr_lit_expanded; // keep helper available for future
            Ok(out)
        }
    }
}

enum CondBranchKind {
    BCond,
    Cbz { reg: u8, nonzero: bool, is64: bool },
    Tbz { reg: u8, bit: u8, nonzero: bool },
}

/// Rewrite short conditional as: inverted-cond → skip; abs jump to real target; fallthrough.
///
/// Layout:
/// ```text
///   <inverted cond>  → .+20   (skip the abs branch)
///   LDR X17, #8
///   BR  X17
///   <u64 target>
///   ; fallthrough continues here
/// ```
fn rewrite_cond_branch(
    emit_pc: u64,
    cond: Cond,
    target: u64,
    kind: CondBranchKind,
    _reg: u8,
    _nonzero: bool,
    _is64: bool,
    _bit: u8,
) -> Vec<u8> {
    let skip_target = emit_pc + 4 + 16; // after cond insn + abs branch
    let mut out = Vec::with_capacity(20);
    let cond_word = match kind {
        CondBranchKind::BCond => encode_b_cond(cond.invert(), emit_pc, skip_target),
        CondBranchKind::Cbz {
            reg,
            nonzero,
            is64,
        } => {
            // Invert nonzero: CBZ↔CBNZ
            encode_cbz(reg, !nonzero, is64, emit_pc, skip_target)
        }
        CondBranchKind::Tbz { reg, bit, nonzero } => {
            encode_tbz(reg, bit, !nonzero, emit_pc, skip_target)
        }
    };
    out.extend_from_slice(&cond_word.to_le_bytes());
    out.extend_from_slice(&encode_abs_branch(target));
    out
}

/// `LDR X17, #8; B #12; <u64 addr>` starting at `emit_pc`.
fn encode_abs_addr_into_x17(emit_pc: u64, addr: u64) -> Vec<u8> {
    let _ = emit_pc;
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&0x5800_0051u32.to_le_bytes()); // LDR X17, #8
    out.extend_from_slice(&0x1400_0003u32.to_le_bytes()); // B #12
    out.extend_from_slice(&addr.to_le_bytes());
    out
}

/// Frida-style streaming relocator: read instructions from an input address
/// and emit relocated equivalents into an [`crate::writer::Arm64Writer`].
pub struct Arm64Relocator {
    input: u64,
    input_pc: u64,
    eob: bool,
    eoi: bool,
    read_ahead: Vec<DecodedInsn>,
    /// Optional in-memory source bytes (host/tests). When `None`, reads process memory.
    source: Option<Vec<u8>>,
    source_base: u64,
    bytes_read: usize,
}

impl Arm64Relocator {
    pub fn new(input_code: u64, _output_base: u64) -> Self {
        Self {
            input: input_code,
            input_pc: input_code,
            eob: false,
            eoi: false,
            read_ahead: Vec::new(),
            source: None,
            source_base: input_code,
            bytes_read: 0,
        }
    }

    /// Bind a local byte buffer as the instruction source (for tests / offline use).
    pub fn with_source(mut self, base: u64, bytes: Vec<u8>) -> Self {
        self.source_base = base;
        self.input = base;
        self.input_pc = base;
        self.source = Some(bytes);
        self
    }

    pub fn input(&self) -> Option<&DecodedInsn> {
        self.read_ahead.last()
    }

    pub fn input_addr(&self) -> u64 {
        self.input
    }

    pub fn eob(&self) -> bool {
        self.eob
    }

    pub fn eoi(&self) -> bool {
        self.eoi
    }

    fn read_u32_at(&self, addr: u64) -> Result<u32, RelocError> {
        if let Some(ref src) = self.source {
            let off = addr
                .checked_sub(self.source_base)
                .ok_or(RelocError::OutOfRange)? as usize;
            if off + 4 > src.len() {
                return Err(RelocError::OutOfRange);
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&src[off..off + 4]);
            return Ok(u32::from_le_bytes(b));
        }
        if addr == 0 {
            return Err(RelocError::OutOfRange);
        }
        let word = unsafe { std::ptr::read_unaligned(addr as *const u32) };
        Ok(word)
    }

    /// Read the next instruction into the internal queue.
    /// Returns total bytes read so far (including previous calls), or 0 at EOI.
    pub fn read_one(&mut self) -> Result<usize, RelocError> {
        if self.eoi {
            return Ok(0);
        }
        let word = match self.read_u32_at(self.input_pc) {
            Ok(w) => w,
            Err(_) => {
                self.eoi = true;
                return Ok(0);
            }
        };
        let decoder = DisasmAdapter;
        let insn = decoder.decode(self.input_pc, word);
        match &insn.kind {
            InsnKind::Branch { link: false, .. } | InsnKind::BranchReg { .. } => {
                self.eob = true;
                self.eoi = true;
            }
            InsnKind::Branch { link: true, .. } => {
                self.eob = true;
            }
            InsnKind::BranchCond { .. }
            | InsnKind::CompareBranch { .. }
            | InsnKind::TestBranch { .. } => {
                self.eob = true;
            }
            _ => {}
        }
        self.read_ahead.push(insn);
        self.input_pc = self.input_pc.wrapping_add(4);
        self.bytes_read += 4;
        Ok(self.bytes_read)
    }

    pub fn peek_next_write_source(&self) -> Option<u64> {
        self.read_ahead.first().map(|i| i.addr)
    }

    pub fn peek_next_write_insn(&self) -> Option<&DecodedInsn> {
        self.read_ahead.first()
    }

    /// Copy next buffered instruction without relocating.
    pub fn copy_one(&mut self, writer: &mut crate::writer::Arm64Writer) -> Result<bool, RelocError> {
        if self.read_ahead.is_empty() {
            if self.read_one()? == 0 {
                return Ok(false);
            }
        }
        let insn = self.read_ahead.remove(0);
        writer.put_instruction(insn.raw);
        self.input = insn.addr.wrapping_add(4);
        Ok(true)
    }

    /// Relocate next buffered instruction into `writer`.
    pub fn write_one(&mut self, writer: &mut crate::writer::Arm64Writer) -> Result<bool, RelocError> {
        if self.read_ahead.is_empty() {
            if self.read_one()? == 0 {
                return Ok(false);
            }
        }
        let insn = self.read_ahead.remove(0);
        let bytes = relocate_one(&insn, writer.pc())?;
        writer.put_raw(&bytes);
        self.input = insn.addr.wrapping_add(4);
        Ok(true)
    }

    pub fn skip_one(&mut self) -> Result<bool, RelocError> {
        if self.read_ahead.is_empty() {
            if self.read_one()? == 0 {
                return Ok(false);
            }
        }
        let insn = self.read_ahead.remove(0);
        self.input = insn.addr.wrapping_add(4);
        Ok(true)
    }

    /// Relocate all buffered instructions, reading until eoi if needed.
    pub fn write_all(&mut self, writer: &mut crate::writer::Arm64Writer) -> Result<(), RelocError> {
        loop {
            if self.read_ahead.is_empty() && !self.eoi {
                if self.read_one()? == 0 {
                    break;
                }
            }
            if self.read_ahead.is_empty() {
                break;
            }
            self.write_one(writer)?;
        }
        Ok(())
    }

    pub fn reset(&mut self, input_code: u64, _output_base: u64) {
        self.input = input_code;
        self.input_pc = input_code;
        self.eob = false;
        self.eoi = false;
        self.read_ahead.clear();
        self.bytes_read = 0;
        if self.source.is_some() {
            self.source_base = input_code;
        }
    }

    pub fn dispose(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::DisasmAdapter;
    use crate::writer::Arm64Writer;

    #[test]
    fn patch_covers_four_nops() {
        let code = [0x1Fu8, 0x20, 0x03, 0xD5].repeat(4); // NOP × 4
        let d = DisasmAdapter;
        let insns = compute_patch_insns(&d, 0x1000, &code).unwrap();
        assert_eq!(insns.len(), 4);
        let block = build_trampoline(&d, 0x1000, &code, 0xAAAA_0000).unwrap();
        assert_eq!(block.patch_len, 16);
        assert_eq!(block.resume_addr, 0x1010);
        // 4 NOPs + 16-byte abs back-jump
        assert_eq!(block.code.len(), 16 + 16);
    }

    #[test]
    fn relocates_unconditional_b() {
        // B #0 at 0x1000
        let mut code = vec![0u8; 16];
        code[0..4].copy_from_slice(&0x1400_0000u32.to_le_bytes());
        // fill rest with NOP
        for i in 1..4 {
            code[i * 4..i * 4 + 4].copy_from_slice(&0xD503_201Fu32.to_le_bytes());
        }
        let d = DisasmAdapter;
        let block = build_trampoline(&d, 0x1000, &code, 0xBBBB_0000).unwrap();
        // First relocated insn expands to 16-byte abs branch
        assert!(block.code.len() > 32);
    }

    #[test]
    fn streaming_relocator_nops() {
        let code = [0x1Fu8, 0x20, 0x03, 0xD5].repeat(4);
        let mut w = Arm64Writer::new(0x2000, None);
        let mut r = Arm64Relocator::new(0x1000, w.base()).with_source(0x1000, code);
        assert!(r.read_one().unwrap() > 0);
        assert!(r.write_one(&mut w).unwrap());
        assert_eq!(w.offset(), 4);
    }
}
