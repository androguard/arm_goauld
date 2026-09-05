//! Disassembler integration contract (§4.1).
//!
//! `goauld-native-hook` consumes [`Arm64Decoder`] so the sibling `arm_disassembler`
//! crate only needs a thin adapter — no Capstone.

/// ARM64 condition codes (B.cond).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cond {
    Eq = 0,
    Ne = 1,
    Cs = 2,
    Cc = 3,
    Mi = 4,
    Pl = 5,
    Vs = 6,
    Vc = 7,
    Hi = 8,
    Ls = 9,
    Ge = 10,
    Lt = 11,
    Gt = 12,
    Le = 13,
    Al = 14,
    Nv = 15,
}

impl Cond {
    pub fn invert(self) -> Self {
        // Pairwise invert: eq↔ne, cs↔cc, ...; AL/NV stay as-is for fallthrough rewrites.
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Cs => Self::Cc,
            Self::Cc => Self::Cs,
            Self::Mi => Self::Pl,
            Self::Pl => Self::Mi,
            Self::Vs => Self::Vc,
            Self::Vc => Self::Vs,
            Self::Hi => Self::Ls,
            Self::Ls => Self::Hi,
            Self::Ge => Self::Lt,
            Self::Lt => Self::Ge,
            Self::Gt => Self::Le,
            Self::Le => Self::Gt,
            Self::Al => Self::Nv,
            Self::Nv => Self::Al,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v & 0xF {
            0 => Self::Eq,
            1 => Self::Ne,
            2 => Self::Cs,
            3 => Self::Cc,
            4 => Self::Mi,
            5 => Self::Pl,
            6 => Self::Vs,
            7 => Self::Vc,
            8 => Self::Hi,
            9 => Self::Ls,
            10 => Self::Ge,
            11 => Self::Lt,
            12 => Self::Gt,
            13 => Self::Le,
            14 => Self::Al,
            _ => Self::Nv,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsnKind {
    /// B / BL — absolute target resolved from PC-relative encoding.
    Branch { target: u64, link: bool },
    /// B.cond
    BranchCond { target: u64, cond: Cond },
    /// CBZ / CBNZ
    CompareBranch {
        target: u64,
        reg: u8,
        nonzero: bool,
        is64: bool,
    },
    /// TBZ / TBNZ
    TestBranch {
        target: u64,
        reg: u8,
        bit: u8,
        nonzero: bool,
    },
    /// ADR / ADRP
    PcRelAddr {
        rd: u8,
        target: u64,
        is_page: bool,
    },
    /// LDR (literal)
    PcRelLoad {
        rt: u8,
        target: u64,
        is64: bool,
        is_simd: bool,
    },
    /// BR / BLR / RET — register-indirect, copy as-is.
    BranchReg { rn: u8 },
    /// No PC dependency — safe to copy verbatim.
    PcIndependent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInsn {
    pub addr: u64,
    pub raw: u32,
    pub kind: InsnKind,
}

pub trait Arm64Decoder {
    fn decode(&self, addr: u64, word: u32) -> DecodedInsn;
}

/// Adapter over [`arm_disassembler::decode_raw`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DisasmAdapter;

impl Arm64Decoder for DisasmAdapter {
    fn decode(&self, addr: u64, word: u32) -> DecodedInsn {
        use arm_disassembler::{Code, OpKind, Register};

        let insn = arm_disassembler::decode_raw(addr, word);
        let kind = match insn.code {
            Code::B => InsnKind::Branch {
                target: insn.near_branch_target,
                link: false,
            },
            Code::Bl => InsnKind::Branch {
                target: insn.near_branch_target,
                link: true,
            },
            Code::B_cond => InsnKind::BranchCond {
                target: insn.near_branch_target,
                cond: condition_to_cond(insn.condition),
            },
            Code::Cbz => InsnKind::CompareBranch {
                target: insn.near_branch_target,
                reg: reg_index(insn.op0_reg),
                nonzero: false,
                is64: is_x_reg(insn.op0_reg),
            },
            Code::Cbnz => InsnKind::CompareBranch {
                target: insn.near_branch_target,
                reg: reg_index(insn.op0_reg),
                nonzero: true,
                is64: is_x_reg(insn.op0_reg),
            },
            Code::Tbz => {
                let bit = (insn.op1_imm & 0x3F) as u8;
                InsnKind::TestBranch {
                    target: insn.near_branch_target,
                    reg: reg_index(insn.op0_reg),
                    bit,
                    nonzero: false,
                }
            }
            Code::Tbnz => {
                let bit = (insn.op1_imm & 0x3F) as u8;
                InsnKind::TestBranch {
                    target: insn.near_branch_target,
                    reg: reg_index(insn.op0_reg),
                    bit,
                    nonzero: true,
                }
            }
            Code::Adr => InsnKind::PcRelAddr {
                rd: reg_index(insn.op0_reg),
                target: insn.op1_imm,
                is_page: false,
            },
            Code::Adrp => InsnKind::PcRelAddr {
                rd: reg_index(insn.op0_reg),
                target: insn.op1_imm,
                is_page: true,
            },
            Code::Ldr_lit | Code::Ldrsw_lit => {
                let target = if insn.op1_kind == OpKind::NearBranch
                    || insn.op1_kind == OpKind::Immediate
                {
                    // Prefer near_branch_target when the decoder filled it; else op1_imm.
                    if insn.near_branch_target != 0 {
                        insn.near_branch_target
                    } else {
                        insn.op1_imm
                    }
                } else {
                    insn.near_branch_target
                };
                InsnKind::PcRelLoad {
                    rt: reg_index(insn.op0_reg),
                    target,
                    is64: matches!(insn.code, Code::Ldr_lit) && is_x_reg(insn.op0_reg),
                    is_simd: false,
                }
            }
            Code::Ldr_fp_lit => InsnKind::PcRelLoad {
                rt: reg_index(insn.op0_reg),
                target: if insn.near_branch_target != 0 {
                    insn.near_branch_target
                } else {
                    insn.op1_imm
                },
                is64: true,
                is_simd: true,
            },
            Code::Br | Code::Blr | Code::Ret => InsnKind::BranchReg {
                rn: reg_index(match insn.code {
                    Code::Ret => {
                        if insn.op_count > 0 {
                            insn.op0_reg
                        } else {
                            Register::X30
                        }
                    }
                    _ => insn.op0_reg,
                }),
            },
            _ => InsnKind::PcIndependent,
        };

        DecodedInsn {
            addr,
            raw: word,
            kind,
        }
    }
}

fn condition_to_cond(c: arm_disassembler::Condition) -> Cond {
    use arm_disassembler::Condition;
    match c {
        Condition::Eq => Cond::Eq,
        Condition::Ne => Cond::Ne,
        Condition::Cs => Cond::Cs,
        Condition::Cc => Cond::Cc,
        Condition::Mi => Cond::Mi,
        Condition::Pl => Cond::Pl,
        Condition::Vs => Cond::Vs,
        Condition::Vc => Cond::Vc,
        Condition::Hi => Cond::Hi,
        Condition::Ls => Cond::Ls,
        Condition::Ge => Cond::Ge,
        Condition::Lt => Cond::Lt,
        Condition::Gt => Cond::Gt,
        Condition::Le => Cond::Le,
        Condition::Al => Cond::Al,
        Condition::Nv => Cond::Nv,
    }
}

fn reg_index(r: arm_disassembler::Register) -> u8 {
    use arm_disassembler::Register::*;
    match r {
        X0 | W0 => 0,
        X1 | W1 => 1,
        X2 | W2 => 2,
        X3 | W3 => 3,
        X4 | W4 => 4,
        X5 | W5 => 5,
        X6 | W6 => 6,
        X7 | W7 => 7,
        X8 | W8 => 8,
        X9 | W9 => 9,
        X10 | W10 => 10,
        X11 | W11 => 11,
        X12 | W12 => 12,
        X13 | W13 => 13,
        X14 | W14 => 14,
        X15 | W15 => 15,
        X16 | W16 => 16,
        X17 | W17 => 17,
        X18 | W18 => 18,
        X19 | W19 => 19,
        X20 | W20 => 20,
        X21 | W21 => 21,
        X22 | W22 => 22,
        X23 | W23 => 23,
        X24 | W24 => 24,
        X25 | W25 => 25,
        X26 | W26 => 26,
        X27 | W27 => 27,
        X28 | W28 => 28,
        X29 | W29 => 29,
        X30 | W30 => 30,
        XZR | WZR | SP | WSP => 31,
        _ => 0,
    }
}

fn is_x_reg(r: arm_disassembler::Register) -> bool {
    use arm_disassembler::Register::*;
    matches!(
        r,
        X0 | X1
            | X2
            | X3
            | X4
            | X5
            | X6
            | X7
            | X8
            | X9
            | X10
            | X11
            | X12
            | X13
            | X14
            | X15
            | X16
            | X17
            | X18
            | X19
            | X20
            | X21
            | X22
            | X23
            | X24
            | X25
            | X26
            | X27
            | X28
            | X29
            | X30
            | XZR
            | SP
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_b_bl() {
        let d = DisasmAdapter;
        // B #0 at addr 0 → target 0; encoding imm26=0, link=0 → 0x14000000
        let insn = d.decode(0x1000, 0x14000000);
        assert!(matches!(
            insn.kind,
            InsnKind::Branch {
                target: 0x1000,
                link: false
            }
        ));
        // BL #0 → 0x94000000
        let insn = d.decode(0x2000, 0x94000000);
        assert!(matches!(
            insn.kind,
            InsnKind::Branch {
                target: 0x2000,
                link: true
            }
        ));
    }

    #[test]
    fn decode_pc_independent() {
        let d = DisasmAdapter;
        // NOP
        let insn = d.decode(0, 0xD503201F);
        assert_eq!(insn.kind, InsnKind::PcIndependent);
    }
}
