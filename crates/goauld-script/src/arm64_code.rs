//! Handle registry + JSON op dispatcher for Frida-shaped `Arm64Writer` /
//! `Arm64Relocator` (shared by QuickJS and Symbiote bindings).

use goauld_native_hook::writer::{Arm64Writer, IndexMode, Reg, parse_cond};
use goauld_native_hook::{Arm64Relocator, CallArg, RelocError};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_WRITER: AtomicU32 = AtomicU32::new(1);
static NEXT_RELOC: AtomicU32 = AtomicU32::new(1);

static WRITERS: Mutex<Option<HashMap<u32, Arm64Writer>>> = Mutex::new(None);
static RELOCS: Mutex<Option<HashMap<u32, Arm64Relocator>>> = Mutex::new(None);

fn with_writers<R>(f: impl FnOnce(&mut HashMap<u32, Arm64Writer>) -> R) -> R {
    let mut g = WRITERS.lock();
    if g.is_none() {
        *g = Some(HashMap::new());
    }
    f(g.as_mut().unwrap())
}

fn with_relocs<R>(f: impl FnOnce(&mut HashMap<u32, Arm64Relocator>) -> R) -> R {
    let mut g = RELOCS.lock();
    if g.is_none() {
        *g = Some(HashMap::new());
    }
    f(g.as_mut().unwrap())
}

fn arg_u64(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(|x| {
            x.as_u64()
                .or_else(|| x.as_f64().map(|f| f as u64))
                .or_else(|| x.as_str().and_then(|s| {
                    let s = s.trim();
                    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        u64::from_str_radix(h, 16).ok()
                    } else {
                        s.parse().ok()
                    }
                }))
        })
        .ok_or_else(|| format!("missing/invalid u64 arg: {key}"))
}

fn arg_i64(v: &Value, key: &str) -> Result<i64, String> {
    v.get(key)
        .and_then(|x| {
            x.as_i64()
                .or_else(|| x.as_f64().map(|f| f as i64))
                .or_else(|| x.as_u64().map(|u| u as i64))
        })
        .ok_or_else(|| format!("missing/invalid i64 arg: {key}"))
}

fn arg_str(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(|x| x.as_str().map(|s| s.to_string()))
        .ok_or_else(|| format!("missing/invalid string arg: {key}"))
}

fn arg_reg(v: &Value, key: &str) -> Result<Reg, String> {
    Reg::parse(&arg_str(v, key)?).map_err(|e| e.to_string())
}

fn arg_mode(v: &Value, key: &str) -> Result<IndexMode, String> {
    IndexMode::parse(&arg_str(v, key)?).map_err(|e| e.to_string())
}

fn ok_null() -> String {
    json!({"ok": true}).to_string()
}

fn ok_val(v: Value) -> String {
    json!({"ok": true, "v": v}).to_string()
}

fn err(msg: impl Into<String>) -> String {
    json!({"ok": false, "error": msg.into()}).to_string()
}

pub fn writer_new(code_address: u64, pc: Option<u64>) -> u32 {
    let id = NEXT_WRITER.fetch_add(1, Ordering::Relaxed);
    with_writers(|m| {
        m.insert(id, Arm64Writer::new(code_address, pc));
    });
    id
}

pub fn relocator_new(input: u64, writer_id: u32) -> Result<u32, String> {
    let base = with_writers(|m| {
        m.get(&writer_id)
            .map(|w| w.base())
            .ok_or_else(|| format!("bad writer id {writer_id}"))
    })?;
    let id = NEXT_RELOC.fetch_add(1, Ordering::Relaxed);
    with_relocs(|m| {
        m.insert(id, Arm64Relocator::new(input, base));
    });
    Ok(id)
}

/// Bind offline source bytes to a relocator (tests / Memory.alloc buffers).
pub fn relocator_set_source(id: u32, base: u64, bytes: Vec<u8>) -> Result<(), String> {
    with_relocs(|m| {
        let r = m
            .get_mut(&id)
            .ok_or_else(|| format!("bad relocator id {id}"))?;
        *r = Arm64Relocator::new(base, 0).with_source(base, bytes);
        Ok(())
    })
}

pub fn writer_op(id: u32, op: &str, args_json: &str) -> String {
    let args: Value = if args_json.is_empty() {
        json!({})
    } else {
        match serde_json::from_str(args_json) {
            Ok(v) => v,
            Err(e) => return err(format!("bad args json: {e}")),
        }
    };

    if op == "dispose" {
        with_writers(|m| {
            m.remove(&id);
        });
        return ok_null();
    }

    with_writers(|m| {
        let Some(w) = m.get_mut(&id) else {
            return err(format!("bad writer id {id}"));
        };
        match op {
            "reset" => {
                let addr = match arg_u64(&args, "codeAddress") {
                    Ok(a) => a,
                    Err(e) => return err(e),
                };
                let pc = args.get("pc").and_then(|x| {
                    x.as_u64()
                        .or_else(|| x.as_f64().map(|f| f as u64))
                });
                w.reset(addr, pc);
                ok_null()
            }
            "flush" => match w.flush() {
                Ok(()) => ok_null(),
                Err(e) => err(e.to_string()),
            },
            "base" => ok_val(json!(w.base())),
            "code" => ok_val(json!(w.code())),
            "pc" => ok_val(json!(w.pc())),
            "offset" => ok_val(json!(w.offset())),
            "skip" => {
                let n = match arg_u64(&args, "n") {
                    Ok(n) => n as usize,
                    Err(e) => return err(e),
                };
                w.skip(n);
                ok_null()
            }
            "putLabel" => {
                let id = match arg_str(&args, "id") {
                    Ok(s) => s,
                    Err(e) => return err(e),
                };
                w.put_label(&id);
                ok_null()
            }
            "putNop" => {
                w.put_nop();
                ok_null()
            }
            "putRet" => {
                w.put_ret();
                ok_null()
            }
            "putRetReg" => match arg_reg(&args, "reg").and_then(|r| {
                w.put_ret_reg(r).map_err(|e| e.to_string())
            }) {
                Ok(()) => ok_null(),
                Err(e) => err(e),
            },
            "putBrkImm" => {
                let imm = match arg_u64(&args, "imm") {
                    Ok(i) => i as u16,
                    Err(e) => return err(e),
                };
                w.put_brk_imm(imm);
                ok_null()
            }
            "putInstruction" => {
                let insn = match arg_u64(&args, "insn") {
                    Ok(i) => i as u32,
                    Err(e) => return err(e),
                };
                w.put_instruction(insn);
                ok_null()
            }
            "putBytes" => {
                let arr = match args.get("data").and_then(|x| x.as_array()) {
                    Some(a) => a,
                    None => return err("putBytes needs data:number[]"),
                };
                let mut bytes = Vec::with_capacity(arr.len());
                for v in arr {
                    let b = v
                        .as_u64()
                        .or_else(|| v.as_f64().map(|f| f as u64))
                        .unwrap_or(0) as u8;
                    bytes.push(b);
                }
                w.put_bytes(&bytes);
                ok_null()
            }
            "putBranchAddress" => match arg_u64(&args, "address") {
                Ok(a) => {
                    w.put_branch_address(a);
                    ok_null()
                }
                Err(e) => err(e),
            },
            "canBranchDirectlyBetween" => {
                let from = match arg_u64(&args, "from") {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };
                let to = match arg_u64(&args, "to") {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };
                ok_val(json!(Arm64Writer::can_branch_directly_between(from, to)))
            }
            "putBImm" => match arg_u64(&args, "address").and_then(|a| {
                w.put_b_imm(a).map_err(|e| e.to_string())
            }) {
                Ok(()) => ok_null(),
                Err(e) => err(e),
            },
            "putBlImm" => match arg_u64(&args, "address").and_then(|a| {
                w.put_bl_imm(a).map_err(|e| e.to_string())
            }) {
                Ok(()) => ok_null(),
                Err(e) => err(e),
            },
            "putBLabel" => match arg_str(&args, "labelId") {
                Ok(l) => {
                    w.put_b_label(&l);
                    ok_null()
                }
                Err(e) => err(e),
            },
            "putBlLabel" => match arg_str(&args, "labelId") {
                Ok(l) => {
                    w.put_bl_label(&l);
                    ok_null()
                }
                Err(e) => err(e),
            },
            "putBCondLabel" => {
                let cc = match arg_str(&args, "cc").and_then(|s| {
                    parse_cond(&s).map_err(|e| e.to_string())
                }) {
                    Ok(c) => c,
                    Err(e) => return err(e),
                };
                let lab = match arg_str(&args, "labelId") {
                    Ok(s) => s,
                    Err(e) => return err(e),
                };
                w.put_b_cond_label(cc, &lab);
                ok_null()
            }
            "putBrReg" | "putBrRegNoAuth" => match arg_reg(&args, "reg").and_then(|r| {
                w.put_br_reg(r).map_err(|e| e.to_string())
            }) {
                Ok(()) => ok_null(),
                Err(e) => err(e),
            },
            "putBlrReg" | "putBlrRegNoAuth" => match arg_reg(&args, "reg").and_then(|r| {
                w.put_blr_reg(r).map_err(|e| e.to_string())
            }) {
                Ok(()) => ok_null(),
                Err(e) => err(e),
            },
            "putCbzRegImm" | "putCbnzRegImm" => {
                let nonzero = op == "putCbnzRegImm";
                match arg_reg(&args, "reg").and_then(|r| {
                    let t = arg_u64(&args, "target")?;
                    w.put_cbz_reg_imm(r, t, nonzero).map_err(|e| e.to_string())
                }) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e),
                }
            }
            "putCbzRegLabel" | "putCbnzRegLabel" => {
                let nonzero = op == "putCbnzRegLabel";
                match arg_reg(&args, "reg").and_then(|r| {
                    let l = arg_str(&args, "labelId")?;
                    w.put_cbz_reg_label(r, &l, nonzero);
                    Ok(())
                }) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e),
                }
            }
            "putTbzRegImmImm" | "putTbnzRegImmImm" => {
                let nonzero = op == "putTbnzRegImmImm";
                match arg_reg(&args, "reg").and_then(|r| {
                    let bit = arg_u64(&args, "bit")? as u8;
                    let t = arg_u64(&args, "target")?;
                    w.put_tbz_reg_imm_imm(r, bit, t, nonzero)
                        .map_err(|e| e.to_string())
                }) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e),
                }
            }
            "putTbzRegImmLabel" | "putTbnzRegImmLabel" => {
                let nonzero = op == "putTbnzRegImmLabel";
                match arg_reg(&args, "reg").and_then(|r| {
                    let bit = arg_u64(&args, "bit")? as u8;
                    let l = arg_str(&args, "labelId")?;
                    w.put_tbz_reg_imm_label(r, bit, &l, nonzero);
                    Ok(())
                }) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e),
                }
            }
            "putPushRegReg" => match (arg_reg(&args, "regA"), arg_reg(&args, "regB")) {
                (Ok(a), Ok(b)) => match w.put_push_reg_reg(a, b) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putPopRegReg" => match (arg_reg(&args, "regA"), arg_reg(&args, "regB")) {
                (Ok(a), Ok(b)) => match w.put_pop_reg_reg(a, b) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putLdrRegAddress" => match (arg_reg(&args, "reg"), arg_u64(&args, "address")) {
                (Ok(r), Ok(a)) => match w.put_ldr_reg_address(r, a) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putLdrRegU32" => match (arg_reg(&args, "reg"), arg_u64(&args, "val")) {
                (Ok(r), Ok(v)) => match w.put_ldr_reg_u32(r, v as u32) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putLdrRegU64" => match (arg_reg(&args, "reg"), arg_u64(&args, "val")) {
                (Ok(r), Ok(v)) => match w.put_ldr_reg_u64(r, v) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putLdrRegReg" => match (arg_reg(&args, "dstReg"), arg_reg(&args, "srcReg")) {
                (Ok(d), Ok(s)) => match w.put_ldr_reg_reg(d, s) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putLdrRegRegOffset" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "srcReg"),
                    arg_i64(&args, "srcOffset"),
                ) {
                    (Ok(d), Ok(s), Ok(off)) => {
                        match w.put_ldr_reg_reg_offset(d, s, off as i32, IndexMode::SignedOffset)
                        {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putLdrRegRegOffsetMode" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "srcReg"),
                    arg_i64(&args, "srcOffset"),
                    arg_mode(&args, "mode"),
                ) {
                    (Ok(d), Ok(s), Ok(off), Ok(mode)) => {
                        match w.put_ldr_reg_reg_offset(d, s, off as i32, mode) {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _, _)
                    | (_, Err(e), _, _)
                    | (_, _, Err(e), _)
                    | (_, _, _, Err(e)) => err(e),
                }
            }
            "putStrRegReg" => match (arg_reg(&args, "srcReg"), arg_reg(&args, "dstReg")) {
                (Ok(s), Ok(d)) => match w.put_str_reg_reg(s, d) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putStrRegRegOffset" => {
                match (
                    arg_reg(&args, "srcReg"),
                    arg_reg(&args, "dstReg"),
                    arg_i64(&args, "dstOffset"),
                ) {
                    (Ok(s), Ok(d), Ok(off)) => {
                        match w.put_str_reg_reg_offset(s, d, off as i32, IndexMode::SignedOffset)
                        {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putStrRegRegOffsetMode" => {
                match (
                    arg_reg(&args, "srcReg"),
                    arg_reg(&args, "dstReg"),
                    arg_i64(&args, "dstOffset"),
                    arg_mode(&args, "mode"),
                ) {
                    (Ok(s), Ok(d), Ok(off), Ok(mode)) => {
                        match w.put_str_reg_reg_offset(s, d, off as i32, mode) {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _, _)
                    | (_, Err(e), _, _)
                    | (_, _, Err(e), _)
                    | (_, _, _, Err(e)) => err(e),
                }
            }
            "putStpRegRegRegOffset" => {
                match (
                    arg_reg(&args, "regA"),
                    arg_reg(&args, "regB"),
                    arg_reg(&args, "regDst"),
                    arg_i64(&args, "dstOffset"),
                    arg_mode(&args, "mode"),
                ) {
                    (Ok(a), Ok(b), Ok(d), Ok(off), Ok(mode)) => {
                        match w.put_stp_reg_reg_reg_offset(a, b, d, off as i32, mode) {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _, _, _)
                    | (_, Err(e), _, _, _)
                    | (_, _, Err(e), _, _)
                    | (_, _, _, Err(e), _)
                    | (_, _, _, _, Err(e)) => err(e),
                }
            }
            "putMovRegReg" => match (arg_reg(&args, "dstReg"), arg_reg(&args, "srcReg")) {
                (Ok(d), Ok(s)) => match w.put_mov_reg_reg(d, s) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putMovkRegImm" => {
                match (
                    arg_reg(&args, "reg"),
                    arg_u64(&args, "imm"),
                    arg_u64(&args, "shift"),
                ) {
                    (Ok(r), Ok(imm), Ok(shift)) => {
                        match w.put_movk_reg_imm(r, imm as u16, shift as u8) {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putAddRegRegImm" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "leftReg"),
                    arg_u64(&args, "rightValue"),
                ) {
                    (Ok(d), Ok(l), Ok(imm)) => {
                        match w.put_add_reg_reg_imm(d, l, imm as u32) {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putAddRegRegReg" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "leftReg"),
                    arg_reg(&args, "rightReg"),
                ) {
                    (Ok(d), Ok(a), Ok(b)) => match w.put_add_reg_reg_reg(d, a, b) {
                        Ok(()) => ok_null(),
                        Err(e) => err(e.to_string()),
                    },
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putSubRegRegImm" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "leftReg"),
                    arg_u64(&args, "rightValue"),
                ) {
                    (Ok(d), Ok(l), Ok(imm)) => {
                        match w.put_sub_reg_reg_imm(d, l, imm as u32) {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putSubRegRegReg" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "leftReg"),
                    arg_reg(&args, "rightReg"),
                ) {
                    (Ok(d), Ok(a), Ok(b)) => match w.put_sub_reg_reg_reg(d, a, b) {
                        Ok(()) => ok_null(),
                        Err(e) => err(e.to_string()),
                    },
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putAndRegRegImm" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "leftReg"),
                    arg_u64(&args, "rightValue"),
                ) {
                    (Ok(d), Ok(l), Ok(imm)) => match w.put_and_reg_reg_imm(d, l, imm) {
                        Ok(()) => ok_null(),
                        Err(e) => err(e.to_string()),
                    },
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putEorRegRegReg" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "leftReg"),
                    arg_reg(&args, "rightReg"),
                ) {
                    (Ok(d), Ok(a), Ok(b)) => match w.put_eor_reg_reg_reg(d, a, b) {
                        Ok(()) => ok_null(),
                        Err(e) => err(e.to_string()),
                    },
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putLslRegImm" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "srcReg"),
                    arg_u64(&args, "shift"),
                ) {
                    (Ok(d), Ok(s), Ok(sh)) => match w.put_lsl_reg_imm(d, s, sh as u8) {
                        Ok(()) => ok_null(),
                        Err(e) => err(e.to_string()),
                    },
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putCmpRegReg" => match (arg_reg(&args, "regA"), arg_reg(&args, "regB")) {
                (Ok(a), Ok(b)) => match w.put_cmp_reg_reg(a, b) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putAdrpRegAddress" => match (arg_reg(&args, "reg"), arg_u64(&args, "address")) {
                (Ok(r), Ok(a)) => match w.put_adrp_reg_address(r, a) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putPushAllXRegisters" => match w.put_push_all_x_registers() {
                Ok(()) => ok_null(),
                Err(e) => err(e.to_string()),
            },
            "putPopAllXRegisters" => match w.put_pop_all_x_registers() {
                Ok(()) => ok_null(),
                Err(e) => err(e.to_string()),
            },
            "putPushAllQRegisters" => match w.put_push_all_q_registers() {
                Ok(()) => ok_null(),
                Err(e) => err(e.to_string()),
            },
            "putPopAllQRegisters" => match w.put_pop_all_q_registers() {
                Ok(()) => ok_null(),
                Err(e) => err(e.to_string()),
            },
            "putLdrRegU32Ptr" => match (arg_reg(&args, "reg"), arg_u64(&args, "srcAddress")) {
                (Ok(r), Ok(a)) => match w.put_ldr_reg_u32_ptr(r, a) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putLdrRegU64Ptr" => match (arg_reg(&args, "reg"), arg_u64(&args, "srcAddress")) {
                (Ok(r), Ok(a)) => match w.put_ldr_reg_u64_ptr(r, a) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putLdrRegRef" => match arg_reg(&args, "reg") {
                Ok(r) => match w.put_ldr_reg_ref(r) {
                    Ok(reff) => ok_val(json!(reff)),
                    Err(e) => err(e.to_string()),
                },
                Err(e) => err(e),
            },
            "putLdrRegValue" => match (arg_u64(&args, "ref"), arg_u64(&args, "value")) {
                (Ok(r), Ok(v)) => match w.put_ldr_reg_value(r as u32, v) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putLdrswRegRegOffset" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "srcReg"),
                    arg_u64(&args, "srcOffset"),
                ) {
                    (Ok(d), Ok(s), Ok(off)) => {
                        match w.put_ldrsw_reg_reg_offset(d, s, off as u32) {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putLdpRegRegRegOffset" => {
                match (
                    arg_reg(&args, "regA"),
                    arg_reg(&args, "regB"),
                    arg_reg(&args, "regSrc"),
                    arg_i64(&args, "srcOffset"),
                    arg_mode(&args, "mode"),
                ) {
                    (Ok(a), Ok(b), Ok(s), Ok(off), Ok(mode)) => {
                        match w.put_ldp_reg_reg_reg_offset(a, b, s, off as i32, mode) {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _, _, _)
                    | (_, Err(e), _, _, _)
                    | (_, _, Err(e), _, _)
                    | (_, _, _, Err(e), _)
                    | (_, _, _, _, Err(e)) => err(e),
                }
            }
            "putMovRegNzcv" => match arg_reg(&args, "reg") {
                Ok(r) => match w.put_mov_reg_nzcv(r) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                Err(e) => err(e),
            },
            "putMovNzcvReg" => match arg_reg(&args, "reg") {
                Ok(r) => match w.put_mov_nzcv_reg(r) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                Err(e) => err(e),
            },
            "putUxtwRegReg" => match (arg_reg(&args, "dstReg"), arg_reg(&args, "srcReg")) {
                (Ok(d), Ok(s)) => match w.put_uxtw_reg_reg(d, s) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putUbfm" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "srcReg"),
                    arg_u64(&args, "imms"),
                    arg_u64(&args, "immr"),
                ) {
                    (Ok(d), Ok(s), Ok(imms), Ok(immr)) => {
                        match w.put_ubfm(d, s, immr as u8, imms as u8) {
                            Ok(()) => ok_null(),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    (Err(e), _, _, _)
                    | (_, Err(e), _, _)
                    | (_, _, Err(e), _)
                    | (_, _, _, Err(e)) => err(e),
                }
            }
            "putLsrRegImm" => {
                match (
                    arg_reg(&args, "dstReg"),
                    arg_reg(&args, "srcReg"),
                    arg_u64(&args, "shift"),
                ) {
                    (Ok(d), Ok(s), Ok(sh)) => match w.put_lsr_reg_imm(d, s, sh as u8) {
                        Ok(()) => ok_null(),
                        Err(e) => err(e.to_string()),
                    },
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
                }
            }
            "putTstRegImm" => match (arg_reg(&args, "reg"), arg_u64(&args, "immValue")) {
                (Ok(r), Ok(imm)) => match w.put_tst_reg_imm(r, imm) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putXpaciReg" => match arg_reg(&args, "reg") {
                Ok(r) => match w.put_xpaci_reg(r) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                Err(e) => err(e),
            },
            "putPaciaRegReg" => match (arg_reg(&args, "dstReg"), arg_reg(&args, "modReg")) {
                (Ok(d), Ok(m)) => match w.put_pacia_reg_reg(d, m) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putMrs" => match (arg_reg(&args, "dstReg"), arg_u64(&args, "systemReg")) {
                (Ok(d), Ok(sys)) => match w.put_mrs(d, sys as u16) {
                    Ok(()) => ok_null(),
                    Err(e) => err(e.to_string()),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            },
            "putCallAddressWithArguments" => {
                let func = match arg_u64(&args, "func") {
                    Ok(f) => f,
                    Err(e) => return err(e),
                };
                match parse_call_args(&args) {
                    Ok(call_args) => match w.put_call_address_with_arguments(func, &call_args) {
                        Ok(()) => ok_null(),
                        Err(e) => err(e.to_string()),
                    },
                    Err(e) => err(e),
                }
            }
            "putCallRegWithArguments" => {
                let reg = match arg_reg(&args, "reg") {
                    Ok(r) => r,
                    Err(e) => return err(e),
                };
                match parse_call_args(&args) {
                    Ok(call_args) => match w.put_call_reg_with_arguments(reg, &call_args) {
                        Ok(()) => ok_null(),
                        Err(e) => err(e.to_string()),
                    },
                    Err(e) => err(e),
                }
            }
            "sign" => match arg_u64(&args, "value") {
                Ok(v) => ok_val(json!(w.sign(v))),
                Err(e) => err(e),
            },
            other => err(format!("unknown Arm64Writer op: {other}")),
        }
    })
}

fn parse_call_args(args: &Value) -> Result<Vec<CallArg>, String> {
    let arr = args
        .get("args")
        .and_then(|x| x.as_array())
        .ok_or_else(|| "call needs args:[]".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        if let Some(s) = v.as_str() {
            let r = Reg::parse(s).map_err(|e| e.to_string())?;
            out.push(CallArg::Register(r));
        } else if let Some(n) = v
            .as_u64()
            .or_else(|| v.as_f64().map(|f| f as u64))
            .or_else(|| {
                v.as_object().and_then(|o| {
                    o.get("address")
                        .and_then(|a| a.as_u64().or_else(|| a.as_f64().map(|f| f as u64)))
                })
            })
        {
            out.push(CallArg::Address(n));
        } else {
            return Err(format!("bad call arg: {v}"));
        }
    }
    Ok(out)
}

pub fn relocator_op(id: u32, writer_id: u32, op: &str, args_json: &str) -> String {
    let args: Value = if args_json.is_empty() {
        json!({})
    } else {
        match serde_json::from_str(args_json) {
            Ok(v) => v,
            Err(e) => return err(format!("bad args json: {e}")),
        }
    };

    if op == "dispose" {
        with_relocs(|m| {
            m.remove(&id);
        });
        return ok_null();
    }

    if op == "reset" {
        let input = match arg_u64(&args, "inputCode") {
            Ok(a) => a,
            Err(e) => return err(e),
        };
        let base = with_writers(|m| {
            m.get(&writer_id)
                .map(|w| w.base())
                .ok_or_else(|| format!("bad writer id {writer_id}"))
        });
        let base = match base {
            Ok(b) => b,
            Err(e) => return err(e),
        };
        return with_relocs(|m| {
            let Some(r) = m.get_mut(&id) else {
                return err(format!("bad relocator id {id}"));
            };
            r.reset(input, base);
            ok_null()
        });
    }

    if op == "eob" || op == "eoi" || op == "input" || op == "peekNextWriteSource" {
        return with_relocs(|m| {
            let Some(r) = m.get(&id) else {
                return err(format!("bad relocator id {id}"));
            };
            match op {
                "eob" => ok_val(json!(r.eob())),
                "eoi" => ok_val(json!(r.eoi())),
                "input" => ok_val(json!(r.input().map(|i| i.addr))),
                "peekNextWriteSource" => ok_val(json!(r.peek_next_write_source())),
                _ => unreachable!(),
            }
        });
    }

    if op == "readOne" || op == "skipOne" {
        return with_relocs(|m| {
            let Some(r) = m.get_mut(&id) else {
                return err(format!("bad relocator id {id}"));
            };
            match op {
                "readOne" => match r.read_one() {
                    Ok(n) => ok_val(json!(n)),
                    Err(e) => err(reloc_err(e)),
                },
                "skipOne" => match r.skip_one() {
                    Ok(b) => ok_val(json!(b)),
                    Err(e) => err(reloc_err(e)),
                },
                _ => unreachable!(),
            }
        });
    }

    // Ops that need both relocator + writer
    with_writers(|wm| {
        let Some(w) = wm.get_mut(&writer_id) else {
            return err(format!("bad writer id {writer_id}"));
        };
        with_relocs(|rm| {
            let Some(r) = rm.get_mut(&id) else {
                return err(format!("bad relocator id {id}"));
            };
            match op {
                "writeOne" => match r.write_one(w) {
                    Ok(b) => ok_val(json!(b)),
                    Err(e) => err(reloc_err(e)),
                },
                "writeAll" => match r.write_all(w) {
                    Ok(()) => ok_null(),
                    Err(e) => err(reloc_err(e)),
                },
                "peekNextWriteInsn" => {
                    // Lightweight: return raw word + address
                    match r.peek_next_write_insn() {
                        Some(i) => ok_val(json!({"address": i.addr, "raw": i.raw})),
                        None => ok_val(Value::Null),
                    }
                }
                other => err(format!("unknown Arm64Relocator op: {other}")),
            }
        })
    })
}

fn reloc_err(e: RelocError) -> String {
    e.to_string()
}
