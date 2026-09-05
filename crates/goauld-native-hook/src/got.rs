//! GOT/PLT hooking for `Interceptor.replace` at library boundaries (§4.6).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GotError {
    #[error("ELF parse: {0}")]
    Elf(String),
    #[error("symbol not found: {0}")]
    NotFound(String),
    #[error("mprotect failed")]
    Mprotect,
}

/// Resolve a symbol's GOT slot address by walking `.dynamic` / `.rela.plt`.
///
/// `base` is the module load bias; `dyn_bytes` is a view of the mapped ELF
/// starting at `base` (or a copy thereof). Returns the absolute address of the
/// 8-byte GOT entry.
pub fn find_got_slot(base: u64, image: &[u8], symbol: &str) -> Result<u64, GotError> {
    let e_ident = image.get(0..16).ok_or_else(|| GotError::Elf("too short".into()))?;
    if e_ident[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(GotError::Elf("bad magic".into()));
    }
    if e_ident[4] != 2 {
        return Err(GotError::Elf("not ELF64".into()));
    }
    // e_phoff @ 32, e_phentsize @ 54, e_phnum @ 56
    let phoff = u64::from_le_bytes(image[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(image[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(image[56..58].try_into().unwrap()) as usize;

    let mut dyn_vaddr = None;
    let mut dyn_filesz = 0usize;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(image[off..off + 4].try_into().unwrap());
        if p_type == 2 {
            // PT_DYNAMIC
            let p_vaddr = u64::from_le_bytes(image[off + 16..off + 24].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(image[off + 32..off + 40].try_into().unwrap());
            dyn_vaddr = Some(p_vaddr);
            dyn_filesz = p_filesz as usize;
            break;
        }
    }
    let dyn_vaddr = dyn_vaddr.ok_or_else(|| GotError::Elf("no PT_DYNAMIC".into()))?;
    // Prefer file offset via program headers: find segment containing dyn_vaddr.
    let dyn_off = vaddr_to_offset(image, phoff, phentsize, phnum, dyn_vaddr)
        .ok_or_else(|| GotError::Elf("dyn vaddr unmapped".into()))?;

    let mut pltrel = None;
    let mut pltrelsz = 0u64;
    let mut symtab = None;
    let mut strtab = None;
    let mut strsz = 0u64;
    let mut rela_ent = 24u64; // Elf64_Rela

    let mut pos = dyn_off;
    let end = dyn_off + dyn_filesz;
    while pos + 16 <= end && pos + 16 <= image.len() {
        let tag = i64::from_le_bytes(image[pos..pos + 8].try_into().unwrap());
        let val = u64::from_le_bytes(image[pos + 8..pos + 16].try_into().unwrap());
        pos += 16;
        match tag {
            0 => break, // DT_NULL
            23 => pltrel = Some(val),      // DT_JMPREL
            2 => pltrelsz = val,           // DT_PLTRELSZ
            6 => symtab = Some(val),       // DT_SYMTAB
            5 => strtab = Some(val),       // DT_STRTAB
            10 => strsz = val,             // DT_STRSZ
            9 => rela_ent = val,           // DT_RELAENT
            _ => {}
        }
    }

    let pltrel = pltrel.ok_or_else(|| GotError::Elf("no DT_JMPREL".into()))?;
    let symtab = symtab.ok_or_else(|| GotError::Elf("no DT_SYMTAB".into()))?;
    let strtab = strtab.ok_or_else(|| GotError::Elf("no DT_STRTAB".into()))?;

    let plt_off = vaddr_to_offset(image, phoff, phentsize, phnum, pltrel)
        .ok_or_else(|| GotError::Elf("JMPREL unmapped".into()))?;
    let sym_off = vaddr_to_offset(image, phoff, phentsize, phnum, symtab)
        .ok_or_else(|| GotError::Elf("SYMTAB unmapped".into()))?;
    let str_off = vaddr_to_offset(image, phoff, phentsize, phnum, strtab)
        .ok_or_else(|| GotError::Elf("STRTAB unmapped".into()))?;

    let n = (pltrelsz / rela_ent) as usize;
    for i in 0..n {
        let re = plt_off + i * rela_ent as usize;
        if re + 24 > image.len() {
            break;
        }
        let r_offset = u64::from_le_bytes(image[re..re + 8].try_into().unwrap());
        let r_info = u64::from_le_bytes(image[re + 8..re + 16].try_into().unwrap());
        let sym_idx = (r_info >> 32) as usize;
        let sym = sym_off + sym_idx * 24; // Elf64_Sym
        if sym + 24 > image.len() {
            continue;
        }
        let st_name = u32::from_le_bytes(image[sym..sym + 4].try_into().unwrap()) as usize;
        let name = read_cstr(image, str_off + st_name, strsz as usize);
        if name == symbol {
            return Ok(base + r_offset);
        }
    }
    let _ = strsz;
    Err(GotError::NotFound(symbol.into()))
}

/// Overwrite an 8-byte GOT entry with `replacement`. Temporarily makes the page writable.
///
/// # Safety
/// `got_addr` must point at a live GOT slot in this process.
pub unsafe fn replace_got(got_addr: u64, replacement: u64) -> Result<u64, GotError> {
    let page = (got_addr as usize) & !(page_size() - 1);
    let rc = libc::mprotect(
        page as *mut _,
        page_size(),
        libc::PROT_READ | libc::PROT_WRITE,
    );
    if rc != 0 {
        return Err(GotError::Mprotect);
    }
    let slot = got_addr as *mut u64;
    let old = slot.read();
    slot.write(replacement);
    let _ = libc::mprotect(page as *mut _, page_size(), libc::PROT_READ);
    Ok(old)
}

fn vaddr_to_offset(
    image: &[u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    vaddr: u64,
) -> Option<usize> {
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        if off + 56 > image.len() {
            return None;
        }
        let p_type = u32::from_le_bytes(image[off..off + 4].try_into().unwrap());
        if p_type != 1 {
            // PT_LOAD
            continue;
        }
        let p_offset = u64::from_le_bytes(image[off + 8..off + 16].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(image[off + 16..off + 24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(image[off + 32..off + 40].try_into().unwrap());
        if vaddr >= p_vaddr && vaddr < p_vaddr + p_filesz {
            return Some((p_offset + (vaddr - p_vaddr)) as usize);
        }
    }
    None
}

fn read_cstr(image: &[u8], start: usize, max: usize) -> String {
    let end = (start + max).min(image.len());
    let slice = &image[start..end];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul]).into_owned()
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }.max(4096)
}
