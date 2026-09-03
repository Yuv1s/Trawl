//! ELF binaries, read for what the format's own tables declare about
//! themselves.
//!
//! This is the same kind of reading [`crate::pdf`] does, pointed at an
//! executable: the header, the section table, the program headers, and the
//! dynamic symbol table, each walked and reported as found. Nothing here
//! decodes an instruction. A disassembler answers what the code does, which
//! is a different question needing a different tool; what the tables say is
//! already most of a triage, and unlike a decompiler's output every line of
//! it is a field at a byte offset rather than an inference.
//!
//! The three things a challenge binary is usually asked about are all
//! declarations rather than deductions. Whether the stack is executable is a
//! flag on a `PT_GNU_STACK` header. Whether the binary loads at a fixed
//! address is its `e_type`. Whether the relocation table is made read-only
//! before `main` runs is a `PT_GNU_RELRO` header plus a bit in `.dynamic`.
//! Each is read here and each is reported with the distinction the format
//! actually supports: a header that is absent is reported as absent, not as
//! a protection that is off, because those are different facts.

use crate::binary::{Binary, Guard, Section, Segment, Symbol, MAX_SYMBOLS};

/// Reads numbers out of an ELF the way its own header says to: in the
/// endianness it declares, and four or eight bytes wide depending on its
/// class. Every table in the format changes shape on those two bits, so
/// they are settled once here rather than at each read.
#[derive(Clone, Copy)]
struct Reader<'a> {
    data: &'a [u8],
    little: bool,
    wide: bool,
}

impl Reader<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        let raw: [u8; 2] = self.data.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(if self.little {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        })
    }

    fn u32(&self, at: usize) -> Option<u32> {
        let raw: [u8; 4] = self.data.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if self.little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    }

    fn u64(&self, at: usize) -> Option<u64> {
        let raw: [u8; 8] = self.data.get(at..at.checked_add(8)?)?.try_into().ok()?;
        Some(if self.little {
            u64::from_le_bytes(raw)
        } else {
            u64::from_be_bytes(raw)
        })
    }

    /// An address-sized number: eight bytes in a 64-bit file, four in a
    /// 32-bit one. This single difference runs through every table here.
    fn addr(&self, at: usize) -> Option<u64> {
        if self.wide {
            self.u64(at)
        } else {
            self.u32(at).map(u64::from)
        }
    }

    fn word(&self) -> usize {
        if self.wide { 8 } else { 4 }
    }
}

/// A null-terminated name out of a string table, held to that table's own
/// bounds so a corrupt offset reads nothing rather than the rest of the file.
fn string_at(data: &[u8], table: (usize, usize), offset: u32) -> Option<String> {
    let (start, size) = table;
    let end = start.checked_add(size)?;
    let at = start.checked_add(offset as usize)?;
    let slice = data.get(at..end)?;
    let stop = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Some(crate::json::latin1(&slice[..stop]))
}

fn machine_name(value: u16) -> &'static str {
    match value {
        2 => "SPARC",
        3 => "x86",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC 64",
        22 => "S/390",
        40 => "ARM",
        42 => "SuperH",
        62 => "x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "an architecture this does not name",
    }
}

fn section_kind(value: u32) -> &'static str {
    match value {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        16 => "PREINIT_ARRAY",
        0x6fff_fff6 => "GNU_HASH",
        0x6fff_fffd => "VERDEF",
        0x6fff_fffe => "VERNEED",
        0x6fff_ffff => "VERSYM",
        _ => "other",
    }
}

fn segment_kind(value: u32) -> &'static str {
    match value {
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        6 => "PHDR",
        7 => "TLS",
        0x6474_e550 => "GNU_EH_FRAME",
        0x6474_e551 => "GNU_STACK",
        0x6474_e552 => "GNU_RELRO",
        0x6474_e553 => "GNU_PROPERTY",
        _ => "other",
    }
}

fn symbol_kind(info: u8) -> &'static str {
    match info & 0xf {
        1 => "object",
        2 => "function",
        3 => "section",
        4 => "file",
        6 => "thread-local",
        10 => "ifunc",
        _ => "untyped",
    }
}

/// `r`, `w` and `x` for whichever of read, write and execute a header
/// carries, in a fixed order so two rows line up when read down a column.
fn permissions(flags: u32) -> String {
    let mut out = String::new();
    out.push(if flags & 4 != 0 { 'r' } else { '-' });
    out.push(if flags & 2 != 0 { 'w' } else { '-' });
    out.push(if flags & 1 != 0 { 'x' } else { '-' });
    out
}

/// The section-header flags worth naming, which are not the same bits as a
/// program header's: here `alloc` means the section occupies memory at run
/// time at all.
fn section_flags(flags: u64) -> String {
    let mut out = Vec::new();
    if flags & 0x2 != 0 {
        out.push("alloc");
    }
    if flags & 0x1 != 0 {
        out.push("write");
    }
    if flags & 0x4 != 0 {
        out.push("execute");
    }
    out.join(", ")
}

const SHN_UNDEF: u16 = 0;
const STB_LOCAL: u8 = 0;

pub fn read(data: &[u8]) -> Option<Binary> {
    if !data.starts_with(b"\x7fELF") {
        return None;
    }

    let wide = match data.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little = match data.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };

    let r = Reader { data, little, wide };

    let kind = match r.u16(16)? {
        1 => "relocatable object",
        2 => "executable",
        3 => "shared object",
        4 => "core dump",
        _ => "unknown",
    };
    let machine = machine_name(r.u16(18)?);
    let entry = r.addr(24)?;

    // Past the entry point the header's own field offsets move, because the
    // three addresses in the middle of it are the width the class declared.
    let (phoff, shoff, after) = if wide {
        (r.addr(32)?, r.addr(40)?, 48)
    } else {
        (r.addr(28)?, r.addr(32)?, 36)
    };
    let phentsize = r.u16(after + 6)? as usize;
    let phnum = r.u16(after + 8)? as usize;
    let shentsize = r.u16(after + 10)? as usize;
    let shnum = r.u16(after + 12)? as usize;
    let shstrndx = r.u16(after + 14)? as usize;

    let raw_sections = read_section_headers(&r, shoff as usize, shentsize, shnum);
    let shstrtab = raw_sections
        .get(shstrndx)
        .map(|s| (s.offset as usize, s.size as usize));

    let sections: Vec<Section> = raw_sections
        .iter()
        .map(|s| Section {
            name: shstrtab
                .and_then(|table| string_at(data, table, s.name_offset))
                .unwrap_or_default(),
            kind: section_kind(s.kind).to_string(),
            address: s.address,
            offset: s.offset,
            size: s.size,
            flags: section_flags(s.flags),
        })
        .collect();

    let segments = read_program_headers(&r, phoff as usize, phentsize, phnum);

    let interpreter = segments
        .iter()
        .find(|s| s.kind == "INTERP")
        .and_then(|s| {
            let start = s.offset as usize;
            let end = start.checked_add(s.file_size as usize)?;
            let slice = data.get(start..end)?;
            let stop = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
            Some(crate::json::latin1(&slice[..stop]))
        })
        .filter(|name| !name.is_empty());

    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut import_count = 0usize;
    let mut export_count = 0usize;
    let mut canary = false;
    let mut fortify = false;

    // Both symbol tables are walked, not just the dynamic one: a statically
    // linked binary has no `.dynsym` at all, and its guard symbols live in
    // `.symtab` instead.
    for table in raw_sections.iter().filter(|s| s.kind == 2 || s.kind == 11) {
        let strings = raw_sections
            .get(table.link as usize)
            .map(|s| (s.offset as usize, s.size as usize));
        let Some(strings) = strings else { continue };

        let stride = if wide { 24 } else { 16 };
        let count = (table.size as usize) / stride.max(1);

        for index in 0..count {
            let at = (table.offset as usize).saturating_add(index * stride);
            let Some(name_offset) = r.u32(at) else { break };

            let (info, shndx, value) = if wide {
                let Some(info) = data.get(at + 4).copied() else { break };
                let Some(shndx) = r.u16(at + 6) else { break };
                let Some(value) = r.u64(at + 8) else { break };
                (info, shndx, value)
            } else {
                let Some(value) = r.u32(at + 4) else { break };
                let Some(info) = data.get(at + 12).copied() else { break };
                let Some(shndx) = r.u16(at + 14) else { break };
                (info, shndx, u64::from(value))
            };

            let Some(name) = string_at(data, strings, name_offset) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }

            if name == "__stack_chk_fail" {
                canary = true;
            }
            if name.starts_with("__") && name.ends_with("_chk") {
                fortify = true;
            }

            // A dynamic table is what the loader resolves, so only it says
            // what is genuinely imported or exported. `.symtab` is walked
            // for the guard names above and nothing else.
            if table.kind != 11 {
                continue;
            }

            let symbol = Symbol {
                name,
                kind: symbol_kind(info),
                address: value,
                from: None,
            };

            if shndx == SHN_UNDEF {
                import_count += 1;
                if imports.len() < MAX_SYMBOLS {
                    imports.push(symbol);
                }
            } else if info >> 4 != STB_LOCAL {
                export_count += 1;
                if exports.len() < MAX_SYMBOLS {
                    exports.push(symbol);
                }
            }
        }
    }

    let (needed, runpath, bind_now) = read_dynamic(&r, &raw_sections);

    let nx = match segments.iter().find(|s| s.kind == "GNU_STACK") {
        Some(stack) if stack.permissions.contains('x') => Guard::Off,
        Some(_) => Guard::On,
        None => Guard::Undeclared,
    };

    let relro = match segments.iter().any(|s| s.kind == "GNU_RELRO") {
        true if bind_now => "full",
        true => "partial",
        false => "none",
    };

    let pie = match kind {
        "shared object" if interpreter.is_some() => "yes",
        "shared object" => "shared object",
        _ => "no",
    };

    let stripped = !raw_sections.iter().any(|s| s.kind == 2);

    Some(Binary {
        format: "ELF",
        class: if wide { "64-bit" } else { "32-bit" },
        endianness: if little { "little" } else { "big" },
        machine,
        kind,
        entry,
        interpreter,
        runpath,
        subsystem: None,
        pdb_path: None,
        stripped,
        nx,
        pie,
        relro: Some(relro),
        canary,
        fortify: Some(fortify),
        cfg: None,
        needed,
        sections,
        segments,
        imports,
        exports,
        import_count,
        export_count,
    })
}

/// A section header as the table holds it, before its name is resolved: the
/// string table that names sections is itself a section, so the table has to
/// be read once before any of it can be labelled.
struct RawSection {
    name_offset: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
}

fn read_section_headers(
    r: &Reader,
    shoff: usize,
    shentsize: usize,
    shnum: usize,
) -> Vec<RawSection> {
    let (f_addr, f_offset, f_size, f_link) = if r.wide {
        (16, 24, 32, 40)
    } else {
        (12, 16, 20, 24)
    };

    (0..shnum)
        .filter_map(|index| {
            let at = shoff.checked_add(index.checked_mul(shentsize)?)?;
            Some(RawSection {
                name_offset: r.u32(at)?,
                kind: r.u32(at + 4)?,
                flags: r.addr(at + 8)?,
                address: r.addr(at + f_addr)?,
                offset: r.addr(at + f_offset)?,
                size: r.addr(at + f_size)?,
                link: r.u32(at + f_link)?,
            })
        })
        .collect()
}

fn read_program_headers(
    r: &Reader,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
) -> Vec<Segment> {
    (0..phnum)
        .filter_map(|index| {
            let at = phoff.checked_add(index.checked_mul(phentsize)?)?;
            // The flags word sits right after the type in a 64-bit header
            // and all the way past the sizes in a 32-bit one, which is the
            // one place the two layouts disagree on order rather than width.
            let (flags, offset, address, file_size, memory_size) = if r.wide {
                (r.u32(at + 4)?, r.u64(at + 8)?, r.u64(at + 16)?, r.u64(at + 32)?, r.u64(at + 40)?)
            } else {
                (
                    r.u32(at + 24)?,
                    u64::from(r.u32(at + 4)?),
                    u64::from(r.u32(at + 8)?),
                    u64::from(r.u32(at + 16)?),
                    u64::from(r.u32(at + 20)?),
                )
            };

            Some(Segment {
                kind: segment_kind(r.u32(at)?).to_string(),
                permissions: permissions(flags),
                offset,
                address,
                file_size,
                memory_size,
            })
        })
        .collect()
}

/// The `.dynamic` table, read for the three things it says that the section
/// and program headers do not: which libraries are needed, where they are
/// searched for, and whether relocations are resolved before `main` runs.
fn read_dynamic(r: &Reader, sections: &[RawSection]) -> (Vec<String>, Option<String>, bool) {
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    const DT_RPATH: u64 = 15;
    const DT_BIND_NOW: u64 = 24;
    const DT_RUNPATH: u64 = 29;
    const DT_FLAGS: u64 = 30;
    const DT_FLAGS_1: u64 = 0x6fff_fffb;
    const DF_BIND_NOW: u64 = 0x8;
    const DF_1_NOW: u64 = 0x1;

    let mut needed = Vec::new();
    let mut runpath = None;
    let mut bind_now = false;

    let Some(dynamic) = sections.iter().find(|s| s.kind == 6) else {
        return (needed, runpath, bind_now);
    };
    let Some(strings) = sections
        .get(dynamic.link as usize)
        .map(|s| (s.offset as usize, s.size as usize))
    else {
        return (needed, runpath, bind_now);
    };

    let stride = r.word() * 2;
    let count = (dynamic.size as usize) / stride.max(1);

    for index in 0..count {
        let at = (dynamic.offset as usize).saturating_add(index * stride);
        let (Some(tag), Some(value)) = (r.addr(at), r.addr(at + r.word())) else {
            break;
        };

        match tag {
            DT_NULL => break,
            DT_NEEDED => {
                if let Some(name) = string_at(r.data, strings, value as u32) {
                    needed.push(name);
                }
            }
            DT_RPATH | DT_RUNPATH => {
                runpath = string_at(r.data, strings, value as u32).filter(|s| !s.is_empty());
            }
            DT_BIND_NOW => bind_now = true,
            DT_FLAGS if value & DF_BIND_NOW != 0 => bind_now = true,
            DT_FLAGS_1 if value & DF_1_NOW != 0 => bind_now = true,
            _ => {}
        }
    }

    (needed, runpath, bind_now)
}

#[cfg(test)]
pub(crate) mod tests;
