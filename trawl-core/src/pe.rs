//! PE binaries, the Windows half of what [`crate::elf`] reads.
//!
//! The questions are the same ones an ELF is asked and the answers sit in
//! entirely different places. Two differences shape everything here.
//!
//! The first is addressing. An ELF section header carries both where the
//! section lands in memory and where its bytes sit in the file, so reading a
//! table is a matter of going to the offset it names. PE names almost
//! everything by relative virtual address instead, an address relative to
//! where the image is loaded, and the file offset for it exists only as a
//! consequence of the section that happens to contain it. So nearly every
//! read here goes through [`Rva::to_offset`], which finds the containing
//! section and translates. A pointer that lands in no section is not
//! followed rather than guessed at.
//!
//! The second is that PE states its protections as bits in one field rather
//! than as separate headers. `DllCharacteristics` says whether the image
//! opts into a non-executable stack and into being loaded somewhere it did
//! not choose, and either bit being clear is a real claim by the file, so
//! unlike a missing `PT_GNU_STACK` there is no undeclared case to report.
//! The stack cookie is the exception: it is not a bit anywhere, and the only
//! honest evidence for it is the load configuration naming a cookie's
//! address, which is what is read.

use crate::binary::{Binary, Guard, MAX_SYMBOLS, Section, Segment, Symbol};

/// Reads little-endian numbers, which PE always is on every machine it
/// targets, unlike ELF where the header declares it.
struct Reader<'a> {
    data: &'a [u8],
}

impl Reader<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        let raw: [u8; 2] = self.data.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(u16::from_le_bytes(raw))
    }

    fn u32(&self, at: usize) -> Option<u32> {
        let raw: [u8; 4] = self.data.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(u32::from_le_bytes(raw))
    }

    fn u64(&self, at: usize) -> Option<u64> {
        let raw: [u8; 8] = self.data.get(at..at.checked_add(8)?)?.try_into().ok()?;
        Some(u64::from_le_bytes(raw))
    }

    /// A null-terminated ASCII name at a file offset, held to a length so a
    /// pointer into unterminated bytes cannot run to the end of the file.
    fn string(&self, at: usize, limit: usize) -> Option<String> {
        let end = at.saturating_add(limit).min(self.data.len());
        let slice = self.data.get(at..end)?;
        let stop = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        Some(crate::json::latin1(&slice[..stop]))
    }
}

/// Where a section lands in memory against where its bytes are in the file,
/// which is the whole of what it takes to follow a PE's own pointers.
struct Rva {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

impl Rva {
    /// The file offset an address maps to, or nothing when it falls outside
    /// every section, which is what a truncated or doctored image looks like.
    fn to_offset(sections: &[Rva], rva: u32) -> Option<usize> {
        let holding = sections.iter().find(|s| {
            let span = s.virtual_size.max(s.raw_size);
            rva >= s.virtual_address && rva < s.virtual_address.saturating_add(span)
        })?;
        let into = rva.checked_sub(holding.virtual_address)?;
        // A section can declare more memory than it has bytes for, the
        // uninitialised tail of a data section being the ordinary case, and
        // an address in that tail has no bytes in the file to read.
        if into >= holding.raw_size {
            return None;
        }
        Some(holding.raw_offset as usize + into as usize)
    }
}

fn machine_name(value: u16) -> &'static str {
    match value {
        0x014c => "x86",
        0x0166 => "MIPS",
        0x01c0 => "ARM",
        0x01c4 => "ARM Thumb-2",
        0x0200 => "Itanium",
        0x8664 => "x86-64",
        0xaa64 => "AArch64",
        0x5032 => "RISC-V 32",
        0x5064 => "RISC-V 64",
        _ => "an architecture this does not name",
    }
}

fn subsystem_name(value: u16) -> &'static str {
    match value {
        1 => "native",
        2 => "Windows GUI",
        3 => "Windows console",
        5 => "OS/2 console",
        7 => "POSIX console",
        9 => "Windows CE",
        10 => "EFI application",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => "an unnamed subsystem",
    }
}

/// What a section's characteristics say it holds and what it may be done
/// with, which PE packs into one word rather than splitting across the two
/// fields ELF uses.
fn section_flags(characteristics: u32) -> String {
    let mut out = Vec::new();
    if characteristics & 0x4000_0000 != 0 {
        out.push("read");
    }
    if characteristics & 0x8000_0000 != 0 {
        out.push("write");
    }
    if characteristics & 0x2000_0000 != 0 {
        out.push("execute");
    }
    if characteristics & 0x0200_0000 != 0 {
        out.push("discardable");
    }
    out.join(", ")
}

fn section_kind(characteristics: u32) -> &'static str {
    if characteristics & 0x0000_0020 != 0 {
        "code"
    } else if characteristics & 0x0000_0040 != 0 {
        "data"
    } else if characteristics & 0x0000_0080 != 0 {
        "uninitialised data"
    } else {
        "other"
    }
}

pub fn read(data: &[u8]) -> Option<Binary> {
    // "MZ" alone is any DOS-era executable, so the signature is not settled
    // until the offset in the DOS header leads to a real PE header. Trusting
    // the two letters alone would claim every ancient .com-era stub is one.
    if !data.starts_with(b"MZ") {
        return None;
    }

    let r = Reader { data };
    let pe_at = r.u32(0x3c)? as usize;
    if data.get(pe_at..pe_at.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }

    let coff = pe_at + 4;
    let machine = machine_name(r.u16(coff)?);
    let section_count = r.u16(coff + 2)? as usize;
    let symbol_table = r.u32(coff + 8)?;
    let optional_size = r.u16(coff + 16)? as usize;
    let characteristics = r.u16(coff + 18)?;

    let optional = coff + 20;
    let magic = r.u16(optional)?;
    let wide = match magic {
        0x10b => false,
        0x20b => true,
        _ => return None,
    };

    let entry_rva = r.u32(optional + 16)?;
    // PE32 carries a BaseOfData field that PE32+ drops, so everything from
    // the image base onwards sits eight bytes earlier in a 64-bit image even
    // though the base itself is eight bytes wider.
    let image_base = if wide {
        r.u64(optional + 24)?
    } else {
        u64::from(r.u32(optional + 28)?)
    };
    let subsystem = subsystem_name(r.u16(optional + 68)?);
    let dll_characteristics = r.u16(optional + 70)?;
    let directories_at = optional + if wide { 112 } else { 96 };
    let directory_count = r.u32(optional + if wide { 108 } else { 92 })? as usize;

    let directory = |index: usize| -> Option<(u32, u32)> {
        if index >= directory_count {
            return None;
        }
        let at = directories_at + index * 8;
        let address = r.u32(at)?;
        let size = r.u32(at + 4)?;
        (address != 0).then_some((address, size))
    };

    let table_at = optional + optional_size;
    let mut sections = Vec::new();
    let mut map = Vec::new();
    for index in 0..section_count {
        let at = table_at + index * 40;
        let Some(name) = r.string(at, 8) else { break };
        let (Some(virtual_size), Some(virtual_address), Some(raw_size), Some(raw_offset)) =
            (r.u32(at + 8), r.u32(at + 12), r.u32(at + 16), r.u32(at + 20))
        else {
            break;
        };
        let Some(flags) = r.u32(at + 36) else { break };

        map.push(Rva {
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
        });
        sections.push(Section {
            name,
            kind: section_kind(flags).to_string(),
            address: image_base + u64::from(virtual_address),
            offset: u64::from(raw_offset),
            size: u64::from(virtual_size),
            flags: section_flags(flags),
        });
    }

    let (imports, needed, import_count) = read_imports(&r, &map, directory(1), wide);
    let (exports, export_count) = read_exports(&r, &map, directory(0));
    let pdb_path = read_pdb_path(&r, &map, directory(6));
    let canary = read_security_cookie(&r, &map, directory(10), wide);

    let is_dll = characteristics & 0x2000 != 0;

    Some(Binary {
        format: "PE",
        class: if wide { "64-bit" } else { "32-bit" },
        endianness: "little",
        machine,
        kind: if is_dll {
            "dynamic library"
        } else {
            "executable"
        },
        entry: image_base + u64::from(entry_rva),
        interpreter: None,
        runpath: None,
        subsystem: Some(subsystem),
        pdb_path,
        // PE keeps its symbol names in a separate database rather than in the
        // image, so an absent COFF table is the ordinary case rather than a
        // sign anything was removed. What names are in the file are the
        // imports and exports, and those are read above.
        stripped: symbol_table == 0,
        nx: if dll_characteristics & 0x0100 != 0 {
            Guard::On
        } else {
            Guard::Off
        },
        pie: if dll_characteristics & 0x0040 != 0 {
            "yes"
        } else {
            "no"
        },
        relro: None,
        canary,
        fortify: None,
        cfg: Some(dll_characteristics & 0x4000 != 0),
        needed,
        sections,
        segments: Vec::<Segment>::new(),
        imports,
        exports,
        import_count,
        export_count,
    })
}

/// The import directory: one descriptor per library, each naming a list of
/// the functions wanted from it.
fn read_imports(
    r: &Reader,
    map: &[Rva],
    directory: Option<(u32, u32)>,
    wide: bool,
) -> (Vec<Symbol>, Vec<String>, usize) {
    let mut imports = Vec::new();
    let mut needed = Vec::new();
    let mut count = 0usize;

    let Some((address, _)) = directory else {
        return (imports, needed, count);
    };
    let Some(start) = Rva::to_offset(map, address) else {
        return (imports, needed, count);
    };

    // The table ends at an all-zero descriptor rather than declaring its own
    // length, and a doctored image can leave that terminator off, so the walk
    // is bounded as well.
    for index in 0..1024 {
        let at = start + index * 20;
        let (Some(lookup), Some(name_rva), Some(bound)) =
            (r.u32(at), r.u32(at + 12), r.u32(at + 16))
        else {
            break;
        };
        if lookup == 0 && name_rva == 0 && bound == 0 {
            break;
        }

        let library = Rva::to_offset(map, name_rva)
            .and_then(|at| r.string(at, 256))
            .filter(|name| !name.is_empty());
        if let Some(name) = &library {
            needed.push(name.clone());
        }

        // The lookup table holds what was asked for and survives binding; the
        // address table is overwritten with resolved addresses when an image
        // is bound, so it is only read when there is no lookup table.
        let thunks = if lookup != 0 { lookup } else { bound };
        let Some(thunk_start) = Rva::to_offset(map, thunks) else {
            continue;
        };

        let stride = if wide { 8 } else { 4 };
        for slot in 0..4096 {
            let at = thunk_start + slot * stride;
            let value = if wide {
                r.u64(at)
            } else {
                r.u32(at).map(u64::from)
            };
            let Some(value) = value else { break };
            if value == 0 {
                break;
            }

            let ordinal_bit = if wide { 1 << 63 } else { 1 << 31 };
            let name = if value & ordinal_bit != 0 {
                // Imported by number rather than by name, which says nothing
                // about what the function is, so the number is what is shown.
                format!("ordinal {}", value & 0xffff)
            } else {
                let Some(at) = Rva::to_offset(map, value as u32) else {
                    continue;
                };
                // Two bytes of hint precede the name itself.
                match r.string(at + 2, 512).filter(|n| !n.is_empty()) {
                    Some(name) => name,
                    None => continue,
                }
            };

            count += 1;
            if imports.len() < MAX_SYMBOLS {
                imports.push(Symbol {
                    name,
                    kind: "function",
                    address: 0,
                    from: library.clone(),
                });
            }
        }
    }

    (imports, needed, count)
}

/// The export directory, read through its parallel arrays: one of addresses,
/// one of names, and one of the indices tying the second to the first.
fn read_exports(r: &Reader, map: &[Rva], directory: Option<(u32, u32)>) -> (Vec<Symbol>, usize) {
    let mut exports = Vec::new();

    let Some((address, _)) = directory else {
        return (exports, 0);
    };
    let Some(at) = Rva::to_offset(map, address) else {
        return (exports, 0);
    };

    let (Some(name_count), Some(functions_rva), Some(names_rva), Some(ordinals_rva)) = (
        r.u32(at + 24),
        r.u32(at + 28),
        r.u32(at + 32),
        r.u32(at + 36),
    ) else {
        return (exports, 0);
    };

    let (Some(names_at), Some(ordinals_at)) = (
        Rva::to_offset(map, names_rva),
        Rva::to_offset(map, ordinals_rva),
    ) else {
        return (exports, 0);
    };
    let functions_at = Rva::to_offset(map, functions_rva);

    let total = name_count as usize;
    for index in 0..total {
        let Some(name_rva) = r.u32(names_at + index * 4) else {
            break;
        };
        let Some(name) = Rva::to_offset(map, name_rva)
            .and_then(|at| r.string(at, 512))
            .filter(|n| !n.is_empty())
        else {
            continue;
        };

        // The ordinal array indexes the address array, so a name's address is
        // only reachable through both.
        let address = r
            .u16(ordinals_at + index * 2)
            .zip(functions_at)
            .and_then(|(ordinal, functions)| r.u32(functions + ordinal as usize * 4))
            .unwrap_or(0);

        if exports.len() < MAX_SYMBOLS {
            exports.push(Symbol {
                name,
                kind: "function",
                address: u64::from(address),
                from: None,
            });
        }
    }

    (exports, total)
}

/// The build path of the debug database, which the linker writes verbatim
/// into the image and which therefore carries whatever the build machine's
/// directories happened to be called.
fn read_pdb_path(r: &Reader, map: &[Rva], directory: Option<(u32, u32)>) -> Option<String> {
    const CODEVIEW: u32 = 2;

    let (address, size) = directory?;
    let start = Rva::to_offset(map, address)?;

    for index in 0..(size as usize / 28).min(64) {
        let at = start + index * 28;
        if r.u32(at + 12)? != CODEVIEW {
            continue;
        }
        let raw_at = r.u32(at + 24)? as usize;
        // "RSDS", then a build identifier and an age, then the path.
        if r.data.get(raw_at..raw_at + 4)? != b"RSDS" {
            continue;
        }
        return r.string(raw_at + 24, 512).filter(|path| !path.is_empty());
    }

    None
}

/// Whether the load configuration names a stack cookie.
///
/// There is no bit anywhere that says a binary was built with stack
/// protection. What there is, on a build that was, is a cookie the loader
/// has to initialise, and the load configuration naming its address is the
/// only evidence in the file that one exists.
fn read_security_cookie(
    r: &Reader,
    map: &[Rva],
    directory: Option<(u32, u32)>,
    wide: bool,
) -> bool {
    let Some((address, size)) = directory else {
        return false;
    };
    let Some(at) = Rva::to_offset(map, address) else {
        return false;
    };

    let field = if wide { 88 } else { 60 };
    // The structure has grown over the years and an older image declares a
    // shorter one, in which the cookie field is simply not present.
    if (size as usize) < field + if wide { 8 } else { 4 } {
        return false;
    }

    let cookie = if wide {
        r.u64(at + field)
    } else {
        r.u32(at + field).map(u64::from)
    };

    cookie.is_some_and(|value| value != 0)
}

#[cfg(test)]
pub(crate) mod tests;
