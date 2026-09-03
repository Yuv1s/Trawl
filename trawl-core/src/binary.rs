//! What an executable declares about itself, in one shape for both formats
//! that carry it.
//!
//! ELF and PE answer the same questions with entirely different bytes, and
//! [`crate::elf`] and [`crate::pe`] each read their own. What they produce is
//! held here, and serialised here, so the two cannot drift apart in the shape
//! a single reader on the other side of the WASM boundary expects. Where a
//! field belongs to one format and has no counterpart in the other it is an
//! `Option` and comes back null, rather than being given a value invented to
//! fill the column.

/// What the file says about a protection, kept to three states because the
/// formats support three: declared on, declared off, and never declared at
/// all. Collapsing the third into the second would report a fact the binary
/// does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    On,
    Off,
    Undeclared,
}

impl Guard {
    pub fn label(self) -> &'static str {
        match self {
            Guard::On => "on",
            Guard::Off => "off",
            Guard::Undeclared => "not declared",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub kind: String,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    /// Which of the permissions and contents the header declares, named.
    pub flags: String,
}

/// A run of the file the loader maps into memory as a unit. ELF carries these
/// as program headers; PE has no equivalent and leaves the list empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub kind: String,
    pub permissions: String,
    pub offset: u64,
    pub address: u64,
    pub file_size: u64,
    pub memory_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub kind: &'static str,
    pub address: u64,
    /// Which library the name is imported from. PE names one per import; ELF
    /// does not say, and leaves this empty.
    pub from: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binary {
    /// "ELF" or "PE".
    pub format: &'static str,
    pub class: &'static str,
    pub endianness: &'static str,
    pub machine: &'static str,
    pub kind: &'static str,
    /// Where execution starts, at the file's own preferred load address.
    pub entry: u64,
    /// The dynamic loader named in `PT_INTERP`. ELF only.
    pub interpreter: Option<String>,
    /// A library search path baked into the file. ELF only.
    pub runpath: Option<String>,
    /// Which Windows subsystem the image asks for. PE only.
    pub subsystem: Option<&'static str>,
    /// The build path of the debug database, which a linker writes verbatim
    /// and which therefore carries whatever the build machine's directories
    /// were called. PE only.
    pub pdb_path: Option<String>,
    /// True when the file carries no symbol table of its own.
    pub stripped: bool,
    pub nx: Guard,
    /// "yes", "no", or "shared object": whether the image can be loaded at an
    /// address it did not choose.
    pub pie: &'static str,
    /// "none", "partial", or "full". ELF only; PE has no counterpart.
    pub relro: Option<&'static str>,
    pub canary: bool,
    /// Whether fortified libc calls are linked. ELF only.
    pub fortify: Option<bool>,
    /// Whether Control Flow Guard is on. PE only.
    pub cfg: Option<bool>,
    /// Libraries the file needs at run time.
    pub needed: Vec<String>,
    pub sections: Vec<Section>,
    pub segments: Vec<Segment>,
    pub imports: Vec<Symbol>,
    pub exports: Vec<Symbol>,
    /// True totals, which the two lists above are capped copies of.
    pub import_count: usize,
    pub export_count: usize,
}

/// How many symbols of each kind reach the caller. A challenge binary has a
/// handful; a system library can have thousands, and the true count is
/// reported separately so a capped list never reads as the whole truth.
pub const MAX_SYMBOLS: usize = 512;

/// Reads whichever executable format the bytes are in, or nothing.
pub fn read(data: &[u8]) -> Option<Binary> {
    crate::elf::read(data).or_else(|| crate::pe::read(data))
}

pub fn json(data: &[u8]) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let Some(binary) = read(data) else {
        return "null".to_string();
    };

    /// A field that is null where the format has no counterpart for it.
    fn push_maybe(out: &mut String, key: &str, value: Option<&str>) {
        push_string(out, key);
        out.push(':');
        match value {
            Some(text) => push_string(out, text),
            None => out.push_str("null"),
        }
    }

    let mut out = String::from("{");
    push_field(&mut out, "format", binary.format);
    out.push(',');
    push_field(&mut out, "class", binary.class);
    out.push(',');
    push_field(&mut out, "endianness", binary.endianness);
    out.push(',');
    push_field(&mut out, "machine", binary.machine);
    out.push(',');
    push_field(&mut out, "kind", binary.kind);
    out.push(',');
    push_field(&mut out, "entry", &format!("0x{:x}", binary.entry));
    out.push(',');
    push_maybe(&mut out, "interpreter", binary.interpreter.as_deref());
    out.push(',');
    push_maybe(&mut out, "runpath", binary.runpath.as_deref());
    out.push(',');
    push_maybe(&mut out, "subsystem", binary.subsystem);
    out.push(',');
    push_maybe(&mut out, "pdbPath", binary.pdb_path.as_deref());
    out.push(',');
    push_bool(&mut out, "stripped", binary.stripped);
    out.push(',');
    push_field(&mut out, "nx", binary.nx.label());
    out.push(',');
    push_field(&mut out, "pie", binary.pie);
    out.push(',');
    push_maybe(&mut out, "relro", binary.relro);
    out.push(',');
    push_bool(&mut out, "canary", binary.canary);
    out.push(',');

    for (key, value) in [("fortify", binary.fortify), ("cfg", binary.cfg)] {
        push_string(&mut out, key);
        out.push(':');
        match value {
            Some(on) => out.push_str(if on { "true" } else { "false" }),
            None => out.push_str("null"),
        }
        out.push(',');
    }

    push_number(&mut out, "importCount", binary.import_count);
    out.push(',');
    push_number(&mut out, "exportCount", binary.export_count);
    out.push(',');

    push_string(&mut out, "needed");
    out.push_str(":[");
    for (i, name) in binary.needed.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_string(&mut out, name);
    }
    out.push_str("],");

    push_string(&mut out, "sections");
    out.push_str(":[");
    for (i, section) in binary.sections.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "name", &section.name);
        out.push(',');
        push_field(&mut out, "kind", &section.kind);
        out.push(',');
        push_field(&mut out, "address", &format!("0x{:x}", section.address));
        out.push(',');
        push_number(&mut out, "offset", section.offset as usize);
        out.push(',');
        push_number(&mut out, "size", section.size as usize);
        out.push(',');
        push_field(&mut out, "flags", &section.flags);
        out.push('}');
    }
    out.push_str("],");

    push_string(&mut out, "segments");
    out.push_str(":[");
    for (i, segment) in binary.segments.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "kind", &segment.kind);
        out.push(',');
        push_field(&mut out, "permissions", &segment.permissions);
        out.push(',');
        push_field(&mut out, "address", &format!("0x{:x}", segment.address));
        out.push(',');
        push_number(&mut out, "offset", segment.offset as usize);
        out.push(',');
        push_number(&mut out, "fileSize", segment.file_size as usize);
        out.push(',');
        push_number(&mut out, "memorySize", segment.memory_size as usize);
        out.push('}');
    }
    out.push_str("],");

    for (key, symbols) in [("imports", &binary.imports), ("exports", &binary.exports)] {
        push_string(&mut out, key);
        out.push_str(":[");
        for (i, symbol) in symbols.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            push_field(&mut out, "name", &symbol.name);
            out.push(',');
            push_field(&mut out, "kind", symbol.kind);
            out.push(',');
            push_field(&mut out, "address", &format!("0x{:x}", symbol.address));
            out.push(',');
            push_maybe(&mut out, "from", symbol.from.as_deref());
            out.push('}');
        }
        out.push_str("],");
    }

    out.pop();
    out.push('}');
    out
}

#[cfg(test)]
mod tests;
