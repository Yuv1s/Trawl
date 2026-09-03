use super::*;

/// A string table, which is how ELF stores every name in the file: a run of
/// null-terminated strings that everything else points into by offset.
/// Index 0 is always the empty string, which is what a nameless section or
/// symbol points at.
struct Strings {
    data: Vec<u8>,
}

impl Strings {
    fn new() -> Self {
        Self { data: vec![0] }
    }

    fn add(&mut self, text: &str) -> u32 {
        let at = self.data.len() as u32;
        self.data.extend_from_slice(text.as_bytes());
        self.data.push(0);
        at
    }
}

struct BuildSection {
    name: String,
    kind: u32,
    flags: u64,
    link: u32,
    data: Vec<u8>,
}

impl BuildSection {
    fn new(name: &str, kind: u32, data: Vec<u8>) -> Self {
        Self {
            name: name.to_string(),
            kind,
            flags: 0,
            link: 0,
            data,
        }
    }

    fn linked(mut self, link: u32) -> Self {
        self.link = link;
        self
    }

    fn flagged(mut self, flags: u64) -> Self {
        self.flags = flags;
        self
    }
}

struct BuildSegment {
    kind: u32,
    flags: u32,
    /// The section whose bytes this segment covers, so a program header does
    /// not have to be given an offset the layout has not decided yet.
    over: Option<String>,
}

impl BuildSegment {
    fn new(kind: u32, flags: u32) -> Self {
        Self {
            kind,
            flags,
            over: None,
        }
    }

    fn over(mut self, section: &str) -> Self {
        self.over = Some(section.to_string());
        self
    }
}

/// Builds a genuine ELF from parts: a header, program headers, section
/// bytes, and the section header table, with every offset tracked as the
/// bytes are written rather than counted by hand, the same way
/// `pdf::tests::build` tracks its cross-reference offsets.
struct Builder {
    wide: bool,
    little: bool,
    kind: u16,
    machine: u16,
    entry: u64,
    sections: Vec<BuildSection>,
    segments: Vec<BuildSegment>,
}

impl Builder {
    fn new() -> Self {
        Self {
            wide: true,
            little: true,
            kind: 2,
            machine: 62,
            entry: 0x1040,
            sections: Vec::new(),
            segments: Vec::new(),
        }
    }

    fn narrow(mut self) -> Self {
        self.wide = false;
        self
    }

    fn big_endian(mut self) -> Self {
        self.little = false;
        self
    }

    fn kind(mut self, kind: u16) -> Self {
        self.kind = kind;
        self
    }

    fn machine(mut self, machine: u16) -> Self {
        self.machine = machine;
        self
    }

    fn section(mut self, section: BuildSection) -> Self {
        self.sections.push(section);
        self
    }

    fn segment(mut self, segment: BuildSegment) -> Self {
        self.segments.push(segment);
        self
    }

    fn u16(&self, out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&if self.little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        });
    }

    fn u32(&self, out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&if self.little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        });
    }

    fn addr(&self, out: &mut Vec<u8>, value: u64) {
        if self.wide {
            out.extend_from_slice(&if self.little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            });
        } else {
            self.u32(out, value as u32);
        }
    }

    fn build(mut self) -> Vec<u8> {
        // Section 0 is reserved and always empty, and the name table has to
        // be a section itself, so both are added here rather than by every
        // caller.
        self.sections.insert(0, BuildSection::new("", 0, Vec::new()));

        let mut names = Strings::new();
        let name_offsets: Vec<u32> = self
            .sections
            .iter()
            .map(|s| {
                if s.name.is_empty() {
                    0
                } else {
                    names.add(&s.name)
                }
            })
            .collect();
        let shstrndx = self.sections.len() as u16;
        let mut name_offsets = name_offsets;
        name_offsets.push(names.add(".shstrtab"));
        self.sections
            .push(BuildSection::new(".shstrtab", 3, names.data.clone()));

        let ehsize: usize = if self.wide { 64 } else { 52 };
        let phentsize: usize = if self.wide { 56 } else { 32 };
        let shentsize: usize = if self.wide { 64 } else { 40 };

        let mut at = ehsize;
        let phoff = at;
        at += self.segments.len() * phentsize;

        let mut offsets = Vec::new();
        for section in &self.sections {
            if section.kind == 0 {
                offsets.push(0usize);
                continue;
            }
            at = at.div_ceil(8) * 8;
            offsets.push(at);
            at += section.data.len();
        }

        at = at.div_ceil(8) * 8;
        let shoff = at;

        let mut out = Vec::new();
        out.extend_from_slice(b"\x7fELF");
        out.push(if self.wide { 2 } else { 1 });
        out.push(if self.little { 1 } else { 2 });
        out.push(1);
        out.push(0);
        out.extend_from_slice(&[0u8; 8]);
        self.u16(&mut out, self.kind);
        self.u16(&mut out, self.machine);
        self.u32(&mut out, 1);
        self.addr(&mut out, self.entry);
        self.addr(&mut out, phoff as u64);
        self.addr(&mut out, shoff as u64);
        self.u32(&mut out, 0);
        self.u16(&mut out, ehsize as u16);
        self.u16(&mut out, phentsize as u16);
        self.u16(&mut out, self.segments.len() as u16);
        self.u16(&mut out, shentsize as u16);
        self.u16(&mut out, self.sections.len() as u16);
        self.u16(&mut out, shstrndx);
        assert_eq!(out.len(), ehsize, "header is the size it declares");

        for segment in &self.segments {
            let covered = segment.over.as_ref().and_then(|name| {
                self.sections
                    .iter()
                    .position(|s| &s.name == name)
                    .map(|index| (offsets[index] as u64, self.sections[index].data.len() as u64))
            });
            let (offset, size) = covered.unwrap_or((0, 0));

            let before = out.len();
            self.u32(&mut out, segment.kind);
            if self.wide {
                self.u32(&mut out, segment.flags);
            }
            self.addr(&mut out, offset);
            self.addr(&mut out, 0x400000 + offset);
            self.addr(&mut out, 0x400000 + offset);
            self.addr(&mut out, size);
            self.addr(&mut out, size);
            if !self.wide {
                self.u32(&mut out, segment.flags);
            }
            self.addr(&mut out, 8);
            assert_eq!(out.len() - before, phentsize, "program header size");
        }

        for (index, section) in self.sections.iter().enumerate() {
            if section.kind == 0 {
                continue;
            }
            while out.len() < offsets[index] {
                out.push(0);
            }
            out.extend_from_slice(&section.data);
        }

        while out.len() < shoff {
            out.push(0);
        }

        for (index, section) in self.sections.iter().enumerate() {
            let before = out.len();
            self.u32(&mut out, name_offsets[index]);
            self.u32(&mut out, section.kind);
            self.addr(&mut out, section.flags);
            self.addr(&mut out, if section.kind == 0 { 0 } else { 0x400000 });
            self.addr(&mut out, offsets[index] as u64);
            self.addr(&mut out, section.data.len() as u64);
            self.u32(&mut out, section.link);
            self.u32(&mut out, 0);
            self.addr(&mut out, 1);
            self.addr(&mut out, 0);
            assert_eq!(out.len() - before, shentsize, "section header size");
        }

        out
    }
}

/// One symbol table entry, whose field order differs between the two
/// classes: 64-bit puts the value after the section index, 32-bit puts it
/// second and pushes the index to the end.
fn symbol(wide: bool, name: u32, info: u8, shndx: u16, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&name.to_le_bytes());
    if wide {
        out.push(info);
        out.push(0);
        out.extend_from_slice(&shndx.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
    } else {
        out.extend_from_slice(&(value as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.push(info);
        out.push(0);
        out.extend_from_slice(&shndx.to_le_bytes());
    }
    out
}

fn dynamic_entry(wide: bool, tag: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if wide {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
    } else {
        out.extend_from_slice(&(tag as u32).to_le_bytes());
        out.extend_from_slice(&(value as u32).to_le_bytes());
    }
    out
}

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;

const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;

/// A dynamic symbol table and its string table, as the pair the format
/// requires: the table's `sh_link` names the strings that go with it.
fn dynsym(wide: bool, entries: &[(&str, u8, u16, u64)]) -> (BuildSection, BuildSection) {
    let mut strings = Strings::new();
    let mut data = symbol(wide, 0, 0, 0, 0);
    for (name, info, shndx, value) in entries {
        let at = strings.add(name);
        data.extend_from_slice(&symbol(wide, at, *info, *shndx, *value));
    }

    // `.dynstr` is added after `.dynsym`, so its index is one past it; the
    // caller places them in that order.
    (
        BuildSection::new(".dynsym", SHT_DYNSYM, data),
        BuildSection::new(".dynstr", SHT_STRTAB, strings.data),
    )
}

#[test]
fn declines_a_file_that_is_not_an_elf() {
    assert_eq!(read(b"MZ this is a windows binary"), None);
    assert_eq!(read(b""), None);
}

#[test]
fn reads_the_class_endianness_and_machine_from_the_header() {
    let file = Builder::new().build();
    let elf = read(&file).unwrap();

    assert_eq!(elf.class, "64-bit");
    assert_eq!(elf.endianness, "little");
    assert_eq!(elf.machine, "x86-64");
    assert_eq!(elf.kind, "executable");
    assert_eq!(elf.entry, 0x1040);
}

#[test]
fn reads_a_32_bit_big_endian_header_too() {
    let file = Builder::new().narrow().big_endian().machine(40).build();
    let elf = read(&file).unwrap();

    assert_eq!(elf.class, "32-bit");
    assert_eq!(elf.endianness, "big");
    assert_eq!(elf.machine, "ARM");
}

#[test]
fn names_every_section_through_the_string_table() {
    let file = Builder::new()
        .section(BuildSection::new(".text", SHT_PROGBITS, vec![0x90; 16]).flagged(0x2 | 0x4))
        .section(BuildSection::new(".data", SHT_PROGBITS, vec![0; 8]).flagged(0x2 | 0x1))
        .build();
    let elf = read(&file).unwrap();

    let names: Vec<&str> = elf.sections.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&".text"), "got {names:?}");
    assert!(names.contains(&".data"), "got {names:?}");

    let text = elf.sections.iter().find(|s| s.name == ".text").unwrap();
    assert_eq!(text.size, 16);
    assert_eq!(text.flags, "alloc, execute");

    let data = elf.sections.iter().find(|s| s.name == ".data").unwrap();
    assert_eq!(data.flags, "alloc, write");
}

#[test]
fn reads_the_interpreter_out_of_its_own_segment() {
    let path = b"/lib64/ld-linux-x86-64.so.2\0".to_vec();
    let file = Builder::new()
        .kind(3)
        .section(BuildSection::new(".interp", SHT_PROGBITS, path))
        .segment(BuildSegment::new(PT_INTERP, 4).over(".interp"))
        .build();
    let elf = read(&file).unwrap();

    assert_eq!(elf.interpreter.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
}

#[test]
fn reads_a_non_executable_stack_as_on_and_an_executable_one_as_off() {
    let guarded = Builder::new()
        .segment(BuildSegment::new(PT_GNU_STACK, 4 | 2))
        .build();
    assert_eq!(read(&guarded).unwrap().nx, Guard::On);

    let executable = Builder::new()
        .segment(BuildSegment::new(PT_GNU_STACK, 4 | 2 | 1))
        .build();
    assert_eq!(read(&executable).unwrap().nx, Guard::Off);
}

#[test]
fn reports_a_missing_stack_header_as_undeclared_rather_than_off() {
    // The distinction matters: a binary with no PT_GNU_STACK does not say
    // its stack is executable, it says nothing, and the kernel decides.
    // Reporting that as "off" would be inventing a field the file lacks.
    let file = Builder::new().build();
    assert_eq!(read(&file).unwrap().nx, Guard::Undeclared);
}

#[test]
fn tells_a_position_independent_executable_from_a_shared_library() {
    let path = b"/lib64/ld-linux-x86-64.so.2\0".to_vec();
    let pie = Builder::new()
        .kind(3)
        .section(BuildSection::new(".interp", SHT_PROGBITS, path))
        .segment(BuildSegment::new(PT_INTERP, 4).over(".interp"))
        .build();
    assert_eq!(read(&pie).unwrap().pie, "yes");

    // Same e_type, no interpreter: a library, not a program.
    let library = Builder::new().kind(3).build();
    assert_eq!(read(&library).unwrap().pie, "shared object");

    let fixed = Builder::new().kind(2).build();
    assert_eq!(read(&fixed).unwrap().pie, "no");
}

#[test]
fn reads_partial_and_full_relro_apart() {
    let none = Builder::new().build();
    assert_eq!(read(&none).unwrap().relro, "none");

    let partial = Builder::new()
        .segment(BuildSegment::new(PT_GNU_RELRO, 4))
        .build();
    assert_eq!(read(&partial).unwrap().relro, "partial");

    // The same header plus DT_BIND_NOW, which is what makes it full: the
    // relocations are resolved before main runs, so the table can be sealed.
    let mut dynamic = dynamic_entry(true, 24, 0);
    dynamic.extend_from_slice(&dynamic_entry(true, 0, 0));
    let full = Builder::new()
        .segment(BuildSegment::new(PT_GNU_RELRO, 4))
        .section(BuildSection::new(".dynamic", SHT_DYNAMIC, dynamic).linked(2))
        .section(BuildSection::new(".dynstr", SHT_STRTAB, Strings::new().data))
        .build();
    assert_eq!(read(&full).unwrap().relro, "full");
}

#[test]
fn splits_dynamic_symbols_into_imports_and_exports() {
    // Undefined means something else has to provide it; a defined global is
    // what this file offers in return.
    let (table, strings) = dynsym(
        true,
        &[
            ("puts", (1 << 4) | 2, 0, 0),
            ("gets", (1 << 4) | 2, 0, 0),
            ("main", (1 << 4) | 2, 1, 0x1149),
        ],
    );
    let file = Builder::new()
        .section(table.linked(2))
        .section(strings)
        .build();
    let elf = read(&file).unwrap();

    let imports: Vec<&str> = elf.imports.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(imports, vec!["puts", "gets"]);
    assert_eq!(elf.import_count, 2);

    let exports: Vec<&str> = elf.exports.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(exports, vec!["main"]);
    assert_eq!(elf.exports[0].address, 0x1149);
    assert_eq!(elf.exports[0].kind, "function");
}

#[test]
fn splits_dynamic_symbols_in_a_32_bit_file_too() {
    // The 32-bit entry puts its value second and its section index last, so
    // reading it with the 64-bit layout silently mislabels every symbol.
    let (table, strings) = dynsym(
        false,
        &[("puts", (1 << 4) | 2, 0, 0), ("main", (1 << 4) | 2, 1, 0x8048400)],
    );
    let file = Builder::new()
        .narrow()
        .section(table.linked(2))
        .section(strings)
        .build();
    let elf = read(&file).unwrap();

    assert_eq!(elf.imports.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), vec!["puts"]);
    assert_eq!(elf.exports.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), vec!["main"]);
    assert_eq!(elf.exports[0].address, 0x8048400);
}

#[test]
fn finds_the_stack_guard_and_fortified_calls_among_the_symbols() {
    let (table, strings) = dynsym(
        true,
        &[
            ("__stack_chk_fail", (1 << 4) | 2, 0, 0),
            ("__printf_chk", (1 << 4) | 2, 0, 0),
        ],
    );
    let file = Builder::new()
        .section(table.linked(2))
        .section(strings)
        .build();
    let elf = read(&file).unwrap();

    assert!(elf.canary);
    assert!(elf.fortify);
}

#[test]
fn finds_a_guard_symbol_in_a_static_binary_with_no_dynamic_table() {
    // A statically linked binary has no .dynsym at all, so a reader that
    // only walks the dynamic table reports every static binary as unguarded.
    let mut strings = Strings::new();
    let at = strings.add("__stack_chk_fail");
    let mut data = symbol(true, 0, 0, 0, 0);
    data.extend_from_slice(&symbol(true, at, (1 << 4) | 2, 1, 0x401000));

    let file = Builder::new()
        .section(BuildSection::new(".symtab", SHT_SYMTAB, data).linked(2))
        .section(BuildSection::new(".strtab", SHT_STRTAB, strings.data))
        .build();
    let elf = read(&file).unwrap();

    assert!(elf.canary);
    assert!(!elf.stripped);
    // Nothing is imported or exported: those come from the dynamic table.
    assert!(elf.imports.is_empty());
    assert!(elf.exports.is_empty());
}

#[test]
fn reports_a_file_with_no_symbol_table_as_stripped() {
    let file = Builder::new()
        .section(BuildSection::new(".text", SHT_PROGBITS, vec![0x90; 4]))
        .build();
    assert!(read(&file).unwrap().stripped);
}

#[test]
fn lists_the_libraries_and_search_path_the_dynamic_table_names() {
    let mut strings = Strings::new();
    let libc = strings.add("libc.so.6");
    let libm = strings.add("libm.so.6");
    let path = strings.add("/opt/challenge/lib");

    let mut dynamic = dynamic_entry(true, 1, libc as u64);
    dynamic.extend_from_slice(&dynamic_entry(true, 1, libm as u64));
    dynamic.extend_from_slice(&dynamic_entry(true, 29, path as u64));
    dynamic.extend_from_slice(&dynamic_entry(true, 0, 0));

    let file = Builder::new()
        .section(BuildSection::new(".dynamic", SHT_DYNAMIC, dynamic).linked(2))
        .section(BuildSection::new(".dynstr", SHT_STRTAB, strings.data))
        .build();
    let elf = read(&file).unwrap();

    assert_eq!(elf.needed, vec!["libc.so.6", "libm.so.6"]);
    assert_eq!(elf.runpath.as_deref(), Some("/opt/challenge/lib"));
}

#[test]
fn reads_the_segment_table_with_its_permissions() {
    let file = Builder::new()
        .segment(BuildSegment::new(1, 4 | 1))
        .segment(BuildSegment::new(PT_GNU_STACK, 4 | 2))
        .build();
    let elf = read(&file).unwrap();

    assert_eq!(elf.segments.len(), 2);
    assert_eq!(elf.segments[0].kind, "LOAD");
    assert_eq!(elf.segments[0].permissions, "r-x");
    assert_eq!(elf.segments[1].kind, "GNU_STACK");
    assert_eq!(elf.segments[1].permissions, "rw-");
}

#[test]
fn reads_the_segment_table_in_a_32_bit_file_where_the_flags_move() {
    // A 32-bit program header keeps its flags at the end rather than after
    // the type, so reading it with the 64-bit layout returns an offset where
    // the permissions should be.
    let file = Builder::new()
        .narrow()
        .segment(BuildSegment::new(PT_GNU_STACK, 4 | 2))
        .build();
    let elf = read(&file).unwrap();

    assert_eq!(elf.segments[0].permissions, "rw-");
    assert_eq!(read(&file).unwrap().nx, Guard::On);
}

#[test]
fn json_output_is_well_formed_with_every_field_populated() {
    let (table, strings) = dynsym(
        true,
        &[("puts", (1 << 4) | 2, 0, 0), ("main", (1 << 4) | 2, 1, 0x1149)],
    );
    let mut names = Strings::new();
    let libc = names.add("libc.so.6");
    let mut dynamic = dynamic_entry(true, 1, libc as u64);
    dynamic.extend_from_slice(&dynamic_entry(true, 0, 0));

    let file = Builder::new()
        .kind(3)
        .section(BuildSection::new(".interp", SHT_PROGBITS, b"/lib/ld.so\0".to_vec()))
        .section(table.linked(3))
        .section(strings)
        .section(BuildSection::new(".dynamic", SHT_DYNAMIC, dynamic).linked(5))
        .section(BuildSection::new(".dynstr2", SHT_STRTAB, names.data))
        .segment(BuildSegment::new(PT_INTERP, 4).over(".interp"))
        .segment(BuildSegment::new(PT_GNU_STACK, 4 | 2))
        .build();

    let out = json(&file);
    assert!(crate::json::is_well_formed(&out), "malformed JSON: {out}");
    assert!(out.contains("\"puts\""), "{out}");
    assert!(out.contains("\"libc.so.6\""), "{out}");
}

#[test]
fn json_output_is_well_formed_for_a_file_that_is_not_an_elf() {
    assert_eq!(json(b"not an elf"), "null");
    assert!(crate::json::is_well_formed(&json(b"not an elf")));
}

#[test]
fn survives_a_header_that_points_its_tables_past_the_end_of_the_file() {
    // A truncated or doctored binary is exactly what a challenge hands over,
    // and every table read here is bounds-checked rather than trusted.
    let mut file = Builder::new()
        .section(BuildSection::new(".text", SHT_PROGBITS, vec![0x90; 32]))
        .build();
    file.truncate(80);

    let elf = read(&file).expect("still reads the header it has");
    assert_eq!(elf.machine, "x86-64");
    assert!(elf.sections.is_empty() || elf.sections.iter().all(|s| s.name.is_empty()));
}
