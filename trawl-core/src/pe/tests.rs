use super::*;

/// A run of bytes that knows where it will land in memory, so a structure
/// written into it can hand back a usable address rather than one counted by
/// hand. Every table in a PE points at another by address, so building a
/// fixture without this is mostly bookkeeping errors.
struct Blob {
    base: u32,
    data: Vec<u8>,
}

impl Blob {
    fn new(base: u32) -> Self {
        Self {
            base,
            data: Vec::new(),
        }
    }

    /// Where the next thing appended will sit once loaded.
    fn next(&self) -> u32 {
        self.base + self.data.len() as u32
    }

    fn push(&mut self, bytes: &[u8]) -> u32 {
        let at = self.next();
        self.data.extend_from_slice(bytes);
        at
    }

    fn u16(&mut self, value: u16) -> u32 {
        self.push(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> u32 {
        self.push(&value.to_le_bytes())
    }

    fn string(&mut self, text: &str) -> u32 {
        let at = self.next();
        self.data.extend_from_slice(text.as_bytes());
        self.data.push(0);
        at
    }

    fn align(&mut self, to: usize) {
        while !self.data.len().is_multiple_of(to) {
            self.data.push(0);
        }
    }
}

struct BuildSection {
    name: String,
    rva: u32,
    characteristics: u32,
    data: Vec<u8>,
}

struct Builder {
    wide: bool,
    machine: u16,
    dll: bool,
    dll_characteristics: u16,
    image_base: u64,
    entry: u32,
    subsystem: u16,
    symbol_table: u32,
    sections: Vec<BuildSection>,
    /// Index and value for each data directory that is set.
    directories: Vec<(usize, u32, u32)>,
}

impl Builder {
    fn new() -> Self {
        Self {
            wide: true,
            machine: 0x8664,
            dll: false,
            dll_characteristics: 0,
            image_base: 0x1_4000_0000,
            entry: 0x1000,
            subsystem: 3,
            symbol_table: 0,
            sections: Vec::new(),
            directories: Vec::new(),
        }
    }

    fn narrow(mut self) -> Self {
        self.wide = false;
        self.image_base = 0x0040_0000;
        self
    }

    fn machine(mut self, machine: u16) -> Self {
        self.machine = machine;
        self
    }

    fn dll(mut self) -> Self {
        self.dll = true;
        self
    }

    fn guards(mut self, bits: u16) -> Self {
        self.dll_characteristics = bits;
        self
    }

    fn subsystem(mut self, subsystem: u16) -> Self {
        self.subsystem = subsystem;
        self
    }

    fn with_symbol_table(mut self) -> Self {
        self.symbol_table = 0x8000;
        self
    }

    fn section(mut self, name: &str, rva: u32, characteristics: u32, data: Vec<u8>) -> Self {
        self.sections.push(BuildSection {
            name: name.to_string(),
            rva,
            characteristics,
            data,
        });
        self
    }

    fn directory(mut self, index: usize, address: u32, size: u32) -> Self {
        self.directories.push((index, address, size));
        self
    }

    fn build(self) -> Vec<u8> {
        let optional_size: usize = if self.wide { 240 } else { 224 };
        let headers_end = 0x40 + 4 + 20 + optional_size + self.sections.len() * 40;
        let file_alignment = 512usize;
        let mut raw_at = headers_end.div_ceil(file_alignment) * file_alignment;

        let mut placed = Vec::new();
        for section in &self.sections {
            placed.push(raw_at);
            raw_at += section.data.len().div_ceil(file_alignment) * file_alignment;
        }

        let mut out = vec![0u8; 0x40];
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());

        out.extend_from_slice(b"PE\0\0");
        out.extend_from_slice(&self.machine.to_le_bytes());
        out.extend_from_slice(&(self.sections.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        out.extend_from_slice(&self.symbol_table.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        out.extend_from_slice(&(optional_size as u16).to_le_bytes());
        out.extend_from_slice(&(if self.dll { 0x2000u16 } else { 0x0002 }).to_le_bytes());

        let optional_at = out.len();
        out.extend_from_slice(&(if self.wide { 0x20bu16 } else { 0x10b }).to_le_bytes());
        out.extend_from_slice(&[14, 0]); // linker version
        out.extend_from_slice(&0u32.to_le_bytes()); // SizeOfCode
        out.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
        out.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        out.extend_from_slice(&self.entry.to_le_bytes());
        out.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        if self.wide {
            out.extend_from_slice(&self.image_base.to_le_bytes());
        } else {
            out.extend_from_slice(&0u32.to_le_bytes()); // BaseOfData, PE32 only
            out.extend_from_slice(&(self.image_base as u32).to_le_bytes());
        }
        out.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        out.extend_from_slice(&(file_alignment as u32).to_le_bytes());
        // Six versions, two bytes each: OS, image and subsystem, major and
        // minor apiece.
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        out.extend_from_slice(&0x10000u32.to_le_bytes()); // SizeOfImage
        out.extend_from_slice(&(headers_end as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        out.extend_from_slice(&self.subsystem.to_le_bytes());
        out.extend_from_slice(&self.dll_characteristics.to_le_bytes());
        // The four stack and heap sizes, which are the width of the class.
        for _ in 0..4 {
            if self.wide {
                out.extend_from_slice(&0u64.to_le_bytes());
            } else {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        out.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        out.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        for index in 0..16 {
            let entry = self.directories.iter().find(|(i, _, _)| *i == index);
            let (address, size) = entry.map(|(_, a, s)| (*a, *s)).unwrap_or((0, 0));
            out.extend_from_slice(&address.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
        }
        assert_eq!(
            out.len() - optional_at,
            optional_size,
            "optional header is the size it declares"
        );

        for (index, section) in self.sections.iter().enumerate() {
            let mut name = [0u8; 8];
            let bytes = section.name.as_bytes();
            name[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
            out.extend_from_slice(&name);
            out.extend_from_slice(&(section.data.len() as u32).to_le_bytes()); // VirtualSize
            out.extend_from_slice(&section.rva.to_le_bytes());
            out.extend_from_slice(&(section.data.len() as u32).to_le_bytes()); // SizeOfRawData
            out.extend_from_slice(&(placed[index] as u32).to_le_bytes());
            out.extend_from_slice(&[0u8; 12]); // relocation and line number pointers
            out.extend_from_slice(&section.characteristics.to_le_bytes());
        }

        for (index, section) in self.sections.iter().enumerate() {
            while out.len() < placed[index] {
                out.push(0);
            }
            out.extend_from_slice(&section.data);
        }

        out
    }
}

/// The smallest thing this reads as a PE, for the tests that only need one to
/// exist. Shared with [`crate::binary::tests`], which checks that the two
/// formats come out the same shape.
pub(crate) fn minimal() -> Vec<u8> {
    Builder::new()
        .section(".text", 0x1000, 0x6000_0020, vec![0x90; 16])
        .build()
}

const READ_EXECUTE: u32 = 0x6000_0020;
const READ_WRITE: u32 = 0xc000_0040;

/// An import directory naming one library and the functions wanted from it,
/// with every internal pointer resolved through the blob's own addresses.
fn import_blob(base: u32, wide: bool, library: &str, functions: &[&str]) -> (Vec<u8>, u32, u32) {
    let mut blob = Blob::new(base);

    let library_rva = blob.string(library);
    let mut name_rvas = Vec::new();
    for function in functions {
        blob.align(2);
        let at = blob.next();
        blob.u16(0); // hint
        blob.push(function.as_bytes());
        blob.push(&[0]);
        name_rvas.push(at);
    }

    blob.align(8);
    let lookup_rva = blob.next();
    for rva in &name_rvas {
        if wide {
            blob.push(&u64::from(*rva).to_le_bytes());
        } else {
            blob.u32(*rva);
        }
    }
    if wide {
        blob.push(&0u64.to_le_bytes());
    } else {
        blob.u32(0);
    }

    blob.align(4);
    let directory_rva = blob.next();
    blob.u32(lookup_rva);
    blob.u32(0); // TimeDateStamp
    blob.u32(0); // ForwarderChain
    blob.u32(library_rva);
    blob.u32(lookup_rva); // FirstThunk, the same list before binding
    for _ in 0..5 {
        blob.u32(0); // the all-zero descriptor that ends the table
    }

    let size = blob.next() - directory_rva;
    (blob.data, directory_rva, size)
}

/// An export directory: the three parallel arrays a PE uses to tie a name to
/// an address through an ordinal.
fn export_blob(base: u32, functions: &[(&str, u32)]) -> (Vec<u8>, u32, u32) {
    let mut blob = Blob::new(base);

    let mut name_rvas = Vec::new();
    for (name, _) in functions {
        name_rvas.push(blob.string(name));
    }

    blob.align(4);
    let addresses_rva = blob.next();
    for (_, address) in functions {
        blob.u32(*address);
    }

    let names_rva = blob.next();
    for rva in &name_rvas {
        blob.u32(*rva);
    }

    let ordinals_rva = blob.next();
    for index in 0..functions.len() {
        blob.u16(index as u16);
    }

    blob.align(4);
    let directory_rva = blob.next();
    blob.u32(0); // Characteristics
    blob.u32(0); // TimeDateStamp
    blob.u32(0); // the two version halves
    blob.u32(0); // Name
    blob.u32(1); // Base
    blob.u32(functions.len() as u32); // NumberOfFunctions
    blob.u32(functions.len() as u32); // NumberOfNames
    blob.u32(addresses_rva);
    blob.u32(names_rva);
    blob.u32(ordinals_rva);

    let size = blob.next() - directory_rva;
    (blob.data, directory_rva, size)
}

#[test]
fn declines_a_file_that_is_not_a_pe() {
    assert_eq!(read(b"\x7fELF and the rest of an elf"), None);
    assert_eq!(read(b""), None);
}

#[test]
fn declines_a_dos_stub_with_no_pe_header_behind_it() {
    // "MZ" alone is any DOS-era executable, and claiming those are PE images
    // is what reading the two letters on their own would do.
    let mut file = vec![0u8; 0x80];
    file[0] = b'M';
    file[1] = b'Z';
    file[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    file[0x40..0x44].copy_from_slice(b"NOPE");

    assert_eq!(read(&file), None);
}

#[test]
fn declines_a_header_whose_pointer_leads_off_the_end() {
    let mut file = vec![0u8; 0x80];
    file[0] = b'M';
    file[1] = b'Z';
    file[0x3c..0x40].copy_from_slice(&0x0f00_0000u32.to_le_bytes());

    assert_eq!(read(&file), None);
}

#[test]
fn reads_the_class_machine_and_subsystem_from_the_headers() {
    let file = Builder::new()
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .build();
    let pe = read(&file).unwrap();

    assert_eq!(pe.format, "PE");
    assert_eq!(pe.class, "64-bit");
    assert_eq!(pe.endianness, "little");
    assert_eq!(pe.machine, "x86-64");
    assert_eq!(pe.kind, "executable");
    assert_eq!(pe.subsystem, Some("Windows console"));
    // The entry point is an address relative to the image base, so it is
    // reported the way a debugger shows it rather than as the bare offset.
    assert_eq!(pe.entry, 0x1_4000_0000 + 0x1000);
}

#[test]
fn reads_a_32_bit_image_where_the_image_base_moves() {
    // PE32 carries a BaseOfData field that PE32+ drops, so every field from
    // the image base onwards sits at a different offset in the two.
    let file = Builder::new()
        .narrow()
        .machine(0x014c)
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .build();
    let pe = read(&file).unwrap();

    assert_eq!(pe.class, "32-bit");
    assert_eq!(pe.machine, "x86");
    assert_eq!(pe.entry, 0x0040_0000 + 0x1000);
}

#[test]
fn names_a_library_as_a_library() {
    let file = Builder::new()
        .dll()
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .build();
    assert_eq!(read(&file).unwrap().kind, "dynamic library");
}

#[test]
fn reads_the_section_table_with_what_each_section_may_be_done_with() {
    let file = Builder::new()
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 32])
        .section(".data", 0x2000, READ_WRITE, vec![0; 16])
        .build();
    let pe = read(&file).unwrap();

    assert_eq!(pe.sections.len(), 2);
    assert_eq!(pe.sections[0].name, ".text");
    assert_eq!(pe.sections[0].kind, "code");
    assert_eq!(pe.sections[0].flags, "read, execute");
    assert_eq!(pe.sections[0].address, 0x1_4000_0000 + 0x1000);

    assert_eq!(pe.sections[1].name, ".data");
    assert_eq!(pe.sections[1].kind, "data");
    assert_eq!(pe.sections[1].flags, "read, write");
}

#[test]
fn a_pe_has_no_segments_to_report() {
    // Program headers are an ELF idea. Reporting an empty list is the honest
    // answer rather than inventing one out of the sections.
    let file = minimal();
    assert!(read(&file).unwrap().segments.is_empty());
}

#[test]
fn reads_imports_through_the_address_translation() {
    let (data, directory, size) = import_blob(0x2000, true, "KERNEL32.dll", &["CreateFileW", "ExitProcess"]);
    let file = Builder::new()
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .section(".rdata", 0x2000, 0x4000_0040, data)
        .directory(1, directory, size)
        .build();
    let pe = read(&file).unwrap();

    let names: Vec<&str> = pe.imports.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["CreateFileW", "ExitProcess"]);
    assert_eq!(pe.import_count, 2);
    assert_eq!(pe.needed, vec!["KERNEL32.dll"]);
    // Which library a name came from is worth keeping: it is the half of an
    // import that says where the behaviour actually lives.
    assert_eq!(pe.imports[0].from.as_deref(), Some("KERNEL32.dll"));
}

#[test]
fn reads_imports_in_a_32_bit_image_where_the_thunks_are_half_as_wide() {
    let (data, directory, size) = import_blob(0x2000, false, "msvcrt.dll", &["printf"]);
    let file = Builder::new()
        .narrow()
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .section(".rdata", 0x2000, 0x4000_0040, data)
        .directory(1, directory, size)
        .build();
    let pe = read(&file).unwrap();

    assert_eq!(pe.imports.len(), 1);
    assert_eq!(pe.imports[0].name, "printf");
    assert_eq!(pe.needed, vec!["msvcrt.dll"]);
}

#[test]
fn reports_an_import_by_ordinal_as_the_number_it_is() {
    // Importing by number says nothing about what the function is, so the
    // number is what gets shown rather than a name guessed from a table.
    let mut blob = Blob::new(0x2000);
    let library = blob.string("WS2_32.dll");
    blob.align(8);
    let lookup = blob.next();
    blob.push(&((1u64 << 63) | 115).to_le_bytes());
    blob.push(&0u64.to_le_bytes());
    blob.align(4);
    let directory = blob.next();
    blob.u32(lookup);
    blob.u32(0);
    blob.u32(0);
    blob.u32(library);
    blob.u32(lookup);
    for _ in 0..5 {
        blob.u32(0);
    }
    let size = blob.next() - directory;

    let file = Builder::new()
        .section(".rdata", 0x2000, 0x4000_0040, blob.data)
        .directory(1, directory, size)
        .build();
    let pe = read(&file).unwrap();

    assert_eq!(pe.imports.len(), 1);
    assert_eq!(pe.imports[0].name, "ordinal 115");
}

#[test]
fn reads_exports_through_their_three_parallel_arrays() {
    let (data, directory, size) = export_blob(0x2000, &[("add", 0x1100), ("mul", 0x1120)]);
    let file = Builder::new()
        .dll()
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .section(".rdata", 0x2000, 0x4000_0040, data)
        .directory(0, directory, size)
        .build();
    let pe = read(&file).unwrap();

    let names: Vec<&str> = pe.exports.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["add", "mul"]);
    assert_eq!(pe.export_count, 2);
    // The address only comes back if the ordinal array was followed to the
    // address array, which is the part worth testing.
    assert_eq!(pe.exports[0].address, 0x1100);
    assert_eq!(pe.exports[1].address, 0x1120);
}

#[test]
fn reads_the_protections_out_of_the_characteristics_word() {
    const NX: u16 = 0x0100;
    const ASLR: u16 = 0x0040;
    const CFG: u16 = 0x4000;

    let on = Builder::new()
        .guards(NX | ASLR | CFG)
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .build();
    let pe = read(&on).unwrap();
    assert_eq!(pe.nx, Guard::On);
    assert_eq!(pe.pie, "yes");
    assert_eq!(pe.cfg, Some(true));

    let off = Builder::new()
        .guards(0)
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .build();
    let pe = read(&off).unwrap();
    assert_eq!(pe.nx, Guard::Off);
    assert_eq!(pe.pie, "no");
    assert_eq!(pe.cfg, Some(false));
}

#[test]
fn a_clear_bit_is_off_rather_than_undeclared() {
    // Unlike a missing PT_GNU_STACK, a clear bit in a field the image always
    // carries is a claim the file is making, so there is no third state.
    let file = minimal();
    assert_ne!(read(&file).unwrap().nx, Guard::Undeclared);
}

#[test]
fn finds_the_stack_cookie_in_the_load_configuration() {
    let mut blob = Blob::new(0x2000);
    let directory = blob.next();
    for _ in 0..88 {
        blob.push(&[0]);
    }
    blob.push(&0x1_4000_5000u64.to_le_bytes()); // SecurityCookie
    let size = blob.next() - directory;

    let file = Builder::new()
        .section(".rdata", 0x2000, 0x4000_0040, blob.data)
        .directory(10, directory, size)
        .build();
    assert!(read(&file).unwrap().canary);
}

#[test]
fn reports_no_cookie_when_the_load_configuration_is_too_old_to_hold_one() {
    // The structure has grown over the years, and an older image declares a
    // shorter one in which the field simply is not there.
    let mut blob = Blob::new(0x2000);
    let directory = blob.next();
    for _ in 0..40 {
        blob.push(&[0]);
    }
    let size = blob.next() - directory;

    let file = Builder::new()
        .section(".rdata", 0x2000, 0x4000_0040, blob.data)
        .directory(10, directory, size)
        .build();
    assert!(!read(&file).unwrap().canary);
}

#[test]
fn reads_the_build_path_out_of_the_debug_directory() {
    let mut blob = Blob::new(0x2000);
    let record = blob.next();
    blob.push(&[0; 12]);
    blob.u32(2); // CODEVIEW
    blob.u32(0); // SizeOfData
    blob.u32(0); // AddressOfRawData
    // A debug record names a file offset rather than an address, the one
    // place PE points straight into the file, so this is patched once the
    // layout has actually decided where the payload landed.
    const SENTINEL: u32 = 0xdead_beef;
    blob.u32(SENTINEL);
    let size = blob.next() - record;

    blob.align(4);
    blob.push(b"RSDS");
    blob.push(&[0; 20]); // build identifier and age
    blob.string(r"C:\Users\setter\challenge\build\chal.pdb");

    let mut file = Builder::new()
        .section(".rdata", 0x2000, 0x4000_0040, blob.data)
        .directory(6, record, size)
        .build();

    let payload_at = file
        .windows(4)
        .position(|w| w == b"RSDS")
        .expect("payload is in the file") as u32;
    let pointer_at = file
        .windows(4)
        .position(|w| w == SENTINEL.to_le_bytes())
        .expect("pointer field is in the file");
    file[pointer_at..pointer_at + 4].copy_from_slice(&payload_at.to_le_bytes());

    let pe = read(&file).unwrap();

    assert_eq!(
        pe.pdb_path.as_deref(),
        Some(r"C:\Users\setter\challenge\build\chal.pdb")
    );
}

#[test]
fn reports_a_file_with_no_coff_symbol_table_as_stripped() {
    assert!(read(&minimal()).unwrap().stripped);
    let kept = Builder::new()
        .with_symbol_table()
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .build();
    assert!(!read(&kept).unwrap().stripped);
}

#[test]
fn does_not_follow_a_directory_that_points_outside_every_section() {
    // A doctored image is the ordinary case here, and an address in no
    // section has no bytes to read rather than bytes somewhere else.
    let file = Builder::new()
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .directory(1, 0x9999_0000, 200)
        .directory(0, 0x9999_0000, 200)
        .build();
    let pe = read(&file).unwrap();

    assert!(pe.imports.is_empty());
    assert!(pe.exports.is_empty());
    assert!(pe.needed.is_empty());
}

#[test]
fn survives_a_section_table_that_runs_past_the_end_of_the_file() {
    let mut file = Builder::new()
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 64])
        .build();
    // Cut after the optional header but inside the section table, so the
    // headers are whole and the table they point at is not.
    file.truncate(0x40 + 4 + 20 + 240 + 8);

    let pe = read(&file).expect("the headers survive");
    assert_eq!(pe.machine, "x86-64");
    assert!(pe.sections.is_empty());
}

#[test]
fn declines_an_image_whose_optional_header_is_cut_short() {
    // Without it there is no image base, no entry point and no protections
    // to report, so there is nothing honest to return.
    let mut file = minimal();
    file.truncate(0x60);

    assert_eq!(read(&file), None);
}

#[test]
fn reads_the_subsystem_a_gui_program_asks_for() {
    let file = Builder::new()
        .subsystem(2)
        .section(".text", 0x1000, READ_EXECUTE, vec![0x90; 16])
        .build();
    assert_eq!(read(&file).unwrap().subsystem, Some("Windows GUI"));
}
