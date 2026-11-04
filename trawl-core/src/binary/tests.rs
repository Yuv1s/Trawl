use super::*;

#[test]
fn declines_a_file_that_is_neither_format() {
    assert_eq!(read(b"just some bytes, no magic here"), None);
    assert_eq!(json(b"just some bytes"), "null");
    assert!(crate::json::is_well_formed(&json(b"just some bytes")));
}

#[test]
fn routes_an_elf_to_the_elf_reader() {
    let elf = crate::elf::tests::minimal();
    let binary = read(&elf).expect("reads as ELF");
    assert_eq!(binary.format, "ELF");
    // The fields PE alone carries come back empty rather than invented.
    assert_eq!(binary.subsystem, None);
    assert_eq!(binary.cfg, None);
    assert!(binary.relro.is_some());
}

#[test]
fn routes_a_pe_to_the_pe_reader() {
    let pe = crate::pe::tests::minimal();
    let binary = read(&pe).expect("reads as PE");
    assert_eq!(binary.format, "PE");
    // And the same in reverse, for the fields only ELF has.
    assert_eq!(binary.relro, None);
    assert_eq!(binary.fortify, None);
    assert_eq!(binary.interpreter, None);
    assert!(binary.subsystem.is_some());
}

#[test]
fn json_from_both_formats_is_well_formed_and_shares_a_shape() {
    let from_elf = json(&crate::elf::tests::minimal());
    let from_pe = json(&crate::pe::tests::minimal());

    assert!(crate::json::is_well_formed(&from_elf), "{from_elf}");
    assert!(crate::json::is_well_formed(&from_pe), "{from_pe}");

    // One reader on the other side of the boundary reads both, so every key
    // one writes the other has to write too, whatever its value.
    for key in [
        "format", "class", "endianness", "machine", "kind", "entry", "interpreter", "runpath",
        "subsystem", "pdbPath", "stripped", "nx", "pie", "relro", "canary", "fortify", "cfg",
        "importCount", "exportCount", "needed", "sections", "segments", "imports", "exports",
    ] {
        let quoted = format!("\"{key}\":");
        assert!(from_elf.contains(&quoted), "ELF output is missing {key}");
        assert!(from_pe.contains(&quoted), "PE output is missing {key}");
    }
}

#[test]
fn a_table_of_one_header_read_sixty_five_thousand_times_is_listed_once_over() {
    // 128 bytes of file, a header size of zero, and a count at the top of its range.
    let mut file = vec![0u8; 128];
    file[..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[16..18].copy_from_slice(&3u16.to_le_bytes());
    file[18..20].copy_from_slice(&62u16.to_le_bytes());
    file[40..48].copy_from_slice(&64u64.to_le_bytes());
    file[60..62].copy_from_slice(&u16::MAX.to_le_bytes());

    let text = json(&file);
    assert!(crate::json::is_well_formed(&text));
    assert!(text.contains("\"sectionCount\":65535"), "the true count is still reported");
    assert_eq!(text.matches("\"flags\":").count(), MAX_TABLE_ROWS);
    assert!(text.contains("\"symbolsCapped\":false"));
}

#[test]
fn a_guard_names_its_three_states_apart() {
    assert_eq!(Guard::On.label(), "on");
    assert_eq!(Guard::Off.label(), "off");
    assert_eq!(Guard::Undeclared.label(), "not declared");
}
