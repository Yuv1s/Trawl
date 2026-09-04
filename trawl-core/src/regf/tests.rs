use super::*;

/// Builds a genuine hive from parts.
///
/// A hive is a tree of cells that reference each other by offset, so
/// everything here is written bottom up: a key's values and children have to
/// exist, and have addresses, before the key that points at them can be
/// written. `alloc` hands back the offset of whatever it just wrote, which
/// is what makes that possible without counting bytes by hand.
pub(crate) struct Builder {
    /// The hive bins area, which every offset in the file is measured from.
    bins: Vec<u8>,
}

/// One value to write into a key.
pub(crate) struct BuildValue {
    name: String,
    kind: u32,
    data: Vec<u8>,
}

impl BuildValue {
    pub(crate) fn string(name: &str, text: &str) -> Self {
        let mut data: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        data.extend_from_slice(&[0, 0]);
        Self {
            name: name.to_string(),
            kind: 1,
            data,
        }
    }

    pub(crate) fn dword(name: &str, value: u32) -> Self {
        Self {
            name: name.to_string(),
            kind: 4,
            data: value.to_le_bytes().to_vec(),
        }
    }

    pub(crate) fn binary(name: &str, data: Vec<u8>) -> Self {
        Self {
            name: name.to_string(),
            kind: 3,
            data,
        }
    }

    pub(crate) fn multi(name: &str, parts: &[&str]) -> Self {
        let mut text = String::new();
        for part in parts {
            text.push_str(part);
            text.push('\0');
        }
        text.push('\0');
        Self {
            name: name.to_string(),
            kind: 7,
            data: text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        }
    }
}

/// A key to write, with its children, so a whole subtree can be described in
/// one expression and written in the order the format needs.
pub(crate) struct BuildKey {
    name: String,
    written: u64,
    values: Vec<BuildValue>,
    children: Vec<BuildKey>,
}

impl BuildKey {
    pub(crate) fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            // 2024-06-01 12:00:00 UTC, so a fixture's timestamps are a date
            // a person can recognise rather than noise.
            written: 133_617_168_000_000_000,
            values: Vec::new(),
            children: Vec::new(),
        }
    }

    pub(crate) fn at(mut self, written: u64) -> Self {
        self.written = written;
        self
    }

    pub(crate) fn value(mut self, value: BuildValue) -> Self {
        self.values.push(value);
        self
    }

    pub(crate) fn child(mut self, child: BuildKey) -> Self {
        self.children.push(child);
        self
    }
}

impl Builder {
    pub(crate) fn new() -> Self {
        // The bins area opens with an hbin header, which the cells follow.
        let mut bins = Vec::new();
        bins.extend_from_slice(b"hbin");
        bins.extend_from_slice(&0u32.to_le_bytes()); // this bin's own offset
        bins.extend_from_slice(&0u32.to_le_bytes()); // size, filled in at the end
        bins.extend_from_slice(&[0u8; 24]);
        Self { bins }
    }

    /// Writes one cell and returns the offset it can be referenced by. A
    /// negative size is what marks a cell as in use rather than freed.
    fn alloc(&mut self, body: &[u8]) -> u32 {
        let at = self.bins.len() as u32;
        let size = (4 + body.len()).div_ceil(8) * 8;
        self.bins
            .extend_from_slice(&(-(size as i32)).to_le_bytes());
        self.bins.extend_from_slice(body);
        self.bins.resize(at as usize + size, 0);
        at
    }

    fn write_value(&mut self, value: &BuildValue) -> u32 {
        let data_offset = self.alloc(&value.data);

        let mut body = Vec::new();
        body.extend_from_slice(b"vk");
        body.extend_from_slice(&(value.name.len() as u16).to_le_bytes());
        body.extend_from_slice(&(value.data.len() as u32).to_le_bytes());
        body.extend_from_slice(&data_offset.to_le_bytes());
        body.extend_from_slice(&value.kind.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // the name is ASCII
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(value.name.as_bytes());
        self.alloc(&body)
    }

    pub(crate) fn write_key(&mut self, key: &BuildKey) -> u32 {
        let value_offsets: Vec<u32> = key.values.iter().map(|v| self.write_value(v)).collect();
        let value_list = if value_offsets.is_empty() {
            u32::MAX
        } else {
            let body: Vec<u8> = value_offsets
                .iter()
                .flat_map(|o| o.to_le_bytes())
                .collect();
            self.alloc(&body)
        };

        let child_offsets: Vec<u32> = key.children.iter().map(|c| self.write_key(c)).collect();
        let subkey_list = if child_offsets.is_empty() {
            u32::MAX
        } else {
            let mut body = Vec::new();
            body.extend_from_slice(b"lf");
            body.extend_from_slice(&(child_offsets.len() as u16).to_le_bytes());
            for (offset, child) in child_offsets.iter().zip(&key.children) {
                body.extend_from_slice(&offset.to_le_bytes());
                let hint = child.name.as_bytes();
                let mut four = [0u8; 4];
                four[..hint.len().min(4)].copy_from_slice(&hint[..hint.len().min(4)]);
                body.extend_from_slice(&four);
            }
            self.alloc(&body)
        };

        let mut body = vec![0u8; 0x4c];
        body[0..2].copy_from_slice(b"nk");
        body[2..4].copy_from_slice(&0x20u16.to_le_bytes()); // ASCII name
        body[4..12].copy_from_slice(&key.written.to_le_bytes());
        body[0x10..0x14].copy_from_slice(&u32::MAX.to_le_bytes()); // parent
        body[0x14..0x18].copy_from_slice(&(key.children.len() as u32).to_le_bytes());
        body[0x1c..0x20].copy_from_slice(&subkey_list.to_le_bytes());
        body[0x24..0x28].copy_from_slice(&(key.values.len() as u32).to_le_bytes());
        body[0x28..0x2c].copy_from_slice(&value_list.to_le_bytes());
        body[0x2c..0x30].copy_from_slice(&u32::MAX.to_le_bytes()); // security
        body[0x30..0x34].copy_from_slice(&u32::MAX.to_le_bytes()); // class
        body[0x48..0x4a].copy_from_slice(&(key.name.len() as u16).to_le_bytes());
        body.extend_from_slice(key.name.as_bytes());
        self.alloc(&body)
    }

    /// Wraps the bins in a base block, which is what makes the whole thing a
    /// file rather than a heap.
    pub(crate) fn finish(mut self, root: u32, name: &str) -> Vec<u8> {
        let size = self.bins.len().div_ceil(4096) * 4096;
        self.bins.resize(size, 0);
        self.bins[8..12].copy_from_slice(&(size as u32).to_le_bytes());

        let mut out = vec![0u8; BASE_BLOCK];
        out[0..4].copy_from_slice(b"regf");
        out[0x0c..0x14].copy_from_slice(&133_617_168_000_000_000u64.to_le_bytes());
        out[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major
        out[0x18..0x1c].copy_from_slice(&5u32.to_le_bytes()); // minor
        out[0x1c..0x20].copy_from_slice(&1u32.to_le_bytes()); // primary file
        out[0x24..0x28].copy_from_slice(&root.to_le_bytes());
        out[0x28..0x2c].copy_from_slice(&(size as u32).to_le_bytes());

        let encoded: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let room = encoded.len().min(62);
        out[0x30..0x30 + room].copy_from_slice(&encoded[..room]);

        out.extend_from_slice(&self.bins);
        out
    }
}

/// A hive holding one key tree, which is what most of these tests need.
pub(crate) fn hive_of(root: BuildKey, name: &str) -> Vec<u8> {
    let mut builder = Builder::new();
    let offset = builder.write_key(&root);
    builder.finish(offset, name)
}

/// A SYSTEM hive shaped the way a real one is, down to the device key naming
/// that Windows actually writes. The device below is the shape this machine's
/// own USBSTOR key holds.
pub(crate) fn system_hive() -> Vec<u8> {
    hive_of(
        BuildKey::new("ROOT").child(
            BuildKey::new("ControlSet001").child(
                BuildKey::new("Enum").child(
                    BuildKey::new("USBSTOR")
                        .child(
                            BuildKey::new("Disk&Ven_General&Prod_USB_Flash_Disk&Rev_1.00").child(
                                BuildKey::new("04028700000004C6&0")
                                    .at(133_617_168_000_000_000)
                                    .value(BuildValue::string(
                                        "FriendlyName",
                                        "General USB Flash Disk USB Device",
                                    ))
                                    .value(BuildValue::string("Service", "disk"))
                                    .value(BuildValue::string(
                                        "Mfg",
                                        "@disk.inf,%genmanufacturer%;(Standard disk drives)",
                                    )),
                            ),
                        )
                        .child(
                            BuildKey::new("Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.26").child(
                                BuildKey::new("7&1ec5b3e5&0")
                                    .at(133_700_024_000_000_000)
                                    .value(BuildValue::string(
                                        "FriendlyName",
                                        "SanDisk Cruzer USB Device",
                                    )),
                            ),
                        ),
                ),
            ),
        ),
        "\\??\\C:\\Windows\\System32\\SYSTEM",
    )
}

#[test]
fn declines_a_file_that_is_not_a_hive() {
    assert!(Hive::open(b"not a hive at all").is_none());
    assert!(Hive::open(&[0u8; 8]).is_none());
    // The magic alone is not enough: a hive is at least a base block long.
    assert!(Hive::open(b"regf and then nothing").is_none());
}

#[test]
fn reads_the_base_block() {
    let file = hive_of(BuildKey::new("ROOT"), "\\??\\C:\\Windows\\System32\\SYSTEM");
    let hive = Hive::open(&file).unwrap();

    assert_eq!(hive.version, "1.5");
    assert_eq!(hive.file_name, "\\??\\C:\\Windows\\System32\\SYSTEM");
    assert_eq!(hive.written, "2024-06-01 12:00:00");
}

#[test]
fn reads_the_root_key_and_its_children() {
    let file = hive_of(
        BuildKey::new("ROOT")
            .child(BuildKey::new("Software"))
            .child(BuildKey::new("System"))
            .child(BuildKey::new("Environment")),
        "NTUSER.DAT",
    );
    let hive = Hive::open(&file).unwrap();

    let root = hive.root().unwrap();
    assert_eq!(root.name, "ROOT");
    assert_eq!(root.subkeys, 3);

    let names: Vec<String> = hive
        .children(hive.root_offset())
        .into_iter()
        .map(|(_, key)| key.name)
        .collect();
    assert_eq!(names, vec!["Software", "System", "Environment"]);
}

#[test]
fn walks_a_path_down_the_tree() {
    let hive_bytes = system_hive();
    let hive = Hive::open(&hive_bytes).unwrap();

    let (_, key) = hive.find("ControlSet001\\Enum\\USBSTOR").unwrap();
    assert_eq!(key.name, "USBSTOR");
    assert_eq!(key.subkeys, 2);
}

#[test]
fn matches_a_path_without_caring_about_case() {
    // Windows does not distinguish, so neither does this. A path typed by a
    // person is the ordinary way in here.
    let hive_bytes = system_hive();
    let hive = Hive::open(&hive_bytes).unwrap();

    assert!(hive.find("controlset001\\enum\\usbstor").is_some());
    assert!(hive.find("CONTROLSET001\\ENUM\\USBSTOR").is_some());
}

#[test]
fn returns_nothing_for_a_path_that_is_not_there() {
    let hive_bytes = system_hive();
    let hive = Hive::open(&hive_bytes).unwrap();

    assert!(hive.find("ControlSet001\\Enum\\NoSuchKey").is_none());
    assert!(hive.find("Nonsense").is_none());
}

#[test]
fn reads_each_value_type_as_what_it_is() {
    let file = hive_of(
        BuildKey::new("ROOT")
            .value(BuildValue::string("Name", "General USB Flash Disk"))
            .value(BuildValue::dword("Count", 42))
            .value(BuildValue::binary("Blob", vec![0xde, 0xad, 0xbe, 0xef]))
            .value(BuildValue::multi("List", &["first", "second"])),
        "NTUSER.DAT",
    );
    let hive = Hive::open(&file).unwrap();
    let root = hive.root().unwrap();

    let value = |name: &str| root.values.iter().find(|v| v.name == name).unwrap();

    assert_eq!(value("Name").kind, "REG_SZ");
    assert_eq!(value("Name").data, "General USB Flash Disk");

    assert_eq!(value("Count").kind, "REG_DWORD");
    assert_eq!(value("Count").data, "42");

    assert_eq!(value("Blob").kind, "REG_BINARY");
    assert_eq!(value("Blob").data, "de ad be ef");

    assert_eq!(value("List").kind, "REG_MULTI_SZ");
    assert_eq!(value("List").data, "first, second");
}

#[test]
fn reads_a_key_written_time() {
    let file = hive_of(
        BuildKey::new("ROOT").child(BuildKey::new("Later").at(133_700_024_000_000_000)),
        "NTUSER.DAT",
    );
    let hive = Hive::open(&file).unwrap();

    let (_, key) = hive.find("Later").unwrap();
    assert_eq!(key.written, "2024-09-05 09:33:20");
}

#[test]
fn keeps_the_name_field_to_the_room_the_format_gives_it() {
    // The field is 64 bytes, so a longer path is cut rather than allowed to
    // run into the fields after it. Real hives keep the path short enough
    // to fit; this is what happens when one does not.
    let file = hive_of(BuildKey::new("ROOT"), "\\SystemRoot\\System32\\Config\\SYSTEM");
    let hive = Hive::open(&file).unwrap();

    assert_eq!(hive.file_name.chars().count(), 31);
    assert!(hive.file_name.starts_with("\\SystemRoot\\System32\\Config"));
}

#[test]
fn converts_a_filetime_to_a_date() {
    // Checked against the values Windows itself reports for these instants.
    assert_eq!(filetime(133_617_168_000_000_000), "2024-06-01 12:00:00");
    assert_eq!(filetime(116_444_736_000_000_000), "1970-01-01 00:00:00");
    assert_eq!(filetime(0), "");
}

#[test]
fn a_leap_day_lands_on_the_right_date() {
    // 2024-02-29, which is the case a day-count conversion gets wrong first.
    assert_eq!(filetime(133_536_816_000_000_000), "2024-02-29 12:00:00");
}

#[test]
fn does_not_read_a_cell_that_was_freed() {
    // A positive size means the cell was released and its bytes are
    // leftovers. Reading one as live reports whatever the space last held.
    let mut file = system_hive();
    let hive = Hive::open(&file).unwrap();
    let (offset, _) = hive.find("ControlSet001").unwrap();

    let at = BASE_BLOCK + offset as usize;
    let size = i32::from_le_bytes(file[at..at + 4].try_into().unwrap());
    file[at..at + 4].copy_from_slice(&(-size).to_le_bytes());

    let hive = Hive::open(&file).unwrap();
    assert!(hive.find("ControlSet001").is_none());
}

#[test]
fn survives_a_key_that_points_outside_the_file() {
    let mut file = hive_of(BuildKey::new("ROOT").child(BuildKey::new("Child")), "NTUSER.DAT");
    let root = u32::from_le_bytes(file[0x24..0x28].try_into().unwrap());

    // Point the root's subkey list at an offset far past the end.
    let at = BASE_BLOCK + root as usize + 4 + 0x1c;
    file[at..at + 4].copy_from_slice(&0x7fff_0000u32.to_le_bytes());

    let hive = Hive::open(&file).unwrap();
    assert_eq!(hive.root().unwrap().name, "ROOT");
    assert!(hive.children(hive.root_offset()).is_empty());
}

#[test]
fn survives_a_truncated_hive() {
    let mut file = system_hive();
    file.truncate(BASE_BLOCK + 64);

    // The base block is intact, so the header still reads. The tree it
    // points at is not there, and comes back empty rather than inventing
    // something.
    let hive = Hive::open(&file).unwrap();
    assert_eq!(hive.version, "1.5");
    assert!(hive.find("ControlSet001").is_none());
}

#[test]
fn reads_a_name_stored_as_utf16() {
    // Bit 5 clear means two bytes per character. A reader that assumes ASCII
    // returns every other letter, which looks like corruption rather than a
    // bug in the reader.
    let mut file = hive_of(BuildKey::new("ROOT").child(BuildKey::new("Wide")), "NTUSER.DAT");
    let hive = Hive::open(&file).unwrap();
    let (offset, _) = hive.find("Wide").unwrap();

    let at = BASE_BLOCK + offset as usize + 4;
    let wide: Vec<u8> = "Wide".encode_utf16().flat_map(u16::to_le_bytes).collect();
    file[at + 2..at + 4].copy_from_slice(&0u16.to_le_bytes()); // clear the ASCII flag
    file[at + 0x48..at + 0x4a].copy_from_slice(&(wide.len() as u16).to_le_bytes());
    file[at + 0x4c..at + 0x4c + wide.len()].copy_from_slice(&wide);

    let hive = Hive::open(&file).unwrap();
    assert_eq!(hive.children(hive.root_offset())[0].1.name, "Wide");
}
