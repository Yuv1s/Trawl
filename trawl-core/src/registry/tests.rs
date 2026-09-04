use super::*;
use crate::regf::tests::{BuildKey, BuildValue, hive_of, system_hive};

#[test]
fn declines_a_file_that_is_not_a_hive() {
    assert_eq!(read(b"not a hive"), None);
    assert_eq!(json(b"not a hive"), "null");
    assert!(crate::json::is_well_formed(&json(b"not a hive")));
}

#[test]
fn names_a_hive_from_the_path_it_carries_for_itself() {
    let file = hive_of(BuildKey::new("ROOT"), "\\??\\C:\\Users\\yuvi\\NTUSER.DAT");
    assert_eq!(read(&file).unwrap().kind, "NTUSER.DAT");
}

#[test]
fn names_a_hive_from_its_root_keys_when_the_path_says_nothing() {
    // A hive carved out of an image, or renamed, has no useful path. The
    // keys at the root still say what it is.
    let file = hive_of(
        BuildKey::new("ROOT")
            .child(BuildKey::new("Select"))
            .child(BuildKey::new("ControlSet001")),
        "",
    );
    assert_eq!(read(&file).unwrap().kind, "SYSTEM");

    let user = hive_of(
        BuildKey::new("ROOT")
            .child(BuildKey::new("Environment"))
            .child(BuildKey::new("Control Panel")),
        "",
    );
    assert_eq!(read(&user).unwrap().kind, "NTUSER.DAT");
}

#[test]
fn says_plainly_when_it_does_not_recognise_a_hive() {
    let file = hive_of(BuildKey::new("ROOT").child(BuildKey::new("Whatever")), "");
    assert_eq!(read(&file).unwrap().kind, "a hive this does not recognise");
}

#[test]
fn reads_the_devices_out_of_usbstor() {
    let file = system_hive();
    let report = read(&file).unwrap();

    assert_eq!(report.devices.len(), 2);

    let general = &report.devices[0];
    assert_eq!(general.source, "USBSTOR");
    assert_eq!(general.vendor, "General");
    assert_eq!(general.product, "USB Flash Disk");
    assert_eq!(general.revision, "1.00");
    assert_eq!(general.serial, "04028700000004C6&0");
    assert_eq!(general.friendly_name, "General USB Flash Disk USB Device");
    assert_eq!(general.last_written, "2024-06-01 12:00:00");

    let sandisk = &report.devices[1];
    assert_eq!(sandisk.vendor, "SanDisk");
    assert_eq!(sandisk.product, "Cruzer");
    assert_eq!(sandisk.last_written, "2024-09-05 09:33:20");
}

#[test]
fn tells_a_real_serial_from_one_windows_invented() {
    // The rule is exact: an ampersand in the second position means the
    // device reported no serial, so the identifier belongs to the port
    // rather than to the stick and does not follow it to another machine.
    let file = system_hive();
    let report = read(&file).unwrap();

    let real = report.devices.iter().find(|d| d.vendor == "General").unwrap();
    assert!(!real.generated_serial, "04028700000004C6&0 is a real serial");

    let invented = report.devices.iter().find(|d| d.vendor == "SanDisk").unwrap();
    assert!(invented.generated_serial, "7&1ec5b3e5&0 was generated");
}

#[test]
fn reads_every_control_set_rather_than_only_the_first() {
    // CurrentControlSet exists only in memory. On disk there are numbered
    // sets, and a device can be in one and not the others.
    let file = hive_of(
        BuildKey::new("ROOT")
            .child(
                BuildKey::new("ControlSet001").child(
                    BuildKey::new("Enum").child(
                        BuildKey::new("USBSTOR").child(
                            BuildKey::new("Disk&Ven_A&Prod_First&Rev_1.0")
                                .child(BuildKey::new("AAAA1111&0")),
                        ),
                    ),
                ),
            )
            .child(
                BuildKey::new("ControlSet002").child(
                    BuildKey::new("Enum").child(
                        BuildKey::new("USBSTOR").child(
                            BuildKey::new("Disk&Ven_B&Prod_Second&Rev_2.0")
                                .child(BuildKey::new("BBBB2222&0")),
                        ),
                    ),
                ),
            ),
        "\\??\\C:\\Windows\\System32\\SYSTEM",
    );

    let report = read(&file).unwrap();
    let vendors: Vec<&str> = report.devices.iter().map(|d| d.vendor.as_str()).collect();
    assert_eq!(vendors, vec!["A", "B"]);
    assert!(report.searched.iter().any(|p| p.starts_with("ControlSet001")));
    assert!(report.searched.iter().any(|p| p.starts_with("ControlSet002")));
}

#[test]
fn counts_a_device_recorded_in_several_control_sets_once() {
    // The control sets are near copies of each other, so one stick is
    // normally in all of them. Reporting it three times would be wrong on
    // its own, and it also collides with anything keying off the serial.
    let device = |vendor: &str, seen: u64| {
        BuildKey::new("Enum").child(
            BuildKey::new("USBSTOR").child(
                BuildKey::new(&format!("Disk&Ven_{vendor}&Prod_Stick&Rev_1.0"))
                    .child(BuildKey::new("SERIAL0001&0").at(seen)),
            ),
        )
    };

    let file = hive_of(
        BuildKey::new("ROOT")
            .child(BuildKey::new("Select"))
            .child(BuildKey::new("ControlSet001").child(device("Kingston", 133_617_168_000_000_000)))
            .child(BuildKey::new("ControlSet002").child(device("Kingston", 133_700_024_000_000_000))),
        "",
    );

    let report = read(&file).unwrap();
    assert_eq!(report.devices.len(), 1, "one stick, however many sets hold it");
    // The latest of the two is the one worth keeping.
    assert_eq!(report.devices[0].last_written, "2024-09-05 09:33:20");
    // Both sets were still searched, and both are reported as searched.
    assert_eq!(report.searched.len(), 4);
}

#[test]
fn reads_the_mount_points_a_user_hive_keeps() {
    let file = hive_of(
        BuildKey::new("ROOT")
            .child(BuildKey::new("Environment"))
            .child(BuildKey::new("Control Panel"))
            .child(
                BuildKey::new("Software").child(
                    BuildKey::new("Microsoft").child(
                        BuildKey::new("Windows").child(
                            BuildKey::new("CurrentVersion").child(
                                BuildKey::new("Explorer").child(
                                    BuildKey::new("MountPoints2").child(
                                        BuildKey::new(
                                            "##?#USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.26#4C531001#",
                                        )
                                        .at(133_700_024_000_000_000),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        "\\??\\C:\\Users\\yuvi\\NTUSER.DAT",
    );

    let report = read(&file).unwrap();
    assert_eq!(report.devices.len(), 1);

    let device = &report.devices[0];
    assert_eq!(device.source, "MountPoints2");
    assert_eq!(device.vendor, "SanDisk");
    assert_eq!(device.product, "Cruzer");
    assert_eq!(device.last_written, "2024-09-05 09:33:20");
}

#[test]
fn says_where_it_looked_even_when_it_found_nothing() {
    // An empty result has two very different meanings, and the list of
    // paths searched is what separates them: a SYSTEM hive with no device
    // history, or a hive that would never have carried any.
    let empty_system = hive_of(
        BuildKey::new("ROOT")
            .child(BuildKey::new("Select"))
            .child(BuildKey::new("ControlSet001").child(BuildKey::new("Enum"))),
        "",
    );
    let report = read(&empty_system).unwrap();
    assert!(report.devices.is_empty());
    assert!(
        report.searched.iter().any(|p| p.contains("USBSTOR")),
        "a SYSTEM hive is searched for devices even when it has none"
    );

    let software = hive_of(BuildKey::new("ROOT").child(BuildKey::new("Classes")), "");
    let report = read(&software).unwrap();
    assert!(report.devices.is_empty());
    assert!(
        report.searched.is_empty(),
        "a hive with no control sets has nowhere to look"
    );
}

#[test]
fn splits_a_device_name_into_what_it_names() {
    assert_eq!(
        parse_device_name("Disk&Ven_General&Prod_USB_Flash_Disk&Rev_1.00"),
        (
            "General".to_string(),
            "USB Flash Disk".to_string(),
            "1.00".to_string()
        )
    );

    // A USB key names a device numerically instead, and there is nothing to
    // split out of it.
    assert_eq!(
        parse_device_name("VID_0781&PID_5567"),
        (String::new(), String::new(), String::new())
    );
}

#[test]
fn keeps_a_numeric_usb_model_name_rather_than_reporting_it_blank() {
    let file = hive_of(
        BuildKey::new("ROOT")
            .child(BuildKey::new("Select"))
            .child(
                BuildKey::new("ControlSet001").child(
                    BuildKey::new("Enum").child(
                        BuildKey::new("USB").child(
                            BuildKey::new("VID_0781&PID_5567")
                                .child(BuildKey::new("4C531001560531119142")),
                        ),
                    ),
                ),
            ),
        "",
    );

    let report = read(&file).unwrap();
    assert_eq!(report.devices.len(), 1);
    assert_eq!(report.devices[0].source, "USB");
    assert_eq!(report.devices[0].vendor, "VID_0781&PID_5567");
    assert!(!report.devices[0].generated_serial);
}

#[test]
fn reports_the_top_level_keys_for_orientation() {
    let file = hive_of(
        BuildKey::new("ROOT")
            .child(BuildKey::new("Environment").value(BuildValue::string("TEMP", "C:\\Temp")))
            .child(BuildKey::new("Control Panel")),
        "",
    );

    let report = read(&file).unwrap();
    assert_eq!(report.top.len(), 2);
    assert_eq!(report.top[0].name, "Environment");
    assert_eq!(report.top[0].values, 1);
    assert_eq!(report.top[1].name, "Control Panel");
}

#[test]
fn json_output_is_well_formed_with_every_field_populated() {
    let out = json(&system_hive());
    assert!(crate::json::is_well_formed(&out), "malformed JSON: {out}");
    assert!(out.contains("\"SanDisk\""), "{out}");
    assert!(out.contains("\"generatedSerial\":true"), "{out}");
    assert!(out.contains("\"USBSTOR\""), "{out}");
}
