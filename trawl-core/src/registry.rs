//! What a registry hive says about the USB devices that were plugged into
//! the machine it came from.
//!
//! [`crate::regf`] reads the format. This reads the meaning, which is a
//! separate job and a much less certain one. The format is a specification;
//! this is a set of conventions about where Windows happens to write things,
//! and it can be wrong in ways a parser cannot: a key may have been touched
//! by something other than the event it usually records.
//!
//! So the claim here is deliberately narrow. A key carries the time it was
//! last written, and `USBSTOR` keys are written when a device is connected,
//! which makes that timestamp the best evidence in the hive for when a stick
//! was last plugged in. It is not a connection log, nothing here says the
//! device was ever removed, and a key can be rewritten by a driver update
//! that had nothing to do with anyone touching a port. What gets reported is
//! the timestamp and what it is, rather than a conclusion drawn from it.
//!
//! The one inference made outright is the serial number, because the rule is
//! exact rather than probabilistic: when the second character of a device's
//! instance identifier is an ampersand, the device did not report a serial
//! and Windows generated the identifier itself. That distinction matters,
//! since an identifier of the first kind follows the physical device between
//! machines and one of the second kind does not.

use crate::regf::{Hive, Key};

/// One device the hive remembers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Which key this came out of, since the three carry different evidence.
    pub source: &'static str,
    pub vendor: String,
    pub product: String,
    pub revision: String,
    /// The instance identifier, which is the device's own serial when it had
    /// one to give.
    pub serial: String,
    pub friendly_name: String,
    /// When the device's own key was last written.
    pub last_written: String,
    /// True when Windows made the identifier up because the device reported
    /// no serial of its own.
    pub generated_serial: bool,
}

/// A key worth naming in the report, for orientation rather than evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLine {
    pub name: String,
    pub subkeys: usize,
    pub values: usize,
    pub written: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub version: String,
    /// Which hive this is, worked out from the path it names for itself and
    /// the keys at its root.
    pub kind: &'static str,
    pub file_name: String,
    pub written: String,
    pub root: String,
    pub top: Vec<KeyLine>,
    pub devices: Vec<Device>,
    /// The paths that were looked at, so an empty result says which it is:
    /// a hive with no device history, or a hive that would never have held
    /// any in the first place.
    pub searched: Vec<String>,
}

/// Which hive this is.
///
/// The name a hive carries for itself is the best evidence, since Windows
/// writes the path it was loaded from. A hive that was renamed or carved out
/// of an image may not have one, so the keys at the root are the fallback:
/// each kind of hive has a set that only it has.
fn identify(hive: &Hive, root: &Key, top: &[KeyLine]) -> &'static str {
    let name = hive.file_name.to_ascii_uppercase();
    for (needle, label) in [
        ("NTUSER.DAT", "NTUSER.DAT"),
        ("USRCLASS.DAT", "UsrClass.dat"),
        ("SYSTEM", "SYSTEM"),
        ("SOFTWARE", "SOFTWARE"),
        ("SECURITY", "SECURITY"),
        ("SAM", "SAM"),
    ] {
        if name.contains(needle) {
            return label;
        }
    }

    let has = |wanted: &str| top.iter().any(|k| k.name.eq_ignore_ascii_case(wanted));
    if has("Select") && has("ControlSet001") {
        "SYSTEM"
    } else if has("Microsoft") && has("Classes") {
        "SOFTWARE"
    } else if has("Environment") && has("Control Panel") {
        "NTUSER.DAT"
    } else {
        let _ = root;
        "a hive this does not recognise"
    }
}

/// Splits a `USBSTOR` device key name into what it names.
///
/// The format is `Disk&Ven_X&Prod_Y&Rev_Z`, with underscores where the
/// original text had spaces, which is why the product usually reads as one
/// long run of words.
fn parse_device_name(name: &str) -> (String, String, String) {
    let mut vendor = String::new();
    let mut product = String::new();
    let mut revision = String::new();

    for part in name.split('&') {
        let cleaned = |value: &str| value.replace('_', " ").trim().to_string();
        if let Some(value) = part.strip_prefix("Ven_") {
            vendor = cleaned(value);
        } else if let Some(value) = part.strip_prefix("Prod_") {
            product = cleaned(value);
        } else if let Some(value) = part.strip_prefix("Rev_") {
            revision = cleaned(value);
        }
    }

    (vendor, product, revision)
}

/// Whether Windows invented this identifier rather than reading it off the
/// device.
///
/// The rule is the documented one: an ampersand in the second position means
/// the device reported no serial number, so the identifier belongs to the
/// port and the machine rather than to the stick.
fn is_generated(instance: &str) -> bool {
    instance.chars().nth(1) == Some('&')
}

fn value_of(key: &Key, name: &str) -> String {
    key.values
        .iter()
        .find(|v| v.name.eq_ignore_ascii_case(name))
        .map(|v| v.data.clone())
        .unwrap_or_default()
}

/// Every control set a SYSTEM hive holds. A live machine has one
/// `CurrentControlSet`, but that name exists only in memory: on disk there
/// are numbered sets, and which one was current is named elsewhere. Both are
/// read, since a device may appear in one and not the other.
fn control_sets(hive: &Hive) -> Vec<String> {
    hive.children(hive.root_offset())
        .into_iter()
        .map(|(_, key)| key.name)
        .filter(|name| {
            name.len() > 10
                && name[..10].eq_ignore_ascii_case("ControlSet")
                && name[10..].chars().all(|c| c.is_ascii_digit())
        })
        .collect()
}

/// The `USBSTOR` and `USB` trees, which are two levels deep: a key per
/// device model, and under each one a key per physical device.
fn enumerated_devices(hive: &Hive, base: &str, source: &'static str) -> Vec<Device> {
    let Some((offset, _)) = hive.find(base) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (model_offset, model) in hive.children(offset) {
        let (vendor, product, revision) = parse_device_name(&model.name);

        for (_, instance) in hive.children(model_offset) {
            out.push(Device {
                source,
                // A USB key names a device by its numeric vendor and product
                // codes rather than in words, so the model name is kept as
                // it stands when there is nothing to split out of it.
                vendor: if vendor.is_empty() {
                    model.name.clone()
                } else {
                    vendor.clone()
                },
                product: product.clone(),
                revision: revision.clone(),
                generated_serial: is_generated(&instance.name),
                serial: instance.name.clone(),
                friendly_name: value_of(&instance, "FriendlyName"),
                last_written: instance.written.clone(),
            });
        }
    }

    out
}

/// `MountPoints2`, which a user hive keeps: one key per volume the user
/// mounted, named after the device that carried it.
fn mount_points(hive: &Hive) -> Vec<Device> {
    const PATH: &str =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";

    let Some((offset, _)) = hive.find(PATH) else {
        return Vec::new();
    };

    hive.children(offset)
        .into_iter()
        .filter(|(_, key)| key.name.contains("USBSTOR") || key.name.contains("##?#"))
        .map(|(_, key)| {
            // The key name is a device path with # where a backslash was.
            // How many parts come before the model varies, so the model is
            // found by what it looks like rather than by counting: it is the
            // part naming a vendor, and the device's own identifier is the
            // part after it.
            let parts: Vec<&str> = key.name.split('#').filter(|p| !p.is_empty()).collect();
            let at = parts
                .iter()
                .position(|p| p.contains("Ven_") || p.contains("VID_"));
            let model = at.and_then(|i| parts.get(i)).copied().unwrap_or_default();
            let instance = at.and_then(|i| parts.get(i + 1)).copied().unwrap_or_default();
            let (vendor, product, revision) = parse_device_name(model);

            Device {
                source: "MountPoints2",
                vendor,
                product,
                revision,
                generated_serial: is_generated(instance),
                serial: instance.to_string(),
                friendly_name: String::new(),
                last_written: key.written.clone(),
            }
        })
        .collect()
}

pub fn read(data: &[u8]) -> Option<Report> {
    let hive = Hive::open(data)?;
    let root = hive.root()?;

    let top: Vec<KeyLine> = hive
        .children(hive.root_offset())
        .into_iter()
        .map(|(_, key)| KeyLine {
            name: key.name,
            subkeys: key.subkeys,
            values: key.values.len(),
            written: key.written,
        })
        .collect();

    let kind = identify(&hive, &root, &top);

    let mut devices: Vec<Device> = Vec::new();
    let mut searched = Vec::new();

    for set in control_sets(&hive) {
        for (leaf, source) in [("USBSTOR", "USBSTOR"), ("USB", "USB")] {
            let path = format!("{set}\\Enum\\{leaf}");
            for found in enumerated_devices(&hive, &path, source) {
                // A machine keeps several control sets and they are near
                // copies of each other, so one stick is normally recorded in
                // every one of them. That is one device, not three, and the
                // useful timestamp is the latest any of them recorded.
                match devices
                    .iter_mut()
                    .find(|seen| seen.source == found.source && seen.serial == found.serial)
                {
                    Some(seen) => {
                        if found.last_written > seen.last_written {
                            seen.last_written = found.last_written;
                        }
                    }
                    None => devices.push(found),
                }
            }
            searched.push(path);
        }
    }

    let mounts = mount_points(&hive);
    if !mounts.is_empty() || kind == "NTUSER.DAT" {
        searched.push(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2".to_string(),
        );
    }
    devices.extend(mounts);

    Some(Report {
        version: hive.version.clone(),
        kind,
        file_name: hive.file_name.clone(),
        written: hive.written.clone(),
        root: root.name,
        top,
        devices,
        searched,
    })
}

pub fn json(data: &[u8]) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let Some(report) = read(data) else {
        return "null".to_string();
    };

    let mut out = String::from("{");
    push_field(&mut out, "version", &report.version);
    out.push(',');
    push_field(&mut out, "kind", report.kind);
    out.push(',');
    push_field(&mut out, "fileName", &report.file_name);
    out.push(',');
    push_field(&mut out, "written", &report.written);
    out.push(',');
    push_field(&mut out, "root", &report.root);
    out.push(',');

    push_string(&mut out, "searched");
    out.push_str(":[");
    for (i, path) in report.searched.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_string(&mut out, path);
    }
    out.push_str("],");

    push_string(&mut out, "top");
    out.push_str(":[");
    for (i, key) in report.top.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "name", &key.name);
        out.push(',');
        push_number(&mut out, "subkeys", key.subkeys);
        out.push(',');
        push_number(&mut out, "values", key.values);
        out.push(',');
        push_field(&mut out, "written", &key.written);
        out.push('}');
    }
    out.push_str("],");

    push_string(&mut out, "devices");
    out.push_str(":[");
    for (i, device) in report.devices.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "source", device.source);
        out.push(',');
        push_field(&mut out, "vendor", &device.vendor);
        out.push(',');
        push_field(&mut out, "product", &device.product);
        out.push(',');
        push_field(&mut out, "revision", &device.revision);
        out.push(',');
        push_field(&mut out, "serial", &device.serial);
        out.push(',');
        push_field(&mut out, "friendlyName", &device.friendly_name);
        out.push(',');
        push_field(&mut out, "lastWritten", &device.last_written);
        out.push(',');
        push_bool(&mut out, "generatedSerial", device.generated_serial);
        out.push('}');
    }
    out.push_str("]}");

    out
}

#[cfg(test)]
mod tests;
