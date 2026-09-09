use argowei_core::network_interface::{NetworkInterface, NetworkInterfaceKind};
use std::{fs, io, path::Path};

pub fn run() -> io::Result<()> {
    let interfaces = read_linux_network_interfaces(Path::new("/sys/class/net"))?;
    print_interfaces(&interfaces);

    Ok(())
}

fn read_linux_network_interfaces(sys_class_net: &Path) -> io::Result<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();

    for entry in fs::read_dir(sys_class_net)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();

        let interface = NetworkInterface {
            kind: classify_interface(&name, &path),
            mac_address: read_optional_trimmed(path.join("address")),
            oper_state: read_optional_trimmed(path.join("operstate")),
            name,
        };

        interfaces.push(interface);
    }

    interfaces.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(interfaces)
}

fn classify_interface(name: &str, path: &Path) -> NetworkInterfaceKind {
    if name == "lo" {
        return NetworkInterfaceKind::Loopback;
    }

    if path.join("wireless").exists() {
        return NetworkInterfaceKind::Wireless;
    }

    match fs::read_link(path) {
        Ok(target) if target.to_string_lossy().contains("/devices/virtual/net/") => {
            NetworkInterfaceKind::Virtual
        }
        Ok(_) => NetworkInterfaceKind::Ethernet,
        Err(_) => NetworkInterfaceKind::Unknown,
    }
}

fn read_trimmed(path: impl AsRef<Path>) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn read_optional_trimmed(path: impl AsRef<Path>) -> Option<String> {
    read_trimmed(path).ok().filter(|value| !value.is_empty())
}

fn print_interfaces(interfaces: &[NetworkInterface]) {
    println!("{:<18} {:<10} {:<18} STATE", "NAME", "KIND", "MAC");

    for interface in interfaces {
        println!(
            "{:<18} {:<10} {:<18} {}",
            interface.name,
            interface.kind,
            interface.mac_address.as_deref().unwrap_or("-"),
            interface.oper_state.as_deref().unwrap_or("-"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn reads_wireless_interface_from_sysfs_layout() {
        let root = temp_sysfs_root("wireless");
        let iface = root.join("wlan0");
        fs::create_dir_all(iface.join("wireless")).unwrap();
        fs::write(iface.join("address"), "aa:bb:cc:dd:ee:ff\n").unwrap();
        fs::write(iface.join("operstate"), "up\n").unwrap();

        let interfaces = read_linux_network_interfaces(&root).unwrap();

        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "wlan0");
        assert_eq!(interfaces[0].kind, NetworkInterfaceKind::Wireless);
        assert_eq!(
            interfaces[0].mac_address.as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(interfaces[0].oper_state.as_deref(), Some("up"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recognizes_loopback_by_name() {
        let root = temp_sysfs_root("loopback");
        let iface = root.join("lo");
        fs::create_dir_all(&iface).unwrap();

        let interfaces = read_linux_network_interfaces(&root).unwrap();

        assert_eq!(interfaces[0].kind, NetworkInterfaceKind::Loopback);

        fs::remove_dir_all(root).unwrap();
    }

    fn temp_sysfs_root(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("argowei-cli-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
