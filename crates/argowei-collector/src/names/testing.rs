//! Helpers shared by the resolver tests: targets, a one-shot UDP "device" on
//! loopback, hand-built DNS answers and a throwaway directory.

use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::{dns, RdnsResolver, Target};

pub fn target(ip: &str) -> Target {
    target_with_mac(ip, "aa:bb:cc:dd:ee:01")
}

pub fn target_with_mac(ip: &str, mac: &str) -> Target {
    Target {
        ip: ip.parse().unwrap(),
        mac: mac.to_owned(),
    }
}

/// A UDP "device" on loopback that reads one request and answers it with
/// whatever `handler` returns (`None` = stay silent). Returns its port.
pub fn answer_once(handler: impl FnOnce(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();

    std::thread::spawn(move || {
        let mut buffer = [0u8; 1500];
        if let Ok((length, from)) = socket.recv_from(&mut buffer) {
            if let Some(reply) = handler(&buffer[..length]) {
                let _ = socket.send_to(&reply, from);
            }
        }
    });
    port
}

/// A reverse DNS resolver that asks only the loopback server on `port`.
pub fn rdns_on(port: u16) -> RdnsResolver {
    RdnsResolver::new(vec![format!("127.0.0.1:{port}").parse().unwrap()])
}

/// A PTR response to `request`: it repeats the question, and the answer
/// points back at it, as DNS servers compress. `target_labels` is the
/// answer's target in label form.
pub fn ptr_response(request: &[u8], target_labels: &[u8]) -> Vec<u8> {
    let mut packet = request[..2].to_vec(); // same id
    packet.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    packet.extend_from_slice(&request[12..]); // the question
    packet.extend_from_slice(&[0xc0, 0x0c, 0, dns::TYPE_PTR as u8, 0, 1, 0, 0, 0, 120]);
    packet.extend_from_slice(&(target_labels.len() as u16).to_be_bytes());
    packet.extend_from_slice(target_labels);
    packet
}

/// A throwaway directory, removed when dropped (no extra dependency).
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "argowei-collector-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
