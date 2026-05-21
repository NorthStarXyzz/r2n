use async_trait::async_trait;
use std::net::Ipv4Addr;
#[allow(unused_imports)]
use std::sync::Arc;
use thiserror::Error;
#[cfg(not(target_os = "android"))]
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

pub const MIN_TUN_MTU: u16 = 1280;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunDeviceMode {
    Tun,
    Tap,
}

#[derive(Error, Debug)]
pub enum TunError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Device not found")]
    NotFound,
    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, TunError>;

/// TunInterface defines the basic operations for a virtual network interface
#[async_trait]
pub trait TunInterface: Send + Sync {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
    async fn send(&self, buf: &[u8]) -> Result<usize>;
    fn name(&self) -> Result<String>;
    fn mtu(&self) -> Result<u16>;
}

enum TunDeviceInner {
    #[cfg(not(target_os = "android"))]
    Normal(Arc<AsyncDevice>),
    #[cfg(unix)]
    Fd {
        rx_file: Box<tokio::sync::Mutex<tokio::fs::File>>,
        tx_file: Box<tokio::sync::Mutex<tokio::fs::File>>,
        name: String,
        mtu: u16,
    },
    #[cfg(target_os = "windows")]
    Wintun {
        session: Arc<wintun::Session>,
        name: String,
        mtu: u16,
        rx_packets: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
        tx_free_buffers: std::sync::Mutex<std::sync::mpsc::Sender<Vec<u8>>>,
    },
}

pub struct TunDevice {
    inner: TunDeviceInner,
    ipv4: Option<Ipv4Addr>,
    mode: TunDeviceMode,
    effective_mtu: u16,
}

impl TunDevice {
    #[cfg(target_os = "windows")]
    fn escape_ps_single_quoted(s: &str) -> String {
        s.replace('\'', "''")
    }

    #[cfg(target_os = "windows")]
    fn run_powershell(command: &str) -> Result<()> {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ])
            .output()
            .map_err(TunError::Io)?;

        if !output.status.success() {
            return Err(TunError::Config(format!(
                "PowerShell command failed: cmd={:?}, stdout={:?}, stderr={:?}",
                command,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )));
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn configure_windows_interface(name: &str, ipv4: &str, prefix_len: u8, mtu: u16) -> Result<()> {
        let alias = Self::escape_ps_single_quoted(name);
        let ip = Self::escape_ps_single_quoted(ipv4);
        let ipv4_mtu = mtu;
        let ipv6_mtu = mtu.max(1280);

        if mtu < 1280 {
            log::warn!(
                "IPv6 MTU requires at least 1280 on Windows, keeping IPv4 MTU {} and clamping IPv6 MTU to {}",
                ipv4_mtu,
                ipv6_mtu
            );
        }

        let command = format!(
            r#"
$alias = '{alias}';
$ip = '{ip}';

$iface = Get-NetAdapter -Name $alias -ErrorAction Stop;

$existing = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {{ $_.IPAddress -eq $ip }};

if (-not $existing) {{
    New-NetIPAddress -InterfaceAlias $alias -IPAddress $ip -PrefixLength {prefix_len} -AddressFamily IPv4 -ErrorAction Stop | Out-Null;
}}

Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -NlMtuBytes {ipv4_mtu} -ErrorAction Stop | Out-Null;
Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv6 -NlMtuBytes {ipv6_mtu} -ErrorAction SilentlyContinue | Out-Null;
"#,
        );

        Self::run_powershell(&command)
    }

    #[cfg(target_os = "windows")]
    fn init_wintun_dll() -> Result<()> {
        use std::env;
        use std::fs;

        let exe_path = env::current_exe().map_err(TunError::Io)?;
        let exe_dir = exe_path
            .parent()
            .ok_or_else(|| TunError::Config("Failed to get executable directory".to_string()))?;
        let dll_path = exe_dir.join("wintun.dll");

        if !dll_path.exists() {
            let dll_bytes = match env::consts::ARCH {
                "x86_64" => Some(include_bytes!("wintun_bin/amd64/wintun.dll") as &[u8]),
                "x86" => Some(include_bytes!("wintun_bin/x86/wintun.dll") as &[u8]),
                "aarch64" => Some(include_bytes!("wintun_bin/arm64/wintun.dll") as &[u8]),
                "arm" => Some(include_bytes!("wintun_bin/arm/wintun.dll") as &[u8]),
                _ => None,
            };

            if let Some(bytes) = dll_bytes {
                fs::write(&dll_path, bytes).map_err(TunError::Io)?;
                log::info!("Wintun driver DLL extracted to {}", dll_path.display());
            } else {
                log::warn!("Unsupported CPU architecture for auto-extracting wintun.dll");
            }
        }
        Ok(())
    }

    pub fn prefer_virtual_interface(name: &str) -> Result<bool> {
        Self::prefer_virtual_interface_inner(name)
    }

    #[cfg(target_os = "windows")]
    fn prefer_virtual_interface_inner(name: &str) -> Result<bool> {
        let alias = Self::escape_ps_single_quoted(name);
        let command = format!(
            r#"
$alias = '{alias}';
$errors = @();

try {{
    Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -InterfaceMetric 5 -ErrorAction Stop | Out-Null;
}} catch {{
    $errors += "IPv4 interface metric: $($_.Exception.Message)";
}}

try {{
    Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv6 -InterfaceMetric 5 -ErrorAction SilentlyContinue | Out-Null;
}} catch {{
}}

try {{
    Set-NetConnectionProfile -InterfaceAlias $alias -NetworkCategory Private -ErrorAction Stop | Out-Null;
}} catch {{
    $errors += "network category: $($_.Exception.Message)";
}}

if ($errors.Count -gt 0) {{
    throw ($errors -join '; ');
}}
"#,
        );

        Self::run_powershell(&command)?;
        Ok(true)
    }

    #[cfg(not(target_os = "windows"))]
    fn prefer_virtual_interface_inner(_name: &str) -> Result<bool> {
        Ok(false)
    }

    /// Create a new TUN device with the given name and configuration
    #[allow(unused_variables)]
    pub fn new(name: &str, ipv4: &str, netmask: u8, mtu: u16) -> Result<Self> {
        Self::new_with_mode(name, ipv4, netmask, mtu, TunDeviceMode::Tun)
    }

    /// Create a new TUN/TAP device with the given name and configuration.
    #[allow(unused_variables)]
    pub fn new_with_mode(
        name: &str,
        ipv4: &str,
        netmask: u8,
        mtu: u16,
        mode: TunDeviceMode,
    ) -> Result<Self> {
        let effective_mtu = normalize_mtu(mtu);
        #[cfg(target_os = "windows")]
        {
            if let Err(e) = Self::init_wintun_dll() {
                log::warn!("Failed to initialize Wintun DLL: {:?}", e);
            }
        }

        #[cfg(target_os = "windows")]
        let device = {
            if mode == TunDeviceMode::Tap {
                let dev = DeviceBuilder::new()
                    .name(name)
                    .layer(Layer::L2)
                    .ipv4(ipv4, netmask, None)
                    .mtu(effective_mtu)
                    .build_async()
                    .map_err(TunError::Io)?;
                return Ok(Self {
                    inner: TunDeviceInner::Normal(Arc::new(dev)),
                    ipv4: ipv4.parse().ok(),
                    mode,
                    effective_mtu,
                });
            }

            let wintun = match unsafe { wintun::load_from_path("wintun.dll") } {
                Ok(w) => w,
                Err(e) => return Err(TunError::Config(format!("Failed to load Wintun: {:?}", e))),
            };

            let adapter = match wintun::Adapter::open(&wintun, name) {
                Ok(a) => a,
                Err(_) => match wintun::Adapter::open(&wintun, "r2n") {
                    Ok(a) => {
                        if let Err(err) = a.set_name(name) {
                            log::warn!(
                                "Failed to rename legacy Wintun adapter from r2n to {}: {:?}",
                                name,
                                err
                            );
                        }
                        a
                    }
                    Err(_) => wintun::Adapter::create(&wintun, name, "R2N", None).map_err(|e| {
                        TunError::Config(format!("Failed to create Wintun adapter: {:?}", e))
                    })?,
                },
            };

            let actual_name = adapter.get_name().map_err(|e| {
                TunError::Config(format!("Failed to query Wintun adapter name: {:?}", e))
            })?;
            log::info!("Using Wintun adapter alias {}", actual_name);

            Self::configure_windows_interface(&actual_name, ipv4, netmask, effective_mtu)?;

            let session = Arc::new(
                adapter
                    .start_session(0x400000) // 4MB ring capacity
                    .map_err(|e| {
                        TunError::Config(format!("Failed to start Wintun session: {:?}", e))
                    })?,
            );

            let (tx_packets, rx_packets) = tokio::sync::mpsc::channel(1024);
            let (tx_free, rx_free) = std::sync::mpsc::channel();
            for _ in 0..128 {
                let _ = tx_free.send(vec![0u8; 1600]);
            }

            let session_clone = session.clone();
            std::thread::spawn(move || {
                loop {
                    let packet = match session_clone.receive_blocking() {
                        Ok(p) => p,
                        Err(e) => {
                            log::error!("Wintun receive error: {:?}", e);
                            break;
                        }
                    };
                    let bytes = packet.bytes();
                    let mut buf = rx_free.try_recv().unwrap_or_else(|_| vec![0u8; 1600]);
                    buf.resize(bytes.len(), 0);
                    buf[..bytes.len()].copy_from_slice(bytes);
                    if tx_packets.blocking_send(buf).is_err() {
                        break;
                    }
                }
            });

            Self {
                inner: TunDeviceInner::Wintun {
                    session,
                    name: actual_name,
                    mtu: effective_mtu,
                    rx_packets: tokio::sync::Mutex::new(rx_packets),
                    tx_free_buffers: std::sync::Mutex::new(tx_free),
                },
                ipv4: ipv4.parse().ok(),
                mode,
                effective_mtu,
            }
        };

        #[cfg(target_os = "macos")]
        let device = {
            let mut last_err = None;
            let mut found_device = None;

            // If the user specified a valid utun interface, try it first
            if name.starts_with("utun") && name["utun".len()..].parse::<usize>().is_ok() {
                match DeviceBuilder::new()
                    .name(name)
                    .layer(if mode == TunDeviceMode::Tap {
                        Layer::L2
                    } else {
                        Layer::L3
                    })
                    .ipv4(ipv4, netmask, None)
                    .mtu(effective_mtu)
                    .build_async()
                {
                    Ok(dev) => found_device = Some(dev),
                    Err(e) => last_err = Some(e),
                }
            }

            // If not specified, or if the specified one was already in use, find a free utunX interface
            if found_device.is_none() {
                for i in 10..100 {
                    let candidate = format!("utun{}", i);
                    match DeviceBuilder::new()
                        .name(&candidate)
                        .layer(if mode == TunDeviceMode::Tap {
                            Layer::L2
                        } else {
                            Layer::L3
                        })
                        .ipv4(ipv4, netmask, None)
                        .mtu(effective_mtu)
                        .build_async()
                    {
                        Ok(dev) => {
                            found_device = Some(dev);
                            break;
                        }
                        Err(e) => {
                            last_err = Some(e);
                        }
                    }
                }
            }

            match found_device {
                Some(dev) => dev,
                None => {
                    return Err(TunError::Io(last_err.unwrap_or_else(|| {
                        std::io::Error::other("Failed to allocate free utun interface")
                    })));
                }
            }
        };

        #[cfg(all(
            not(target_os = "macos"),
            not(target_os = "windows"),
            not(target_os = "android")
        ))]
        let device = DeviceBuilder::new()
            .name(name)
            .layer(if mode == TunDeviceMode::Tap {
                Layer::L2
            } else {
                Layer::L3
            })
            .ipv4(ipv4, netmask, None)
            .mtu(effective_mtu)
            .build_async()
            .map_err(TunError::Io)?;

        #[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
        return Ok(Self {
            inner: TunDeviceInner::Normal(Arc::new(device)),
            ipv4: ipv4.parse().ok(),
            mode,
            effective_mtu,
        });

        #[cfg(target_os = "android")]
        {
            return Err(TunError::Config("Creating new TUN device directly is not supported on Android. Use from_fd instead.".to_string()));
        }

        #[cfg(target_os = "windows")]
        return Ok(device);
    }

    /// Create a TUN device from an existing Unix file descriptor
    #[cfg(unix)]
    pub fn from_fd(
        fd: std::os::unix::io::RawFd,
        name: &str,
        mtu: u16,
        ipv4: Option<Ipv4Addr>,
    ) -> Result<Self> {
        use std::os::unix::io::FromRawFd;

        #[cfg(target_os = "android")]
        clear_nonblocking(fd)?;

        let file1 = unsafe { std::fs::File::from_raw_fd(fd) };
        let file2 = file1.try_clone().map_err(TunError::Io)?;

        let rx_file = tokio::fs::File::from_std(file1);
        let tx_file = tokio::fs::File::from_std(file2);

        Ok(Self {
            inner: TunDeviceInner::Fd {
                rx_file: Box::new(tokio::sync::Mutex::new(rx_file)),
                tx_file: Box::new(tokio::sync::Mutex::new(tx_file)),
                name: name.to_string(),
                mtu: normalize_mtu(mtu),
            },
            ipv4,
            mode: TunDeviceMode::Tun,
            effective_mtu: normalize_mtu(mtu),
        })
    }

    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        self.ipv4
    }

    pub fn mode(&self) -> TunDeviceMode {
        self.mode
    }

    pub fn effective_mtu(&self) -> u16 {
        self.effective_mtu
    }
}

pub fn normalize_mtu(mtu: u16) -> u16 {
    if mtu < MIN_TUN_MTU {
        log::warn!(
            "Configured MTU {} is below the minimum {}; using {}",
            mtu,
            MIN_TUN_MTU,
            MIN_TUN_MTU
        );
        MIN_TUN_MTU
    } else {
        mtu
    }
}

#[cfg(target_os = "android")]
fn clear_nonblocking(fd: std::os::unix::io::RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(TunError::Io(std::io::Error::last_os_error()));
    }

    if flags & libc::O_NONBLOCK != 0 {
        let new_flags = flags & !libc::O_NONBLOCK;
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) };
        if rc < 0 {
            return Err(TunError::Io(std::io::Error::last_os_error()));
        }
        log::debug!("Cleared O_NONBLOCK from Android TUN fd");
    }

    Ok(())
}

#[async_trait]
impl TunInterface for TunDevice {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        match &self.inner {
            #[cfg(not(target_os = "android"))]
            TunDeviceInner::Normal(dev) => dev.recv(buf).await.map_err(TunError::Io),
            #[cfg(unix)]
            TunDeviceInner::Fd { rx_file, .. } => {
                use tokio::io::AsyncReadExt;
                let mut file = rx_file.lock().await;
                file.read(buf).await.map_err(TunError::Io)
            }
            #[cfg(target_os = "windows")]
            TunDeviceInner::Wintun {
                rx_packets,
                tx_free_buffers,
                ..
            } => {
                let mut rx = rx_packets.lock().await;
                if let Some(packet_buf) = rx.recv().await {
                    let len = packet_buf.len().min(buf.len());
                    buf[..len].copy_from_slice(&packet_buf[..len]);
                    let _ = tx_free_buffers.lock().unwrap().send(packet_buf);
                    Ok(len)
                } else {
                    Err(TunError::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "Wintun receiver channel closed",
                    )))
                }
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> Result<usize> {
        match &self.inner {
            #[cfg(not(target_os = "android"))]
            TunDeviceInner::Normal(dev) => dev.send(buf).await.map_err(TunError::Io),
            #[cfg(unix)]
            TunDeviceInner::Fd { tx_file, .. } => {
                use tokio::io::AsyncWriteExt;
                let mut file = tx_file.lock().await;
                file.write(buf).await.map_err(TunError::Io)
            }
            #[cfg(target_os = "windows")]
            TunDeviceInner::Wintun { session, .. } => {
                let mut packet = session
                    .allocate_send_packet(buf.len() as u16)
                    .map_err(|_| TunError::Io(std::io::Error::last_os_error()))?;
                packet.bytes_mut().copy_from_slice(buf);
                session.send_packet(packet);
                Ok(buf.len())
            }
        }
    }

    fn name(&self) -> Result<String> {
        match &self.inner {
            #[cfg(not(target_os = "android"))]
            TunDeviceInner::Normal(dev) => dev.name().map_err(TunError::Io),
            #[cfg(unix)]
            TunDeviceInner::Fd { name, .. } => Ok(name.clone()),
            #[cfg(target_os = "windows")]
            TunDeviceInner::Wintun { name, .. } => Ok(name.clone()),
        }
    }

    fn mtu(&self) -> Result<u16> {
        match &self.inner {
            #[cfg(not(target_os = "android"))]
            TunDeviceInner::Normal(dev) => dev.mtu().map_err(TunError::Io),
            #[cfg(unix)]
            TunDeviceInner::Fd { mtu, .. } => Ok(*mtu),
            #[cfg(target_os = "windows")]
            TunDeviceInner::Wintun { mtu, .. } => Ok(*mtu),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_mtu_enforces_windows_safe_floor() {
        assert_eq!(normalize_mtu(MIN_TUN_MTU - 80), MIN_TUN_MTU);
        assert_eq!(normalize_mtu(MIN_TUN_MTU), MIN_TUN_MTU);
        assert_eq!(normalize_mtu(1400), 1400);
    }
}
