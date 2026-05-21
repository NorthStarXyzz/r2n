use ipnet::Ipv4Net;
#[cfg(not(target_os = "android"))]
use std::net::IpAddr;
#[cfg(test)]
use std::net::Ipv4Addr;
use thiserror::Error;

#[cfg(not(target_os = "android"))]
use net_route::{Handle, Route};

#[derive(Error, Debug)]
pub enum RouteError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Route manipulation failed: {0}")]
    Failed(String),
}

pub type Result<T> = std::result::Result<T, RouteError>;

#[cfg(not(target_os = "android"))]
pub struct RouteManager {
    handle: Handle,
}

#[cfg(not(target_os = "android"))]
impl RouteManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            handle: Handle::new()?,
        })
    }

    /// Add a route to the virtual network via the specified interface.
    pub async fn add_route(&self, dest: Ipv4Net, interface_name: &str) -> Result<()> {
        let route = build_route(dest, interface_name).await?;
        log::info!("Adding route to {} via interface {}", dest, interface_name);
        match self.handle.add(&route).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                log::info!(
                    "Route {} via interface {} already exists, reusing it",
                    dest,
                    interface_name
                );
                Ok(())
            }
            Err(err) => Err(RouteError::Io(err)),
        }
    }

    /// Remove a route from the virtual network.
    pub async fn remove_route(&self, dest: Ipv4Net, interface_name: &str) -> Result<()> {
        let route = build_route(dest, interface_name).await?;
        log::info!(
            "Removing route to {} via interface {}",
            dest,
            interface_name
        );
        match self.handle.delete(&route).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(RouteError::Io(err)),
        }
    }
}

#[cfg(target_os = "android")]
pub struct RouteManager {}

#[cfg(target_os = "android")]
impl RouteManager {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    /// On Android, routing configuration is managed by VpnService, so this is a no-op.
    pub async fn add_route(&self, dest: Ipv4Net, interface_name: &str) -> Result<()> {
        log::info!(
            "Android route to {} via interface {} is managed by VpnService, skipping add_route in core",
            dest,
            interface_name
        );
        Ok(())
    }

    /// On Android, routing configuration is managed by VpnService, so this is a no-op.
    pub async fn remove_route(&self, _dest: Ipv4Net, _interface_name: &str) -> Result<()> {
        Ok(())
    }
}

#[cfg(not(target_os = "android"))]
async fn build_route(dest: Ipv4Net, interface_name: &str) -> Result<Route> {
    let mut route = Route::new(IpAddr::V4(dest.network()), dest.prefix_len());
    route = route.with_ifindex(interface_index(interface_name).await?);

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        route = route.with_metric(5);
    }

    Ok(route)
}

#[cfg(target_os = "macos")]
async fn interface_index(interface_name: &str) -> Result<u32> {
    net_route::ifname_to_index(interface_name)
        .ok_or_else(|| RouteError::Failed(format!("unknown interface: {interface_name}")))
}

#[cfg(target_os = "linux")]
async fn interface_index(interface_name: &str) -> Result<u32> {
    use std::ffi::CString;

    let c_name = CString::new(interface_name)
        .map_err(|_| RouteError::Failed(format!("invalid interface name: {interface_name}")))?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(RouteError::Failed(format!(
            "unknown interface: {interface_name}"
        )));
    }
    Ok(index)
}

#[cfg(target_os = "windows")]
async fn interface_index(interface_name: &str) -> Result<u32> {
    let output = tokio::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-NetAdapter -Name '{}' -ErrorAction Stop).ifIndex",
                interface_name.replace('\'', "''")
            ),
        ])
        .output()
        .await?;

    if !output.status.success() {
        return Err(RouteError::Failed(format!(
            "failed to resolve interface index for {interface_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.trim().parse::<u32>().map_err(|_| {
        RouteError::Failed(format!("invalid interface index output: {}", stdout.trim()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_destination_network() {
        let network: Ipv4Net = "10.77.0.0/24".parse().expect("cidr");
        assert_eq!(network.network(), Ipv4Addr::new(10, 77, 0, 0));
        assert_eq!(network.prefix_len(), 24);
    }
}
