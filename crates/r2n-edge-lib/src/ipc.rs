use crate::{EdgeCommand, PeerState, RuntimeState};
use dashmap::DashMap;
use r2n_common::{NodeId, RoomId};
use r2n_dataplane::DataPlane;
use r2n_observability::MetricsRegistry;
use r2n_policy::TrafficRule;
use r2n_tun::TunDevice;
#[cfg(target_os = "android")]
use r2n_tun::TunInterface;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub trait IpcStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
    #[cfg(target_os = "android")]
    fn get_raw_fd(&self) -> std::os::unix::io::RawFd;
}

#[cfg(unix)]
impl IpcStream for tokio::net::UnixStream {
    #[cfg(target_os = "android")]
    fn get_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        self.as_raw_fd()
    }
}

#[cfg(windows)]
impl IpcStream for tokio::net::windows::named_pipe::NamedPipeServer {}

#[derive(Clone)]
pub struct IpcServerContext {
    pub tx: tokio::sync::mpsc::Sender<EdgeCommand>,
    pub peers: Arc<DashMap<NodeId, PeerState>>,
    pub room_id: Arc<tokio::sync::Mutex<Option<RoomId>>>,
    pub tun: Arc<parking_lot::RwLock<Option<Arc<TunDevice>>>>,
    pub metrics: Arc<MetricsRegistry>,
    pub runtime_state: Arc<tokio::sync::RwLock<RuntimeState>>,
    pub dataplane: Arc<DataPlane>,
    pub node_id: NodeId,
}

// IPC connection handling fans in daemon state; splitting this would obscure ownership.
#[allow(clippy::too_many_arguments)]
pub async fn handle_ipc_connection<S>(
    mut stream: S,
    tx: tokio::sync::mpsc::Sender<EdgeCommand>,
    peers: Arc<DashMap<NodeId, PeerState>>,
    room_id: Arc<tokio::sync::Mutex<Option<RoomId>>>,
    tun: Arc<parking_lot::RwLock<Option<Arc<TunDevice>>>>,
    metrics: Arc<MetricsRegistry>,
    runtime_state: Arc<tokio::sync::RwLock<RuntimeState>>,
    dataplane: Arc<DataPlane>,
    node_id: NodeId,
) where
    S: IpcStream,
{
    #[cfg(target_os = "android")]
    let raw_fd = stream.get_raw_fd();

    let (reader, mut writer) = tokio::io::split(&mut stream);
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    while let Ok(n) = buf_reader.read_line(&mut line).await {
        if n == 0 {
            break; // EOF
        }
        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) {
            let mut response = None;
            match msg["command"].as_str() {
                Some("create") => {
                    let name = msg["name"].as_str().unwrap_or("Room").to_string();
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = tx
                        .send(EdgeCommand::CreateRoom {
                            name,
                            reply: reply_tx,
                        })
                        .await;
                    response = Some(wait_for_command_reply(reply_rx).await);
                }
                Some("join") => {
                    let invite = msg["invite"].as_str().unwrap_or("").to_string();
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = tx
                        .send(EdgeCommand::JoinRoom {
                            invite,
                            reply: reply_tx,
                        })
                        .await;
                    response = Some(wait_for_command_reply(reply_rx).await);
                }
                Some("leave") => {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = tx.send(EdgeCommand::LeaveRoom { reply: reply_tx }).await;
                    response = Some(wait_for_command_reply(reply_rx).await);
                }
                Some("stop") => {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = tx.send(EdgeCommand::Stop { reply: reply_tx }).await;
                    response = Some(wait_for_command_reply(reply_rx).await);
                }
                Some("history") => {
                    let list = crate::load_history();
                    response = Some(serde_json::json!({
                        "status": "ok",
                        "history": list
                    }));
                }
                Some("delete_history") => {
                    let room_id = msg["room_id"].as_str().unwrap_or("").to_string();
                    let mut history = crate::load_history();
                    let len_before = history.len();
                    history.retain(|item| item.room_id != room_id);
                    if history.len() < len_before {
                        crate::save_history(history);
                        response = Some(serde_json::json!({
                            "status": "ok",
                            "message": "History item deleted"
                        }));
                    } else {
                        response = Some(serde_json::json!({
                            "status": "error",
                            "error": "History item not found"
                        }));
                    }
                }
                Some("update_history_name") => {
                    let room_id = msg["room_id"].as_str().unwrap_or("").to_string();
                    let new_name = msg["name"].as_str().unwrap_or("").to_string();
                    let mut history = crate::load_history();
                    let mut found = false;
                    for item in &mut history {
                        if item.room_id == room_id {
                            item.name = new_name.clone();
                            found = true;
                            break;
                        }
                    }
                    if found {
                        crate::save_history(history);
                        response = Some(serde_json::json!({
                            "status": "ok",
                            "message": "History item name updated"
                        }));
                    } else {
                        response = Some(serde_json::json!({
                            "status": "error",
                            "error": "History item not found"
                        }));
                    }
                }
                Some("switch_supernode") => {
                    let supernode = msg["supernode"].as_str().unwrap_or("").to_string();
                    if let Ok(addr) = supernode.parse::<std::net::SocketAddr>() {
                        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                        let _ = tx
                            .send(EdgeCommand::SwitchSupernode {
                                addr,
                                reply: reply_tx,
                            })
                            .await;
                        response = Some(wait_for_command_reply(reply_rx).await);
                    } else {
                        response = Some(serde_json::json!({
                            "status": "error",
                            "error": "Invalid supernode SocketAddr"
                        }));
                    }
                }
                Some("active") => {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = tx.send(EdgeCommand::QueryRooms { reply: reply_tx }).await;
                    response = Some(wait_for_command_reply(reply_rx).await);
                }
                Some("status") => {
                    let rid_opt = *room_id.lock().await;
                    let tun_active = tun.read().is_some();
                    let runtime = runtime_state.read().await.clone();
                    let port_mapping_lease_remaining_secs = runtime
                        .port_mapping_lease_expires_at
                        .map(|expires_at| {
                            expires_at
                                .saturating_duration_since(std::time::Instant::now())
                                .as_secs()
                        })
                        .unwrap_or(0);
                    let last_supernode_activity_secs = runtime
                        .last_supernode_activity_at
                        .map(|last_seen| last_seen.elapsed().as_secs());
                    let status_str = if !runtime.supernode_reachable {
                        if rid_opt.is_some() {
                            "Supernode Unreachable"
                        } else {
                            "Waiting for supernode"
                        }
                    } else if tun_active && runtime.route_installed {
                        "Connected"
                    } else if rid_opt.is_some() {
                        "Degraded"
                    } else {
                        "Disconnected"
                    };
                    response = Some(serde_json::json!({
                        "node_id": node_id.to_string(),
                        "room_id": rid_opt.map(|r| r.to_string()).unwrap_or_default(),
                        "status": status_str,
                        "supernode": runtime.supernode_addr,
                        "supernode_reachable": runtime.supernode_reachable,
                        "last_supernode_activity_secs": last_supernode_activity_secs,
                        "nat_type": runtime.nat_type,
                        "tun_name": runtime.tun_name.unwrap_or_default(),
                        "virtual_ip": runtime.virtual_ip.unwrap_or_default(),
                        "route_cidr": runtime.route_cidr.unwrap_or_default(),
                        "route_status": if runtime.route_installed { "Installed" } else { "Not Installed" },
                        "discovery_routes_installed": runtime.discovery_routes_installed,
                        "discovery_route_errors": runtime.discovery_route_errors,
                        "backend_requested": runtime.backend_requested,
                        "backend_active": runtime.backend_active,
                        "backend_degraded": runtime.backend_degraded,
                        "effective_mtu": runtime.effective_mtu,
                        "virtual_interface_preference_requested": runtime.virtual_interface_preference_requested,
                        "virtual_interface_preference_supported": runtime.virtual_interface_preference_supported,
                        "virtual_interface_preference_applied": runtime.virtual_interface_preference_applied,
                        "virtual_interface_preference_error": runtime.virtual_interface_preference_error.unwrap_or_default(),
                        "port_mapping_acquired": runtime.port_mapping_acquired,
                        "port_mapping_protocol": runtime.port_mapping_protocol.unwrap_or_default(),
                        "port_mapping_external_addr": runtime.port_mapping_external_addr.unwrap_or_default(),
                        "port_mapping_lease_remaining_secs": port_mapping_lease_remaining_secs,
                        "peer_count": peers.len(),
                        "last_error": runtime.last_error.unwrap_or_default()
                    }));
                }
                Some("peers") => {
                    let metrics_snapshot = metrics.snapshot();
                    let mut peer_list = serde_json::json!([]);
                    for peer in peers.iter() {
                        let p = peer.value();
                        let metric = metrics_snapshot
                            .peers
                            .iter()
                            .find(|item| item.peer == p.info.node_id);
                        let conn_type = if p.direct_addr.is_some() {
                            "Direct"
                        } else {
                            "Relay"
                        };
                        peer_list.as_array_mut().unwrap().push(serde_json::json!({
                            "node_id": p.info.node_id.to_string(),
                            "virtual_ip": p.info.virtual_ip.to_string(),
                            "nickname": p.info.nickname,
                            "connection": conn_type,
                            "rtt_ms": metric.and_then(|item| item.last_rtt_ms),
                            "loss_rate": metric.map(|item| item.packet_loss_rate).unwrap_or(0.0)
                        }));
                    }
                    response = Some(serde_json::json!({ "peers": peer_list }));
                }
                Some("metrics") => {
                    response = Some(serde_json::to_value(metrics.snapshot()).unwrap_or_default());
                }
                Some("diagnose") => {
                    let rid_opt = *room_id.lock().await;
                    let tun_active = tun.read().is_some();
                    let runtime = runtime_state.read().await.clone();
                    let metrics_snapshot = metrics.snapshot();
                    response = Some(serde_json::json!({
                        "status": "ok",
                        "node_id": node_id.to_string(),
                        "room_id": rid_opt.map(|r| r.to_string()).unwrap_or_default(),
                        "supernode": runtime.supernode_addr,
                        "supernode_reachable": runtime.supernode_reachable,
                        "supernodes": runtime.supernodes,
                        "udp_working": runtime.supernode_reachable || runtime.last_supernode_activity_at.is_some(),
                        "nat_type": runtime.nat_type,
                        "tun_active": tun_active,
                        "tun_name": runtime.tun_name.unwrap_or_default(),
                        "backend_requested": runtime.backend_requested,
                        "backend_active": runtime.backend_active,
                        "backend_degraded": runtime.backend_degraded,
                        "effective_mtu": runtime.effective_mtu,
                        "mtu_ok": runtime.effective_mtu >= 1280,
                        "virtual_ip": runtime.virtual_ip.unwrap_or_default(),
                        "route_cidr": runtime.route_cidr.unwrap_or_default(),
                        "route_installed": runtime.route_installed,
                        "discovery_routes_installed": runtime.discovery_routes_installed,
                        "discovery_route_errors": runtime.discovery_route_errors,
                        "broadcast_packets": metrics_snapshot.broadcast_packets,
                        "multicast_packets": metrics_snapshot.multicast_packets,
                        "l2_flood_packets": metrics_snapshot.l2_flood_packets,
                        "packet_drops": metrics_snapshot.packet_drops,
                        "rules_enabled": dataplane.traffic_policy().enabled,
                        "rules_count": dataplane.traffic_policy().rules.len(),
                        "l2_entries": dataplane.l2_table_snapshot().len(),
                        "last_error": runtime.last_error.unwrap_or_default()
                    }));
                }
                Some("rules_list") | Some("rules") => {
                    response = Some(serde_json::json!({
                        "status": "ok",
                        "policy": dataplane.traffic_policy()
                    }));
                }
                Some("rules_add") => {
                    let rule_value = msg.get("rule").cloned().unwrap_or_default();
                    match serde_json::from_value::<TrafficRule>(rule_value) {
                        Ok(rule) => {
                            let mut policy = dataplane.traffic_policy();
                            if policy.rules.iter().any(|existing| existing.id == rule.id) {
                                response = Some(serde_json::json!({
                                    "status": "error",
                                    "error": format!("rule id already exists: {}", rule.id)
                                }));
                            } else {
                                policy.rules.push(rule);
                                dataplane.set_traffic_policy(policy.clone());
                                response = Some(serde_json::json!({
                                    "status": "ok",
                                    "policy": policy
                                }));
                            }
                        }
                        Err(err) => {
                            response = Some(serde_json::json!({
                                "status": "error",
                                "error": format!("invalid traffic rule: {}", err)
                            }));
                        }
                    }
                }
                Some("rules_remove") => {
                    let id = msg["id"].as_str().unwrap_or("").to_string();
                    let mut policy = dataplane.traffic_policy();
                    let before = policy.rules.len();
                    policy.rules.retain(|rule| rule.id != id);
                    if policy.rules.len() == before {
                        response = Some(serde_json::json!({
                            "status": "error",
                            "error": "rule not found"
                        }));
                    } else {
                        dataplane.set_traffic_policy(policy.clone());
                        response = Some(serde_json::json!({
                            "status": "ok",
                            "policy": policy
                        }));
                    }
                }
                Some("rules_enable") => {
                    let enabled = msg["enabled"].as_bool().unwrap_or(true);
                    let mut policy = dataplane.traffic_policy();
                    policy.enabled = enabled;
                    dataplane.set_traffic_policy(policy.clone());
                    response = Some(serde_json::json!({
                        "status": "ok",
                        "policy": policy
                    }));
                }
                Some("supernodes") => {
                    let runtime = runtime_state.read().await.clone();
                    response = Some(serde_json::json!({
                        "status": "ok",
                        "active": runtime.supernode_addr,
                        "supernodes": runtime.supernodes,
                        "reachable": runtime.supernode_reachable,
                        "last_supernode_activity_secs": runtime.last_supernode_activity_at.map(|last_seen| last_seen.elapsed().as_secs())
                    }));
                }
                Some("routes") => {
                    let runtime = runtime_state.read().await.clone();
                    response = Some(serde_json::json!({
                        "status": "ok",
                        "route_cidr": runtime.route_cidr.unwrap_or_default(),
                        "route_installed": runtime.route_installed,
                        "discovery_routes_installed": runtime.discovery_routes_installed,
                        "discovery_route_errors": runtime.discovery_route_errors,
                        "tun_name": runtime.tun_name.unwrap_or_default()
                    }));
                }
                Some("l2_table") => {
                    response = Some(serde_json::json!({
                        "status": "ok",
                        "entries": dataplane.l2_table_snapshot()
                    }));
                }
                Some("room_detail") => {
                    let rid_opt = *room_id.lock().await;
                    let runtime = runtime_state.read().await.clone();
                    let peer_list = peers
                        .iter()
                        .map(|peer| {
                            let p = peer.value();
                            serde_json::json!({
                                "node_id": p.info.node_id.to_string(),
                                "virtual_ip": p.info.virtual_ip.to_string(),
                                "nickname": p.info.nickname
                            })
                        })
                        .collect::<Vec<_>>();
                    response = Some(serde_json::json!({
                        "status": "ok",
                        "room_id": rid_opt.map(|r| r.to_string()).unwrap_or_default(),
                        "virtual_ip": runtime.virtual_ip.unwrap_or_default(),
                        "virtual_cidr": runtime.route_cidr.unwrap_or_default(),
                        "peers": peer_list
                    }));
                }
                Some("register_tun_fd") => {
                    #[cfg(target_os = "android")]
                    {
                        let challenge = serde_json::json!({
                            "status": "waiting_for_fd"
                        });
                        let mut challenge_str = serde_json::to_string(&challenge).unwrap();
                        challenge_str.push('\n');
                        let _ = writer.write_all(challenge_str.as_bytes()).await;
                        let _ = writer.flush().await;

                        match recv_fd_from_raw(raw_fd).await {
                            Ok(fd) => {
                                let tun_name = msg["tun_name"].as_str().unwrap_or("r2n0");
                                let mtu = msg["mtu"].as_u64().unwrap_or(1280) as u16;
                                let assigned_ipv4 = {
                                    let runtime = runtime_state.read().await;
                                    runtime
                                        .virtual_ip
                                        .as_ref()
                                        .and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
                                };
                                match TunDevice::from_fd(fd, tun_name, mtu, assigned_ipv4) {
                                    Ok(device) => {
                                        let name =
                                            device.name().unwrap_or_else(|_| tun_name.to_string());
                                        let effective_mtu = device.effective_mtu();
                                        *tun.write() = Some(Arc::new(device));
                                        {
                                            let mut runtime = runtime_state.write().await;
                                            runtime.tun_name = Some(name);
                                            runtime.backend_active = "tun".to_string();
                                            runtime.backend_degraded =
                                                runtime.backend_requested != "tun";
                                            runtime.effective_mtu = effective_mtu;
                                        }
                                        log::info!(
                                            "Successfully registered Android TUN fd {} (name: {}, mtu: {})",
                                            fd,
                                            tun_name,
                                            mtu
                                        );
                                        response = Some(serde_json::json!({
                                            "status": "ok",
                                            "message": "TUN device registered successfully"
                                        }));
                                    }
                                    Err(err) => {
                                        log::error!(
                                            "Failed to create TunDevice from fd {}: {}",
                                            fd,
                                            err
                                        );
                                        response = Some(serde_json::json!({
                                            "status": "error",
                                            "error": format!("Failed to create TunDevice: {}", err)
                                        }));
                                    }
                                }
                            }
                            Err(err) => {
                                log::error!("Failed to receive fd over Unix socket: {}", err);
                                response = Some(serde_json::json!({
                                    "status": "error",
                                    "error": format!("Failed to receive fd: {}", err)
                                }));
                            }
                        }
                    }
                    #[cfg(not(target_os = "android"))]
                    {
                        response = Some(serde_json::json!({
                            "status": "error",
                            "error": "register_tun_fd is only supported on Android"
                        }));
                    }
                }
                _ => {}
            }

            if let Some(res) = response {
                let mut res_str = serde_json::to_string(&res).unwrap();
                res_str.push('\n');
                let _ = writer.write_all(res_str.as_bytes()).await;
            }
        }
        line.clear();
    }
}

#[cfg(unix)]
pub async fn spawn_ipc_server(ctx: IpcServerContext) -> anyhow::Result<()> {
    let path = r2n_common::ipc::ipc_path();
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Err(err) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)) {
            log::warn!(
                "failed to relax IPC socket permissions for {}: {}",
                path,
                err
            );
        }
    }
    log::info!("IPC Server listening on Unix socket: {}", path);

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                handle_ipc_connection(
                    stream,
                    ctx.tx,
                    ctx.peers,
                    ctx.room_id,
                    ctx.tun,
                    ctx.metrics,
                    ctx.runtime_state,
                    ctx.dataplane,
                    ctx.node_id,
                )
                .await;
            });
        }
    });
    Ok(())
}

#[cfg(windows)]
pub async fn spawn_ipc_server(ctx: IpcServerContext) -> anyhow::Result<()> {
    let path = r2n_common::ipc::ipc_path();
    log::info!("IPC Server listening on Named Pipe: {}", path);

    tokio::spawn(async move {
        let mut first_instance = true;
        loop {
            let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
            if first_instance {
                options.first_pipe_instance(true);
            }
            let server = match options.create(&path) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Failed to create named pipe: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    first_instance = false;
                    continue;
                }
            };
            first_instance = false;

            match server.connect().await {
                Ok(_) => {
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        handle_ipc_connection(
                            server,
                            ctx.tx,
                            ctx.peers,
                            ctx.room_id,
                            ctx.tun,
                            ctx.metrics,
                            ctx.runtime_state,
                            ctx.dataplane,
                            ctx.node_id,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    log::error!("Named pipe connect error: {}", e);
                }
            }
        }
    });
    Ok(())
}

async fn wait_for_command_reply(
    reply_rx: tokio::sync::oneshot::Receiver<anyhow::Result<serde_json::Value>>,
) -> serde_json::Value {
    match tokio::time::timeout(std::time::Duration::from_secs(35), reply_rx).await {
        Ok(Ok(Ok(response))) => response,
        Ok(Ok(Err(err))) => serde_json::json!({
            "status": "error",
            "error": err.to_string()
        }),
        Ok(Err(_)) => serde_json::json!({
            "status": "error",
            "error": "daemon command channel closed"
        }),
        Err(_) => serde_json::json!({
            "status": "error",
            "error": "daemon command timed out"
        }),
    }
}

#[cfg(target_os = "android")]
async fn recv_fd_from_raw(
    socket_fd: std::os::unix::io::RawFd,
) -> std::io::Result<std::os::unix::io::RawFd> {
    use std::io;
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match try_recv_fd_once(socket_fd) {
            Ok(fd) => return Ok(fd),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(target_os = "android")]
fn try_recv_fd_once(
    socket_fd: std::os::unix::io::RawFd,
) -> std::io::Result<std::os::unix::io::RawFd> {
    use std::io;

    let mut iov_base = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: iov_base.as_mut_ptr() as *mut libc::c_void,
        iov_len: iov_base.len(),
    };

    let mut cmsg_buf = [0u8; unsafe {
        libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as libc::c_uint) as usize
    }];

    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: cmsg_buf.len() as _,
        msg_flags: 0,
    };

    let n = unsafe { libc::recvmsg(socket_fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "IPC socket closed before TUN fd was received",
        ));
    }

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let fd_ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;
                let fd = std::ptr::read_unaligned(fd_ptr);
                log::info!("Successfully received Android TUN fd {}", fd);
                return Ok(fd);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "No file descriptor received in SCM_RIGHTS",
    ))
}
