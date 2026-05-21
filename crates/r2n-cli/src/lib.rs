use clap::{Parser, Subcommand};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

const DAEMON_BOOT_WAIT_RETRIES: usize = 15;
const DAEMON_BOOT_WAIT_INTERVAL_MS: u64 = 200;
const COMMAND_RESPONSE_TIMEOUT_SECS: u64 = 30;
const COLD_START_COMMAND_RESPONSE_TIMEOUT_SECS: u64 = 40;

#[derive(Parser)]
#[command(name = "r2n")]
#[command(about = "R2N: Rust-first Gaming LAN Tunnel", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Room management
    Room {
        #[command(subcommand)]
        action: RoomCommands,
    },
    /// Connection status
    Status,
    /// Runtime metrics
    Metrics,
    /// Run local diagnostics
    Diagnose,
    /// Run local diagnostics
    Doctor,
    /// Traffic restriction rules
    Rules {
        #[command(subcommand)]
        action: RulesCommands,
    },
    /// Supernode health and switching
    Supernode {
        #[command(subcommand)]
        action: SupernodeCommands,
    },
    /// Route diagnostics
    Route {
        #[command(subcommand)]
        action: RouteCommands,
    },
    /// L2/TAP diagnostics
    L2 {
        #[command(subcommand)]
        action: L2Commands,
    },
    /// Stop the background daemon
    Stop,
    /// Run as a daemon (Edge)
    Daemon {
        #[arg(short, long)]
        supernode: Option<String>,

        #[arg(short, long)]
        tun: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum RulesCommands {
    /// List traffic rules
    List,
    /// Add a traffic rule
    Add {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "deny")]
        action: String,
        #[arg(long, default_value = "both")]
        direction: String,
        #[arg(long, default_value = "any")]
        protocol: String,
        #[arg(long)]
        src_cidr: Option<String>,
        #[arg(long)]
        dst_cidr: Option<String>,
        #[arg(long)]
        src_port: Option<String>,
        #[arg(long)]
        dst_port: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    /// Remove a traffic rule by id
    Remove {
        #[arg(long)]
        id: String,
    },
    /// Enable all traffic rules
    Enable,
    /// Disable all traffic rules
    Disable,
}

#[derive(Subcommand)]
pub enum SupernodeCommands {
    /// List configured supernodes and active status
    List,
    /// Switch active supernode
    Switch {
        #[arg(long)]
        addr: String,
    },
}

#[derive(Subcommand)]
pub enum RouteCommands {
    /// Show virtual LAN and discovery routes
    Show,
}

#[derive(Subcommand)]
pub enum L2Commands {
    /// Show learned MAC table
    Table,
}

#[derive(Subcommand)]
pub enum RoomCommands {
    /// Create a new room
    Create {
        #[arg(short, long)]
        name: String,
    },
    /// Join a room using an invite code or a history index
    Join {
        /// Invite code to join the room
        #[arg(short, long)]
        invite: Option<String>,

        /// History index (from 'r2n room history') to join
        #[arg(short, long)]
        index: Option<usize>,
    },
    /// Leave the current room
    Leave,
    /// List room members
    List,
    /// List active rooms on the supernode
    Active,
    /// List local room join/creation history
    History,
}

#[cfg(windows)]
async fn try_connect_windows() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient>
{
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&r2n_common::ipc::ipc_path())
        {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(231) => {
                // ERROR_PIPE_BUSY
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn send_command(cmd: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let is_stop = cmd["command"].as_str() == Some("stop");
    let mut started_daemon = false;

    #[cfg(unix)]
    let connect_result = tokio::net::UnixStream::connect(&r2n_common::ipc::ipc_path()).await;

    #[cfg(windows)]
    let connect_result = try_connect_windows().await;

    let mut stream = match connect_result {
        Ok(s) => s,
        Err(e) => {
            if is_stop {
                println!("Daemon is not running.");
                std::process::exit(0);
            }

            println!("Daemon is not running. Attempting to start daemon in background...");
            let exe = std::env::current_exe()?;
            let log_path = std::env::temp_dir().join("r2n_daemon.log");
            println!("Daemon logs are being written to {:?}", log_path);
            let log_file = std::fs::File::create(&log_path)?;
            std::process::Command::new(exe)
                .arg("daemon")
                .stdin(std::process::Stdio::null())
                .stdout(log_file.try_clone()?)
                .stderr(log_file)
                .spawn()?;
            started_daemon = true;

            // Wait up to 3 seconds for the daemon to start and initialize the IPC channel
            let mut connected = None;
            for _ in 0..DAEMON_BOOT_WAIT_RETRIES {
                tokio::time::sleep(std::time::Duration::from_millis(
                    DAEMON_BOOT_WAIT_INTERVAL_MS,
                ))
                .await;
                #[cfg(unix)]
                let res = tokio::net::UnixStream::connect(&r2n_common::ipc::ipc_path()).await;
                #[cfg(windows)]
                let res = try_connect_windows().await;

                if let Ok(s) = res {
                    connected = Some(s);
                    break;
                }
            }
            match connected {
                Some(s) => s,
                None => {
                    #[cfg(unix)]
                    anyhow::bail!(
                        "Failed to start/connect to daemon. Note: Creating a TUN interface usually requires root/Administrator privileges. Please run 'sudo r2n daemon' or start the daemon manually. Connection error details: {e}"
                    );
                    #[cfg(windows)]
                    anyhow::bail!(
                        "Failed to start/connect to daemon. Note: Creating a TUN interface usually requires Administrator privileges. Please start the daemon manually as Administrator. Connection error details: {e}"
                    );
                }
            }
        }
    };

    let mut data = serde_json::to_string(&cmd)?;
    data.push('\n');

    stream.write_all(data.as_bytes()).await?;

    let mut reader = tokio::io::BufReader::new(stream);
    let mut response = String::new();
    let timeout_secs = if started_daemon {
        COLD_START_COMMAND_RESPONSE_TIMEOUT_SECS
    } else {
        COMMAND_RESPONSE_TIMEOUT_SECS
    };
    match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        reader.read_line(&mut response),
    )
    .await
    {
        Ok(read_result) => {
            read_result?;
        }
        Err(_) => {
            if started_daemon {
                anyhow::bail!(
                    "daemon started but did not answer the first command within {} seconds; try running 'r2n daemon' manually to inspect startup logs",
                    timeout_secs
                );
            }
            anyhow::bail!("daemon did not answer within {} seconds", timeout_secs);
        }
    }

    let res: serde_json::Value = serde_json::from_str(&response)?;
    if res["status"].as_str() == Some("error") {
        anyhow::bail!(
            "{}",
            res["error"]
                .as_str()
                .unwrap_or("local daemon command failed")
        );
    }
    Ok(res)
}

fn parse_port_ranges(value: Option<String>) -> anyhow::Result<Vec<serde_json::Value>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let mut ranges = Vec::new();
    for part in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (start, end) = if let Some((start, end)) = part.split_once('-') {
            (start.parse::<u16>()?, end.parse::<u16>()?)
        } else {
            let port = part.parse::<u16>()?;
            (port, port)
        };
        if start > end {
            anyhow::bail!("invalid port range: {part}");
        }
        ranges.push(json!({ "start": start, "end": end }));
    }
    Ok(ranges)
}

fn print_diagnosis(res: &serde_json::Value) {
    println!("Node ID:      {}", res["node_id"].as_str().unwrap_or("-"));
    println!("Room ID:      {}", res["room_id"].as_str().unwrap_or("-"));
    println!("Supernode:    {}", res["supernode"].as_str().unwrap_or("-"));
    println!(
        "Reachable:    {}",
        res["supernode_reachable"].as_bool().unwrap_or(false)
    );
    println!("NAT:          {}", res["nat_type"].as_str().unwrap_or("-"));
    println!(
        "Backend:      requested={}, active={}, degraded={}",
        res["backend_requested"].as_str().unwrap_or("-"),
        res["backend_active"].as_str().unwrap_or("-"),
        res["backend_degraded"].as_bool().unwrap_or(false)
    );
    println!(
        "MTU:          {}",
        res["effective_mtu"].as_u64().unwrap_or(0)
    );
    println!(
        "Route:        cidr={}, installed={}",
        res["route_cidr"].as_str().unwrap_or("-"),
        res["route_installed"].as_bool().unwrap_or(false)
    );
    println!(
        "Discovery:    routes={}, broadcast={}, multicast={}, l2_flood={}",
        res["discovery_routes_installed"].as_bool().unwrap_or(false),
        res["broadcast_packets"].as_u64().unwrap_or(0),
        res["multicast_packets"].as_u64().unwrap_or(0),
        res["l2_flood_packets"].as_u64().unwrap_or(0)
    );
    println!(
        "Rules:        enabled={}, count={}",
        res["rules_enabled"].as_bool().unwrap_or(false),
        res["rules_count"].as_u64().unwrap_or(0)
    );
    let last_error = res["last_error"].as_str().unwrap_or("");
    if !last_error.is_empty() {
        println!("Last Error:   {}", last_error);
    }
}

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Room { action } => match action {
            RoomCommands::Create { name } => {
                let res = send_command(json!({ "command": "create", "name": name })).await?;
                println!("Room ID:      {}", res["room_id"].as_str().unwrap_or("-"));
                println!(
                    "Virtual IP:   {}",
                    res["assigned_ip"].as_str().unwrap_or("-")
                );
                println!(
                    "Virtual CIDR: {}",
                    res["virtual_cidr"].as_str().unwrap_or("-")
                );
                println!(
                    "Invite Code:  {}",
                    res["invite_code"].as_str().unwrap_or("-")
                );
            }
            RoomCommands::Join { invite, index } => {
                let invite_code = if let Some(idx) = index {
                    let res = send_command(json!({ "command": "history" })).await?;
                    let history = res["history"].as_array().ok_or_else(|| {
                        anyhow::anyhow!("Failed to retrieve history list from daemon")
                    })?;
                    if idx == 0 || idx > history.len() {
                        anyhow::bail!(
                            "Invalid history index. Please run 'r2n room history' to view valid indexes."
                        );
                    }
                    let item = &history[idx - 1];
                    item["invite_code"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Invalid invite code in history"))?
                        .to_string()
                } else if let Some(inv) = invite {
                    inv
                } else {
                    anyhow::bail!(
                        "Please specify either an invite code with --invite, or a history index with --index."
                    );
                };

                let res = send_command(json!({ "command": "join", "invite": invite_code })).await?;
                println!("Joined Room:  {}", res["room_id"].as_str().unwrap_or("-"));
                println!(
                    "Virtual IP:   {}",
                    res["assigned_ip"].as_str().unwrap_or("-")
                );
                println!(
                    "Virtual CIDR: {}",
                    res["virtual_cidr"].as_str().unwrap_or("-")
                );
            }
            RoomCommands::Active => {
                let res = send_command(json!({ "command": "active" })).await?;
                if let Some(rooms) = res["rooms"].as_array() {
                    if rooms.is_empty() {
                        println!("No active rooms on the supernode.");
                    } else {
                        println!(
                            "{:<4} {:<36} {:<15} {:<6}",
                            "No.", "Room ID", "Name", "Peers"
                        );
                        println!("{}", "-".repeat(65));
                        for (idx, r) in rooms.iter().enumerate() {
                            println!(
                                "{:<4} {:<36} {:<15} {:<6}",
                                idx + 1,
                                r["room_id"].as_str().unwrap_or("-"),
                                r["name"].as_str().unwrap_or("-"),
                                r["member_count"].as_u64().unwrap_or(0)
                            );
                        }
                    }
                } else {
                    println!("Failed to retrieve active rooms list.");
                }
            }
            RoomCommands::History => {
                let res = send_command(json!({ "command": "history" })).await?;
                if let Some(history) = res["history"].as_array() {
                    if history.is_empty() {
                        println!("No local room history found.");
                    } else {
                        println!(
                            "{:<4} {:<36} {:<15} {:<30}",
                            "No.", "Room ID", "Name", "Invite Code"
                        );
                        println!("{}", "-".repeat(90));
                        for (idx, item) in history.iter().enumerate() {
                            let invite = item["invite_code"].as_str().unwrap_or("-");
                            let display_invite = if invite.len() > 30 {
                                format!("{}...", &invite[..27])
                            } else {
                                invite.to_string()
                            };
                            println!(
                                "{:<4} {:<36} {:<15} {:<30}",
                                idx + 1,
                                item["room_id"].as_str().unwrap_or("-"),
                                item["name"].as_str().unwrap_or("-"),
                                display_invite
                            );
                        }
                    }
                } else {
                    println!("Failed to retrieve history list.");
                }
            }
            RoomCommands::Leave => {
                let res = send_command(json!({ "command": "leave" })).await?;
                println!("{}", res["message"].as_str().unwrap_or("Left room."));
            }
            RoomCommands::List => match send_command(json!({ "command": "peers" })).await {
                Ok(res) => {
                    if let Some(arr) = res["peers"].as_array() {
                        if arr.is_empty() {
                            println!("No other peers in the room.");
                        } else {
                            println!(
                                "{:<20} {:<15} {:<12} {:<6} {:<8}",
                                "Nickname", "Virtual IP", "Connection", "RTT", "Loss"
                            );
                            println!("{}", "-".repeat(67));
                            for p in arr {
                                let rtt = p["rtt_ms"]
                                    .as_u64()
                                    .map(|value| format!("{value}ms"))
                                    .unwrap_or_else(|| "-".to_string());
                                let loss = p["loss_rate"]
                                    .as_f64()
                                    .map(|value| format!("{:.1}%", value * 100.0))
                                    .unwrap_or_else(|| "-".to_string());
                                println!(
                                    "{:<20} {:<15} {:<12} {:<6} {:<8}",
                                    p["nickname"].as_str().unwrap_or("-"),
                                    p["virtual_ip"].as_str().unwrap_or("-"),
                                    p["connection"].as_str().unwrap_or("Relay"),
                                    rtt,
                                    loss
                                );
                            }
                        }
                    }
                }
                Err(e) => eprintln!(
                    "Error: Failed to query peers from local daemon. Details: {}",
                    e
                ),
            },
        },
        Commands::Status => match send_command(json!({ "command": "status" })).await {
            Ok(res) => {
                println!("Node ID:  {}", res["node_id"].as_str().unwrap_or("-"));
                let room_id = res["room_id"].as_str().unwrap_or("");
                if room_id.is_empty() {
                    println!("Room ID:  Not in a room");
                } else {
                    println!("Room ID:  {}", room_id);
                }
                println!(
                    "Status:   {}",
                    res["status"].as_str().unwrap_or("Disconnected")
                );
                println!("Supernode: {}", res["supernode"].as_str().unwrap_or("-"));
                let tun_name = res["tun_name"].as_str().unwrap_or("");
                if !tun_name.is_empty() {
                    println!("TUN:       {}", tun_name);
                }
                let virtual_ip = res["virtual_ip"].as_str().unwrap_or("");
                if !virtual_ip.is_empty() {
                    println!("Virtual IP: {}", virtual_ip);
                }
                let route_cidr = res["route_cidr"].as_str().unwrap_or("");
                if !route_cidr.is_empty() {
                    println!("Route:     {}", route_cidr);
                }
                println!(
                    "Route OK:  {}",
                    res["route_status"].as_str().unwrap_or("Unknown")
                );
                let backend_requested = res["backend_requested"].as_str().unwrap_or("");
                let backend_active = res["backend_active"].as_str().unwrap_or("");
                if !backend_requested.is_empty() || !backend_active.is_empty() {
                    println!(
                        "Backend:   requested={}, active={}, degraded={}",
                        if backend_requested.is_empty() {
                            "-"
                        } else {
                            backend_requested
                        },
                        if backend_active.is_empty() {
                            "-"
                        } else {
                            backend_active
                        },
                        res["backend_degraded"].as_bool().unwrap_or(false)
                    );
                }
                if let Some(mtu) = res["effective_mtu"].as_u64()
                    && mtu > 0
                {
                    println!("MTU:       {}", mtu);
                }
                if res["virtual_interface_preference_requested"]
                    .as_bool()
                    .unwrap_or(false)
                {
                    println!(
                        "VLAN Pref: supported={}, applied={}",
                        res["virtual_interface_preference_supported"]
                            .as_bool()
                            .unwrap_or(false),
                        res["virtual_interface_preference_applied"]
                            .as_bool()
                            .unwrap_or(false)
                    );
                    let pref_error = res["virtual_interface_preference_error"]
                        .as_str()
                        .unwrap_or("");
                    if !pref_error.is_empty() {
                        println!("VLAN Err:  {}", pref_error);
                    }
                }
                println!(
                    "Discovery: {}",
                    if res["discovery_routes_installed"].as_bool().unwrap_or(false) {
                        "Routes Installed"
                    } else {
                        "Routes Missing"
                    }
                );
                if let Some(errors) = res["discovery_route_errors"].as_array() {
                    for error in errors {
                        if let Some(error) = error.as_str() {
                            println!("Disc Err:  {}", error);
                        }
                    }
                }
                println!(
                    "Port Map:  {}",
                    if res["port_mapping_acquired"].as_bool().unwrap_or(false) {
                        "Acquired"
                    } else {
                        "Not Acquired"
                    }
                );
                let mapping_protocol = res["port_mapping_protocol"].as_str().unwrap_or("");
                if !mapping_protocol.is_empty() {
                    println!("Map Proto: {}", mapping_protocol);
                }
                let mapping_addr = res["port_mapping_external_addr"].as_str().unwrap_or("");
                if !mapping_addr.is_empty() {
                    println!("Map Addr:  {}", mapping_addr);
                }
                if let Some(lease_remaining) = res["port_mapping_lease_remaining_secs"].as_u64()
                    && lease_remaining > 0
                {
                    println!("Map Lease: {}s", lease_remaining);
                }
                println!("Peers:     {}", res["peer_count"].as_u64().unwrap_or(0));
                let last_error = res["last_error"].as_str().unwrap_or("");
                if !last_error.is_empty() {
                    println!("Last Err:  {}", last_error);
                }

                // Add peer details directly in status
                if !room_id.is_empty()
                    && let Ok(peer_res) = send_command(json!({ "command": "peers" })).await
                    && let Some(arr) = peer_res["peers"].as_array()
                {
                    println!("\n--- Room Peers ---");
                    if arr.is_empty() {
                        println!("No other peers in the room.");
                    } else {
                        println!(
                            "{:<20} {:<15} {:<12} {:<6} {:<8}",
                            "Nickname", "Virtual IP", "Connection", "RTT", "Loss"
                        );
                        println!("{}", "-".repeat(67));
                        for p in arr {
                            let rtt = p["rtt_ms"]
                                .as_u64()
                                .map(|value| format!("{value}ms"))
                                .unwrap_or_else(|| "-".to_string());
                            let loss = p["loss_rate"]
                                .as_f64()
                                .map(|value| format!("{:.1}%", value * 100.0))
                                .unwrap_or_else(|| "-".to_string());
                            println!(
                                "{:<20} {:<15} {:<12} {:<6} {:<8}",
                                p["nickname"].as_str().unwrap_or("-"),
                                p["virtual_ip"].as_str().unwrap_or("-"),
                                p["connection"].as_str().unwrap_or("Relay"),
                                rtt,
                                loss
                            );
                        }
                    }
                }
            }
            Err(e) => eprintln!(
                "Error: Failed to query status from local daemon. Details: {}",
                e
            ),
        },
        Commands::Metrics => match send_command(json!({ "command": "metrics" })).await {
            Ok(res) => {
                println!(
                    "Handshake Successes: {}",
                    res["handshake_successes"].as_u64().unwrap_or(0)
                );
                println!(
                    "Handshake Failures: {}",
                    res["handshake_failures"].as_u64().unwrap_or(0)
                );
                println!(
                    "Direct Packets:      {}",
                    res["direct_packets"].as_u64().unwrap_or(0)
                );
                println!(
                    "Relay Packets:       {}",
                    res["relay_packets"].as_u64().unwrap_or(0)
                );
                println!(
                    "Packet Drops:        {}",
                    res["packet_drops"].as_u64().unwrap_or(0)
                );
                println!(
                    "Broadcast Packets:   {}",
                    res["broadcast_packets"].as_u64().unwrap_or(0)
                );
                println!(
                    "Multicast Packets:   {}",
                    res["multicast_packets"].as_u64().unwrap_or(0)
                );
                println!(
                    "L2 Flood Packets:    {}",
                    res["l2_flood_packets"].as_u64().unwrap_or(0)
                );
                println!(
                    "Port Mapping:        {}",
                    if res["port_mapping_acquired"].as_bool().unwrap_or(false) {
                        "Yes"
                    } else {
                        "No"
                    }
                );
                let mapping_protocol = res["port_mapping_protocol"].as_str().unwrap_or("");
                if !mapping_protocol.is_empty() {
                    println!("Mapping Protocol:    {}", mapping_protocol);
                }
                let mapping_addr = res["port_mapping_external_addr"].as_str().unwrap_or("");
                if !mapping_addr.is_empty() {
                    println!("Mapped Public Addr:  {}", mapping_addr);
                }
                if let Some(lease_remaining) = res["port_mapping_lease_remaining_secs"].as_u64()
                    && lease_remaining > 0
                {
                    println!("Lease Remaining:     {}s", lease_remaining);
                }
                if let Some(peers) = res["peers"].as_array()
                    && !peers.is_empty()
                {
                    println!();
                    println!(
                        "{:<18} {:<8} {:<8} {:<8} {:<8} {:<8}",
                        "Peer", "Path", "RTT", "Loss", "Direct", "Relay"
                    );
                    println!("{}", "-".repeat(68));
                    for peer in peers {
                        let peer_label = peer["peer"]
                            .as_str()
                            .map(|value| &value[..16.min(value.len())])
                            .unwrap_or("-");
                        let rtt_label = peer["last_rtt_ms"]
                            .as_u64()
                            .map(|value| format!("{value}ms"))
                            .unwrap_or_else(|| "-".to_string());
                        let loss_label = peer["packet_loss_rate"]
                            .as_f64()
                            .map(|value| format!("{:.1}%", value * 100.0))
                            .unwrap_or_else(|| "-".to_string());
                        println!(
                            "{:<18} {:<8} {:<8} {:<8} {:<8} {:<8}",
                            peer_label,
                            peer["path"].as_str().unwrap_or("-"),
                            rtt_label,
                            loss_label,
                            peer["direct_hits"].as_u64().unwrap_or(0),
                            peer["relay_hits"].as_u64().unwrap_or(0),
                        );
                    }
                }
            }
            Err(e) => eprintln!(
                "Error: Failed to query runtime metrics from local daemon. Details: {}",
                e
            ),
        },
        Commands::Diagnose | Commands::Doctor => {
            let res = send_command(json!({ "command": "diagnose" })).await?;
            print_diagnosis(&res);
        }
        Commands::Rules { action } => match action {
            RulesCommands::List => {
                let res = send_command(json!({ "command": "rules_list" })).await?;
                let policy = &res["policy"];
                println!("Enabled: {}", policy["enabled"].as_bool().unwrap_or(false));
                println!(
                    "Default: {}",
                    policy["default_action"].as_str().unwrap_or("allow")
                );
                let rules = policy["rules"].as_array().cloned().unwrap_or_default();
                if rules.is_empty() {
                    println!("No traffic rules configured.");
                } else {
                    println!(
                        "{:<18} {:<7} {:<9} {:<7} {:<18} {:<18}",
                        "ID", "Action", "Direction", "Proto", "Src", "Dst"
                    );
                    println!("{}", "-".repeat(78));
                    for rule in rules {
                        println!(
                            "{:<18} {:<7} {:<9} {:<7} {:<18} {:<18}",
                            rule["id"].as_str().unwrap_or("-"),
                            rule["action"].as_str().unwrap_or("-"),
                            rule["direction"].as_str().unwrap_or("-"),
                            rule["protocol"].as_str().unwrap_or("any"),
                            rule["src_cidr"].as_str().unwrap_or("*"),
                            rule["dst_cidr"].as_str().unwrap_or("*")
                        );
                    }
                }
            }
            RulesCommands::Add {
                id,
                action,
                direction,
                protocol,
                src_cidr,
                dst_cidr,
                src_port,
                dst_port,
                description,
            } => {
                let rule = json!({
                    "id": id,
                    "enabled": true,
                    "action": action.to_lowercase(),
                    "direction": direction.to_lowercase(),
                    "src_cidr": src_cidr,
                    "dst_cidr": dst_cidr,
                    "protocol": protocol.to_lowercase(),
                    "src_ports": parse_port_ranges(src_port)?,
                    "dst_ports": parse_port_ranges(dst_port)?,
                    "description": description
                });
                let res = send_command(json!({ "command": "rules_add", "rule": rule })).await?;
                println!(
                    "Rule added. Count: {}",
                    res["policy"]["rules"]
                        .as_array()
                        .map(|rules| rules.len())
                        .unwrap_or(0)
                );
            }
            RulesCommands::Remove { id } => {
                let res = send_command(json!({ "command": "rules_remove", "id": id })).await?;
                println!(
                    "Rule removed. Count: {}",
                    res["policy"]["rules"]
                        .as_array()
                        .map(|rules| rules.len())
                        .unwrap_or(0)
                );
            }
            RulesCommands::Enable => {
                let _ = send_command(json!({ "command": "rules_enable", "enabled": true })).await?;
                println!("Traffic rules enabled.");
            }
            RulesCommands::Disable => {
                let _ =
                    send_command(json!({ "command": "rules_enable", "enabled": false })).await?;
                println!("Traffic rules disabled.");
            }
        },
        Commands::Supernode { action } => match action {
            SupernodeCommands::List => {
                let res = send_command(json!({ "command": "supernodes" })).await?;
                println!("Active:    {}", res["active"].as_str().unwrap_or("-"));
                println!("Reachable: {}", res["reachable"].as_bool().unwrap_or(false));
                if let Some(nodes) = res["supernodes"].as_array() {
                    println!("Configured:");
                    for node in nodes {
                        println!("  {}", node.as_str().unwrap_or("-"));
                    }
                }
            }
            SupernodeCommands::Switch { addr } => {
                let res = send_command(json!({ "command": "switch_supernode", "supernode": addr }))
                    .await?;
                println!(
                    "{}",
                    res["message"].as_str().unwrap_or("Supernode switched.")
                );
            }
        },
        Commands::Route { action } => match action {
            RouteCommands::Show => {
                let res = send_command(json!({ "command": "routes" })).await?;
                println!("TUN:        {}", res["tun_name"].as_str().unwrap_or("-"));
                println!("Route CIDR: {}", res["route_cidr"].as_str().unwrap_or("-"));
                println!(
                    "Installed:  {}",
                    res["route_installed"].as_bool().unwrap_or(false)
                );
                println!(
                    "Discovery:  {}",
                    res["discovery_routes_installed"].as_bool().unwrap_or(false)
                );
                if let Some(errors) = res["discovery_route_errors"].as_array() {
                    for error in errors {
                        println!("Error:      {}", error.as_str().unwrap_or("-"));
                    }
                }
            }
        },
        Commands::L2 { action } => match action {
            L2Commands::Table => {
                let res = send_command(json!({ "command": "l2_table" })).await?;
                let entries = res["entries"].as_array().cloned().unwrap_or_default();
                if entries.is_empty() {
                    println!("No learned L2 MAC entries.");
                } else {
                    println!(
                        "{:<18} {:<18} {:<10} {:<10}",
                        "MAC", "Node", "Learned", "Idle"
                    );
                    println!("{}", "-".repeat(62));
                    for entry in entries {
                        let node = entry["node_id"].as_str().unwrap_or("-");
                        let node_short = &node[..18.min(node.len())];
                        println!(
                            "{:<18} {:<18} {:<10} {:<10}",
                            entry["mac"].as_str().unwrap_or("-"),
                            node_short,
                            format!("{}s", entry["learned_for_secs"].as_u64().unwrap_or(0)),
                            format!("{}s", entry["idle_for_secs"].as_u64().unwrap_or(0))
                        );
                    }
                }
            }
        },
        Commands::Daemon { supernode, tun } => {
            let (mut config, config_path) = r2n_config::EdgeConfig::load_or_create()?;
            println!("Loaded configuration from {:?}", config_path);

            let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone());
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&log_level))
                .init();

            // Command line args can override config file
            let final_supernode = supernode.unwrap_or_else(|| config.default_supernode.clone());
            let final_tun = tun.unwrap_or_else(|| config.default_tun_name.clone());

            let mut should_save_config = false;
            if config.default_supernode != final_supernode {
                config.default_supernode = final_supernode.clone();
                if !config.supernodes.contains(&final_supernode) {
                    config.supernodes.insert(0, final_supernode.clone());
                }
                should_save_config = true;
            }
            if config.default_tun_name != final_tun {
                config.default_tun_name = final_tun.clone();
                should_save_config = true;
            }
            if should_save_config {
                config.save(&config_path)?;
            }

            let supernode_addr = tokio::net::lookup_host(&final_supernode)
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("Failed to resolve supernode address"))?;
            let mut supernodes = Vec::new();
            for supernode in &config.supernodes {
                if let Some(addr) = tokio::net::lookup_host(supernode).await?.next() {
                    supernodes.push(addr);
                }
            }
            if !supernodes.contains(&supernode_addr) {
                supernodes.insert(0, supernode_addr);
            }

            println!("Starting R2N Edge Daemon...");
            println!("Node ID: {}", config.node_id);
            println!("Supernode: {}", supernode_addr);
            if supernodes.len() > 1 {
                println!("Supernodes: {}", supernodes.len());
            }
            println!("TUN Interface: {}", final_tun);
            println!("MTU: {}", config.tun_mtu.max(1280));
            println!(
                "Backend: requested={}, desktop_l2_enhanced={}",
                match config.backend.mode {
                    r2n_config::BackendMode::Tun => "tun",
                    r2n_config::BackendMode::Tap => "tap",
                },
                config.backend.desktop_l2_enhanced
            );
            println!(
                "Virtual LAN: prefer_virtual_interface={}",
                config.virtual_lan.prefer_virtual_interface
            );
            println!(
                "Discovery: broadcast={}, subnet_broadcast={}, multicast={}, mdns={}, ssdp={}, netbios={}, rate_limit_pps={}",
                config.discovery.broadcast,
                config.discovery.subnet_broadcast,
                config.discovery.multicast,
                config.discovery.mdns,
                config.discovery.ssdp,
                config.discovery.netbios,
                config.discovery.rate_limit_pps
            );

            let local_addr = format!("0.0.0.0:{}", config.local_udp_port);

            let edge = r2n_edge_lib::Edge::new(
                config.node_id,
                config.private_key,
                config.nickname.clone(),
                &local_addr,
                supernode_addr,
                supernodes,
                &final_tun,
                config.stun_servers.clone(),
                config.tun_mtu,
                config.discovery.clone(),
                config.backend.clone(),
                config.virtual_lan.clone(),
                config.traffic_policy.clone(),
            )
            .await?;

            edge.run().await?;
        }
        Commands::Stop => match send_command(json!({ "command": "stop" })).await {
            Ok(res) => {
                println!(
                    "{}",
                    res["message"]
                        .as_str()
                        .unwrap_or("Daemon stopped successfully.")
                );
            }
            Err(e) => eprintln!("Error: Failed to stop daemon. Details: {e}"),
        },
    }

    Ok(())
}
