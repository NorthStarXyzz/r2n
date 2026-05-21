use anyhow::{Context, Result};
use r2n_common::NodeId;
use r2n_discovery::DiscoveryConfig;
use r2n_policy::TrafficPolicy;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    #[serde(default = "default_node_id")]
    pub node_id: NodeId,

    #[serde(
        default = "default_private_key",
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    pub private_key: [u8; 32],

    #[serde(default = "default_supernode_addr")]
    pub default_supernode: String,

    #[serde(default = "default_supernodes")]
    pub supernodes: Vec<String>,

    #[serde(default = "default_tun_name")]
    pub default_tun_name: String,

    #[serde(default = "default_local_port")]
    pub local_udp_port: u16,

    #[serde(default = "default_tun_mtu")]
    pub tun_mtu: u16,

    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,

    #[serde(default = "default_ping_interval")]
    pub ping_interval_secs: u64,

    #[serde(default = "default_watchdog_timeout")]
    pub watchdog_timeout_secs: u64,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default = "default_nickname")]
    pub nickname: String,

    #[serde(default)]
    pub discovery: DiscoveryConfig,

    #[serde(default)]
    pub backend: BackendConfig,

    #[serde(default)]
    pub virtual_lan: VirtualLanConfig,

    #[serde(default)]
    pub traffic_policy: TrafficPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    #[serde(default)]
    pub mode: BackendMode,

    #[serde(default)]
    pub desktop_l2_enhanced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualLanConfig {
    #[serde(default = "default_prefer_virtual_interface")]
    pub prefer_virtual_interface: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendMode {
    #[default]
    Tun,
    Tap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupernodeConfig {
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    #[serde(default)]
    pub public_addr: Option<String>,

    #[serde(default)]
    pub peers: Vec<String>,

    #[serde(default = "default_admin_token")]
    pub admin_token: String,

    #[serde(default = "default_management_bind")]
    pub management_bind: String,

    #[serde(default = "default_federation_id")]
    pub federation_id: String,

    #[serde(default = "default_address_pool")]
    pub address_pool: String,

    #[serde(default = "default_room_prefix_len")]
    pub room_prefix_len: u8,

    #[serde(default = "default_room_idle_timeout")]
    pub room_idle_timeout_secs: u64,

    #[serde(default = "default_max_room_peers")]
    pub max_room_peers: usize,

    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedConfigFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    edge: Option<EdgeConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supernode: Option<SupernodeConfig>,
}

fn default_local_port() -> u16 {
    0
}

fn default_node_id() -> NodeId {
    NodeId(rand::random::<[u8; 32]>())
}

fn default_private_key() -> [u8; 32] {
    rand::random::<[u8; 32]>()
}

fn default_tun_name() -> String {
    "r2n0".to_string()
}

fn default_tun_mtu() -> u16 {
    1280
}

fn default_prefer_virtual_interface() -> bool {
    true
}

fn default_stun_servers() -> Vec<String> {
    vec![
        "stun.miwifi.com:3478".to_string(),
        "stun.qq.com:3478".to_string(),
        "stun.12voip.com:3478".to_string(),
        "stun.aa.net.uk:3478".to_string(),
        "stun.acrobits.cz:3478".to_string(),
        "stun.actionvoip.com:3478".to_string(),
        "stun.annatel.net:3478".to_string(),
        "stun.antisip.com:3478".to_string(),
        "stun.cablenet-as.net:3478".to_string(),
        "stun.cheapvoip.com:3478".to_string(),
        "stun.commpeak.com:3478".to_string(),
        "stun.cope.es:3478".to_string(),
        "stun.dcalling.de:3478".to_string(),
        "stun.dus.net:3478".to_string(),
        "stun.easyvoip.com:3478".to_string(),
        "stun.epygi.com:3478".to_string(),
        "stun.freecall.com:3478".to_string(),
        "stun.freeswitch.org:3478".to_string(),
        "stun.freevoipdeal.com:3478".to_string(),
        "stun.halonet.pl:3478".to_string(),
        "stun.hoiio.com:3478".to_string(),
        "stun.infra.net:3478".to_string(),
        "stun.internetcalls.com:3478".to_string(),
        "stun.intervoip.com:3478".to_string(),
        "stun.ipfire.org:3478".to_string(),
        "stun.ippi.fr:3478".to_string(),
        "stun.it1.hr:3478".to_string(),
        "stun.jumblo.com:3478".to_string(),
        "stun.justvoip.com:3478".to_string(),
        "stun.linphone.org:3478".to_string(),
        "stun.liveo.fr:3478".to_string(),
        "stun.lowratevoip.com:3478".to_string(),
        "stun.myvoiptraffic.com:3478".to_string(),
        "stun.mywatson.it:3478".to_string(),
        "stun.netappel.com:3478".to_string(),
        "stun.netgsm.com.tr:3478".to_string(),
        "stun.nfon.net:3478".to_string(),
        "stun.nonoh.net:3478".to_string(),
        "stun.ooma.com:3478".to_string(),
        "stun.pjsip.org:3478".to_string(),
        "stun.poivy.com:3478".to_string(),
        "stun.powervoip.com:3478".to_string(),
        "stun.ppdi.com:3478".to_string(),
        "stun.rockenstein.de:3478".to_string(),
        "stun.rolmail.net:3478".to_string(),
        "stun.rynga.com:3478".to_string(),
        "stun.sip.us:3478".to_string(),
        "stun.sipdiscount.com:3478".to_string(),
        "stun.siplogin.de:3478".to_string(),
        "stun.sipnet.net:3478".to_string(),
        "stun.sipnet.ru:3478".to_string(),
        "stun.siptraffic.com:3478".to_string(),
        "stun.smartvoip.com:3478".to_string(),
        "stun.smsdiscount.com:3478".to_string(),
        "stun.solcon.nl:3478".to_string(),
        "stun.solnet.ch:3478".to_string(),
        "stun.sonetel.com:3478".to_string(),
        "stun.sonetel.net:3478".to_string(),
        "stun.srce.hr:3478".to_string(),
        "stun.tel.lu:3478".to_string(),
        "stun.telbo.com:3478".to_string(),
        "stun.t-online.de:3478".to_string(),
        "stun.twt.it:3478".to_string(),
        "stun.uls.co.za:3478".to_string(),
        "stun.usfamily.net:3478".to_string(),
        "stun.vo.lu:3478".to_string(),
        "stun.voicetrading.com:3478".to_string(),
        "stun.voip.aebc.com:3478".to_string(),
        "stun.voip.blackberry.com:3478".to_string(),
        "stun.voip.eutelia.it:3478".to_string(),
        "stun.voipblast.com:3478".to_string(),
        "stun.voipbuster.com:3478".to_string(),
        "stun.voipbusterpro.com:3478".to_string(),
        "stun.voipcheap.com:3478".to_string(),
        "stun.voipfibre.com:3478".to_string(),
        "stun.voipgain.com:3478".to_string(),
        "stun.voipinfocenter.com:3478".to_string(),
        "stun.voipplanet.nl:3478".to_string(),
        "stun.voippro.com:3478".to_string(),
        "stun.voipraider.com:3478".to_string(),
        "stun.voipstunt.com:3478".to_string(),
        "stun.voipwise.com:3478".to_string(),
        "stun.voipzoom.com:3478".to_string(),
        "stun.voys.nl:3478".to_string(),
        "stun.voztele.com:3478".to_string(),
        "stun.webcalldirect.com:3478".to_string(),
        "stun.zadarma.com:3478".to_string(),
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
        "stun2.l.google.com:19302".to_string(),
        "stun3.l.google.com:19302".to_string(),
        "stun4.l.google.com:19302".to_string(),
    ]
}

fn default_ping_interval() -> u64 {
    2
}

fn default_watchdog_timeout() -> u64 {
    25
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_nickname() -> String {
    "R2N-Peer".to_string()
}

fn default_supernode_addr() -> String {
    "127.0.0.1:7777".to_string()
}

fn default_supernodes() -> Vec<String> {
    vec![default_supernode_addr()]
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            mode: BackendMode::Tun,
            desktop_l2_enhanced: false,
        }
    }
}

impl Default for VirtualLanConfig {
    fn default() -> Self {
        Self {
            prefer_virtual_interface: default_prefer_virtual_interface(),
        }
    }
}

fn default_listen_port() -> u16 {
    7777
}

fn default_room_idle_timeout() -> u64 {
    300
}

fn default_max_room_peers() -> usize {
    16
}

fn default_admin_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

fn default_management_bind() -> String {
    "127.0.0.1:7778".to_string()
}

fn default_federation_id() -> String {
    "default".to_string()
}

fn default_address_pool() -> String {
    "192.168.0.0/16".to_string()
}

fn default_room_prefix_len() -> u8 {
    24
}

impl Default for EdgeConfig {
    fn default() -> Self {
        let default_supernode = default_supernode_addr();
        Self {
            node_id: default_node_id(),
            private_key: default_private_key(),
            default_supernode: default_supernode.clone(),
            supernodes: vec![default_supernode],
            default_tun_name: default_tun_name(),
            local_udp_port: default_local_port(),
            tun_mtu: default_tun_mtu(),
            stun_servers: default_stun_servers(),
            ping_interval_secs: default_ping_interval(),
            watchdog_timeout_secs: default_watchdog_timeout(),
            log_level: default_log_level(),
            nickname: default_nickname(),
            discovery: DiscoveryConfig::default(),
            backend: BackendConfig::default(),
            virtual_lan: VirtualLanConfig::default(),
            traffic_policy: TrafficPolicy::default(),
        }
    }
}

impl Default for SupernodeConfig {
    fn default() -> Self {
        Self {
            listen_port: default_listen_port(),
            public_addr: None,
            peers: Vec::new(),
            admin_token: default_admin_token(),
            management_bind: default_management_bind(),
            federation_id: default_federation_id(),
            address_pool: default_address_pool(),
            room_prefix_len: default_room_prefix_len(),
            room_idle_timeout_secs: default_room_idle_timeout(),
            max_room_peers: default_max_room_peers(),
            log_level: default_log_level(),
        }
    }
}

impl EdgeConfig {
    pub fn get_config_path() -> Option<PathBuf> {
        default_config_path()
    }

    pub fn load(path: &PathBuf) -> Result<Self> {
        let shared = load_shared_config(path)?;
        let mut config = if let Some(config) = shared.edge {
            config
        } else {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read config file at {:?}", path))?;
            toml::from_str(&content)
                .with_context(|| format!("Failed to parse TOML from {:?}", path))?
        };
        config.normalize();
        Ok(config)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory at {:?}", parent))?;
        }
        let mut shared = load_shared_config_if_present(path)?;
        shared.edge = Some(self.clone());
        save_shared_config(path, &shared)
    }

    pub fn load_or_create() -> Result<(Self, PathBuf)> {
        let path = Self::get_config_path()
            .ok_or_else(|| anyhow::anyhow!("Could not determine configuration path"))?;
        if path.exists() {
            let config = Self::load(&path)?;
            Ok((config, path))
        } else {
            let new_config = Self::default();
            new_config.save(&path)?;
            Ok((new_config, path))
        }
    }
}

impl EdgeConfig {
    pub fn normalize(&mut self) {
        self.tun_mtu = self.tun_mtu.max(1280);
        let default_supernode = self.default_supernode.trim().to_string();
        self.supernodes.retain(|node| !node.trim().is_empty());
        if self.supernodes.is_empty() && !default_supernode.is_empty() {
            self.supernodes.push(default_supernode.clone());
        }
        if !default_supernode.is_empty() && !self.supernodes.contains(&default_supernode) {
            self.supernodes.insert(0, default_supernode.clone());
        }
        if self.default_supernode.trim().is_empty()
            && let Some(first) = self.supernodes.first()
        {
            self.default_supernode = first.clone();
        }
    }
}

impl SupernodeConfig {
    pub fn get_config_path() -> Option<PathBuf> {
        default_config_path()
    }

    pub fn load(path: &PathBuf) -> Result<Self> {
        let shared = load_shared_config(path)?;
        if let Some(config) = shared.supernode {
            return Ok(config);
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file at {:?}", path))?;
        let config: SupernodeConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse TOML from {:?}", path))?;
        Ok(config)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory at {:?}", parent))?;
        }
        let mut shared = load_shared_config_if_present(path)?;
        shared.supernode = Some(self.clone());
        save_shared_config(path, &shared)
    }

    pub fn load_or_create() -> Result<(Self, PathBuf)> {
        let path = Self::get_config_path()
            .ok_or_else(|| anyhow::anyhow!("Could not determine configuration path"))?;
        if path.exists() {
            let config = Self::load(&path)?;
            Ok((config, path))
        } else {
            let new_config = Self::default();
            new_config.save(&path)?;
            Ok((new_config, path))
        }
    }
}

fn default_config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("R2N_CONFIG_PATH") {
        let trimmed = path.to_string_lossy().trim().to_string();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    let mut path = std::env::current_exe().ok()?;
    path.pop();
    Some(path.join("config.toml"))
}

fn load_shared_config(path: &PathBuf) -> Result<SharedConfigFile> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read config file at {:?}", path))?;
    parse_shared_config_content(path, &content)
}

fn load_shared_config_if_present(path: &PathBuf) -> Result<SharedConfigFile> {
    if path.exists() {
        load_shared_config(path)
    } else {
        Ok(SharedConfigFile::default())
    }
}

fn parse_shared_config_content(path: &PathBuf, content: &str) -> Result<SharedConfigFile> {
    if let Ok(shared) = toml::from_str::<SharedConfigFile>(content) {
        return Ok(shared);
    }

    if let Ok(mut edge) = toml::from_str::<EdgeConfig>(content) {
        edge.normalize();
        return Ok(SharedConfigFile {
            edge: Some(edge),
            supernode: None,
        });
    }

    if let Ok(supernode) = toml::from_str::<SupernodeConfig>(content) {
        return Ok(SharedConfigFile {
            edge: None,
            supernode: Some(supernode),
        });
    }

    Err(anyhow::anyhow!(
        "Failed to parse shared config file at {:?}",
        path
    ))
}

fn save_shared_config(path: &PathBuf, shared: &SharedConfigFile) -> Result<()> {
    let content =
        toml::to_string_pretty(shared).context("Failed to serialize shared config to TOML")?;
    fs::write(path, content)
        .with_context(|| format!("Failed to write config file to {:?}", path))?;
    Ok(())
}

fn serialize_hex<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

fn deserialize_hex<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let vec = hex::decode(&s).map_err(serde::de::Error::custom)?;
    if vec.len() != 32 {
        return Err(serde::de::Error::custom("Private key must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&vec);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn edge_config_defaults_virtual_lan_discovery() {
        let config: EdgeConfig = toml::from_str("").unwrap();
        assert!(config.discovery.broadcast);
        assert!(config.discovery.subnet_broadcast);
        assert!(config.discovery.multicast);
        assert!(config.discovery.mdns);
        assert!(config.discovery.ssdp);
        assert!(!config.discovery.netbios);
        assert_eq!(config.discovery.rate_limit_pps, 100);
        assert_eq!(config.backend.mode, BackendMode::Tun);
        assert!(!config.backend.desktop_l2_enhanced);
        assert!(config.virtual_lan.prefer_virtual_interface);
    }

    #[test]
    fn edge_config_loads_discovery_backend_and_virtual_lan_sections() {
        let config: EdgeConfig = toml::from_str(
            r#"
            [discovery]
            broadcast = false
            subnet_broadcast = true
            multicast = false
            mdns = true
            ssdp = false
            netbios = true
            rate_limit_pps = 42

            [backend]
            mode = "tap"
            desktop_l2_enhanced = true

            [virtual_lan]
            prefer_virtual_interface = false
            "#,
        )
        .unwrap();

        assert!(!config.discovery.broadcast);
        assert!(config.discovery.subnet_broadcast);
        assert!(!config.discovery.multicast);
        assert!(config.discovery.mdns);
        assert!(!config.discovery.ssdp);
        assert!(config.discovery.netbios);
        assert_eq!(config.discovery.rate_limit_pps, 42);
        assert_eq!(config.backend.mode, BackendMode::Tap);
        assert!(config.backend.desktop_l2_enhanced);
        assert!(!config.virtual_lan.prefer_virtual_interface);
    }

    #[test]
    fn edge_and_supernode_save_merge_into_shared_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let mut edge = EdgeConfig::default();
        edge.default_supernode = "203.0.113.10:7777".to_string();
        edge.save(&path).unwrap();

        let mut supernode = SupernodeConfig::default();
        supernode.listen_port = 9000;
        supernode.save(&path).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("[edge]"));
        assert!(content.contains("[supernode]"));

        let loaded_edge = EdgeConfig::load(&path).unwrap();
        let loaded_supernode = SupernodeConfig::load(&path).unwrap();
        assert_eq!(loaded_edge.default_supernode, "203.0.113.10:7777");
        assert_eq!(loaded_supernode.listen_port, 9000);
    }

    #[test]
    fn edge_save_preserves_existing_supernode_section() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let mut supernode = SupernodeConfig::default();
        supernode.management_bind = "127.0.0.1:9001".to_string();
        supernode.save(&path).unwrap();

        let mut edge = EdgeConfig::default();
        edge.default_tun_name = "r2n-test".to_string();
        edge.save(&path).unwrap();

        let loaded_supernode = SupernodeConfig::load(&path).unwrap();
        assert_eq!(loaded_supernode.management_bind, "127.0.0.1:9001");
    }
}
