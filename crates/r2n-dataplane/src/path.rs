use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct PathInfo {
    pub addr: SocketAddr,
    pub is_relay: bool,
    pub rtt_ewma: f32,
    pub jitter_ewma: f32,
    pub loss_ewma: f32,
    pub last_success: Instant,
}

impl PathInfo {
    pub fn new(addr: SocketAddr, is_relay: bool) -> Self {
        Self {
            addr,
            is_relay,
            rtt_ewma: if is_relay { 100.0 } else { 200.0 }, // Initial assumptions
            jitter_ewma: 0.0,
            loss_ewma: 0.0,
            last_success: Instant::now(),
        }
    }

    pub fn score(&self) -> f32 {
        let relay_penalty = if self.is_relay { 80.0 } else { 0.0 };
        self.rtt_ewma + self.jitter_ewma * 2.0 + self.loss_ewma * 1000.0 + relay_penalty
    }

    pub fn update_rtt(&mut self, rtt_ms: f32) {
        let alpha = 0.125;
        let diff = rtt_ms - self.rtt_ewma;
        self.rtt_ewma += alpha * diff;
        self.jitter_ewma += alpha * (diff.abs() - self.jitter_ewma);
        self.last_success = Instant::now();
    }
}

#[derive(Debug, Clone)]
pub struct PathManager {
    pub paths: Vec<PathInfo>,
    pub active_index: usize,
}

impl PathManager {
    pub fn new(relay_addr: SocketAddr) -> Self {
        let paths = vec![PathInfo::new(relay_addr, true)];
        Self {
            paths,
            active_index: 0,
        }
    }

    pub fn active_addr(&self) -> SocketAddr {
        self.paths[self.active_index].addr
    }

    pub fn is_active_relay(&self) -> bool {
        self.paths[self.active_index].is_relay
    }

    pub fn add_or_update_path(&mut self, addr: SocketAddr, is_relay: bool) -> usize {
        if let Some(pos) = self.paths.iter().position(|p| p.addr == addr) {
            pos
        } else {
            self.paths.push(PathInfo::new(addr, is_relay));
            self.paths.len() - 1
        }
    }

    pub fn record_success(&mut self, addr: SocketAddr, rtt_ms: f32) {
        if let Some(path) = self.paths.iter_mut().find(|p| p.addr == addr) {
            path.update_rtt(rtt_ms);
            let alpha = 0.1;
            path.loss_ewma = path.loss_ewma * (1.0 - alpha) + alpha * 0.0;
        }
        self.reevaluate();
    }

    pub fn record_failure(&mut self, addr: SocketAddr) {
        if let Some(path) = self.paths.iter_mut().find(|p| p.addr == addr) {
            let alpha = 0.1;
            path.loss_ewma = path.loss_ewma * (1.0 - alpha) + alpha * 1.0;
        }
        self.reevaluate();
    }

    fn reevaluate(&mut self) {
        if self.paths.is_empty() {
            return;
        }

        // Find best score among paths that succeeded recently (within 5 seconds)
        let now = Instant::now();
        let mut best_idx = 0;
        let mut best_score = f32::MAX;

        for (i, path) in self.paths.iter().enumerate() {
            if now.duration_since(path.last_success).as_secs() < 5 {
                let score = path.score();
                if score < best_score {
                    best_score = score;
                    best_idx = i;
                }
            }
        }
        self.active_index = best_idx;
    }
}
