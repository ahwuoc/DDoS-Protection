use std::time::Duration;

pub const CLEANUP_INTERVAL_SECS: u64 = 60;

// --- Behavioral Thresholds ---
pub const THRESHOLD_IDLE_SECS: u64 = 5;
pub const THRESHOLD_TINY_PAYLOAD_BYTES: u64 = 128;
pub const THRESHOLD_SHORT_LIVED_SECS: u64 = 3;
pub const THRESHOLD_HEAL_MIN_DURATION: u64 = 60;
pub const THRESHOLD_HEAL_MIN_BYTES: u64 = 512;
pub const THRESHOLD_BURST_CONNECTS_PER_MIN: u32 = 5;

// --- Behavioral Penalties/Rewards ---
pub const PENALTY_IDLE_ATTACK: f32 = 5.0;
pub const PENALTY_PORT_SCAN: f32 = 2.0;
pub const PENALTY_TINY_PAYLOAD_SPAM: f32 = 2.0;
pub const PENALTY_LAGGY_USER: f32 = 1.0;
pub const PENALTY_FREQUENCY_MULTIPLIER: f32 = 2.0;
pub const REWARD_STABLE_PLAYER: f32 = 3.0;

// --- Smart Enhancements Constants ---
pub const TRUST_HIGH_BYTES: u64 = 20 * 1024 * 1024;
pub const TRUST_MEDIUM_BYTES: u64 = 5 * 1024 * 1024;
pub const MULTIPLIER_HIGH_TRUST: f32 = 0.2;
pub const MULTIPLIER_MEDIUM_TRUST: f32 = 0.5;
pub const PENALTY_SKEWED_RATIO: f32 = 1.5;
pub const SKEWED_RATIO_THRESHOLD: u64 = 10;

// --- Refactored Constants ---
pub const MINUTE_INTERVAL: Duration = Duration::from_secs(60);
pub const CLEAN_SCORE_THRESHOLD: f32 = 1.0;
pub const TRAFFIC_RATIO_SENT_MIN_BYTES: u64 = 1024;
pub const HEAL_BONUS_RECV_BYTES: u64 = 1024 * 1024;
pub const REWARD_STABLE_BONUS: f32 = 1.0;
pub const CLEANUP_DECAY_AMOUNT: f32 = 1.0;
pub const BAN_FLUSH_INTERVAL: Duration = Duration::from_secs(1);
pub const DEFAULT_IPV4_SUBNET_MASK: &str = "/24";
