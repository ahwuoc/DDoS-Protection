use anyhow::Result;
use std::fs;
use tracing::{info, warn};
use crate::config::KernelTuningConfig;

pub struct SysctlTuner;

impl SysctlTuner {
    /// Tunes kernel parameters based on the provided configuration.
    /// 
    /// ### Formula & Reasoning:
    /// 
    /// * **nf_conntrack_max**: 
    ///   - Mỗi entry tốn ~300 bytes (slab) + ~160-200 bytes metadata. 
    ///   - Công thức an toàn: `RAM_bytes / 16384`. 
    ///   - 1GB RAM ~ 65k entries. 2M entries tốn khoảng 1GB RAM khi bảng đầy.
    /// 
    /// * **tcp_max_syn_backlog**:
    ///   - Số lượng kết nối "nửa mở" (half-open) tối đa. 
    ///   - Mặc định 128-1024 là quá thấp. Cần >= 65535 để chịu tải SYN Flood.
    /// 
    /// * **tcp_syncookies**: 
    ///   - Cứu cánh cuối cùng. Khi backlog đầy, Kernel sẽ dùng mã hóa trong sequence number 
    ///     để không phải lưu trạng thái (Stateless). BẮT BUỘC BẬT = 1.
    /// 
    /// * **tcp_timeout_established**: 
    ///   - Mặc định Linux giữ 5 ngày. Quá lâu! Giảm xuống 1200s (20p) để giải phóng bảng 
    ///     conntrack nhanh hơn cho kết nối mới.
    pub fn tune_all(cfg: &KernelTuningConfig) -> Result<()> {
        if !cfg.enabled {
            info!("Kernel tuning is disabled in config");
            return Ok(());
        }

        info!("[*] Tuning kernel parameters from config...");

        Self::set("net/netfilter/nf_conntrack_max", &cfg.nf_conntrack_max.to_string())?;
        Self::set("net/ipv4/tcp_syncookies", if cfg.tcp_syncookies { "1" } else { "0" })?;
        Self::set("net/ipv4/tcp_max_syn_backlog", &cfg.tcp_max_syn_backlog.to_string())?;
        Self::set("net/core/somaxconn", &cfg.somaxconn.to_string())?;
        Self::set("net/netfilter/nf_conntrack_tcp_timeout_established", &cfg.tcp_timeout_established.to_string())?;
        Self::set("net/netfilter/nf_conntrack_tcp_timeout_syn_recv", &cfg.tcp_timeout_syn_recv.to_string())?;

        info!("[OK] Kernel parameters tuned successfully");
        Ok(())
    }

    fn set(path: &str, value: &str) -> Result<()> {
        let full_path = format!("/proc/sys/{}", path);
        match fs::write(&full_path, value) {
            Ok(_) => {
                info!("  - {} = {}", path, value);
                Ok(())
            }
            Err(e) => {
                warn!("  [ERR] Failed to set {}: {}. Run as root?", path, e);
                // Don't fail the whole process if some sysctls can't be set
                Ok(())
            }
        }
    }
}
