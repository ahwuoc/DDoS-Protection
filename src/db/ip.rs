use super::IpDatabase;
use anyhow::Result;
use rusqlite::params;
use std::net::IpAddr;
use tracing::info;

// ── Whitelist Record ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WhitelistRecord {
    pub ip: String,
    pub country: String,
    pub asn_org: String,
    pub reason: String,
    pub created_at: String,
}

// ── Blacklist Record ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BlacklistRecord {
    pub ip: String,
    pub strikes: u32,
    pub country: String,
    pub asn_org: String,
    pub reason: String,
    pub created_at: String,
}

// ── Whitelist CRUD ──────────────────────────────────────

impl IpDatabase {
    /// Add IP to whitelist (UPSERT — no duplicates).
    pub fn whitelist_ip(&self, ip: &str, country: &str, asn_org: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO whitelist (ip, country, asn_org)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(ip) DO UPDATE SET
                country = excluded.country,
                asn_org = excluded.asn_org",
            params![ip, country, asn_org],
        )?;
        Ok(())
    }

    /// Remove IP from whitelist.
    pub fn unwhitelist_ip(&self, ip: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute("DELETE FROM whitelist WHERE ip = ?1", params![ip])?;
        Ok(())
    }

    /// Load all whitelisted IPs.
    pub fn load_whitelisted_ips(&self) -> Result<Vec<IpAddr>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare("SELECT ip FROM whitelist")?;
        let ips = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();
        Ok(ips)
    }

    /// Load all whitelist records (with metadata).
    pub fn load_whitelist_records(&self) -> Result<Vec<WhitelistRecord>> {
        let conn = self.lock_conn()?;
        let mut stmt =
            conn.prepare("SELECT ip, country, asn_org, reason, created_at FROM whitelist")?;
        let records = stmt
            .query_map([], |row| {
                Ok(WhitelistRecord {
                    ip: row.get(0)?,
                    country: row.get(1)?,
                    asn_org: row.get(2)?,
                    reason: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(records)
    }

    /// Count whitelisted IPs.
    pub fn whitelist_count(&self) -> usize {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return 0,
        };
        conn.query_row("SELECT COUNT(*) FROM whitelist", [], |row| {
            row.get::<_, usize>(0)
        })
        .unwrap_or(0)
    }

    /// Check if whitelist table is empty.
    pub fn is_whitelist_empty(&self) -> bool {
        self.whitelist_count() == 0
    }

    /// Update country/ASN for a whitelist IP.
    pub fn update_whitelist_geo(&self, ip: &str, country: &str, asn_org: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE whitelist SET country = ?1, asn_org = ?2 WHERE ip = ?3",
            params![country, asn_org, ip],
        )?;
        Ok(())
    }

    /// Load whitelist IPs that still have `??` country (need GeoIP enrichment).
    pub fn load_stale_whitelist_ips(&self) -> Result<Vec<String>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare("SELECT ip FROM whitelist WHERE country = '??'")?;
        let ips = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(ips)
    }
}

// ── Blacklist CRUD ──────────────────────────────────────

impl IpDatabase {
    /// Add IP to blacklist (UPSERT — no duplicates).
    pub fn ban_ip(
        &self,
        ip: &str,
        strikes: u32,
        country: &str,
        asn_org: &str,
        reason: &str,
    ) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO blacklist (ip, strikes, country, asn_org, reason)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(ip) DO UPDATE SET
                strikes = excluded.strikes,
                country = excluded.country,
                asn_org = excluded.asn_org,
                reason  = excluded.reason",
            params![ip, strikes, country, asn_org, reason],
        )?;
        Ok(())
    }

    pub fn unban_ip(&self, ip: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute("DELETE FROM blacklist WHERE ip = ?1", params![ip])?;
        Ok(())
    }

    pub fn load_banned_ips(&self) -> Result<Vec<IpAddr>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare("SELECT ip FROM blacklist")?;
        let ips = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();
        Ok(ips)
    }

    pub fn load_blacklist_records(&self) -> Result<Vec<BlacklistRecord>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare("SELECT ip, strikes, country, asn_org, reason, created_at FROM blacklist")?;
        let records = stmt
            .query_map([], |row| {
                Ok(BlacklistRecord {
                    ip: row.get(0)?,
                    strikes: row.get(1)?,
                    country: row.get(2)?,
                    asn_org: row.get(3)?,
                    reason: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(records)
    }

    /// Count banned IPs.
    pub fn blacklist_count(&self) -> usize {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return 0,
        };
        conn.query_row("SELECT COUNT(*) FROM blacklist", [], |row| {
            row.get::<_, usize>(0)
        })
        .unwrap_or(0)
    }
}

// ── Migration ───────────────────────────────────────────

impl IpDatabase {
    /// Migrate IPs from legacy flat files into the database.
    pub fn migrate_ips_from_files(&self) -> Result<usize> {
        let mut migrated = 0;

        if let Ok(data) = std::fs::read_to_string("whitelist_ips.txt") {
            for line in data.lines() {
                let ip_str = line.trim();
                if !ip_str.is_empty() && ip_str.parse::<IpAddr>().is_ok() {
                    if self.whitelist_ip(ip_str, "??", "Unknown").is_ok() {
                        migrated += 1;
                    }
                }
            }
        }

        if let Ok(data) = std::fs::read_to_string("banned_ips.txt") {
            for line in data.lines() {
                let ip_str = line.split("] ").nth(1).unwrap_or(line).trim();
                if !ip_str.is_empty() && ip_str.parse::<IpAddr>().is_ok() {
                    if self
                        .ban_ip(ip_str, 0, "??", "Unknown", "migrated from file")
                        .is_ok()
                    {
                        migrated += 1;
                    }
                }
            }
        }

        if migrated > 0 {
            info!(count = migrated, "Migrated IPs from legacy files to SQLite");
            let _ = std::fs::rename("whitelist_ips.txt", "whitelist_ips.txt.bak");
            let _ = std::fs::rename("banned_ips.txt", "banned_ips.txt.bak");
        }

        Ok(migrated)
    }
}
