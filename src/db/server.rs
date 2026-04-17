use super::IpDatabase;
use crate::config::{Mapping, ServerConfig};
use anyhow::Result;
use rusqlite::params;
use tracing::info;

// ── Types ───────────────────────────────────────────────

/// Server info for display purposes.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub id: i64,
    pub name: String,
    pub target_ip: String,
    pub enabled: bool,
    pub created_at: String,
    pub mapping_count: usize,
}

// ── CRUD ────────────────────────────────────────────────

impl IpDatabase {
    pub fn add_server(
        &self,
        name: &str,
        target_ip: &str,
        allowed_countries: &[String],
        mappings: &[Mapping],
    ) -> Result<i64> {
        let conn = self.lock_conn()?;

        conn.execute(
            "INSERT INTO servers (name, target_ip) VALUES (?1, ?2)",
            params![name, target_ip],
        )?;
        let server_id = conn.last_insert_rowid();

        for country in allowed_countries {
            conn.execute(
                "INSERT OR IGNORE INTO server_allowed_countries (server_id, country_code) VALUES (?1, ?2)",
                params![server_id, country],
            )?;
        }

        for m in mappings {
            conn.execute(
                "INSERT INTO mappings (server_id, name, listen_addr, target_port) VALUES (?1, ?2, ?3, ?4)",
                params![server_id, m.name, m.listen_addr, m.target_port],
            )?;
        }

        info!(id = server_id, name, target_ip, "Added server to DB");
        Ok(server_id)
    }
    pub fn remove_server(&self, server_id: i64) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute("DELETE FROM servers WHERE id = ?1", params![server_id])?;
        info!(id = server_id, "Removed server from DB");
        Ok(())
    }

    pub fn set_server_enabled(&self, server_id: i64, enabled: bool) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE servers SET enabled = ?1 WHERE id = ?2",
            params![enabled as i32, server_id],
        )?;
        Ok(())
    }

    pub fn load_servers(&self) -> Result<Vec<ServerConfig>> {
        let conn = self.lock_conn()?;

        let mut server_stmt =
            conn.prepare("SELECT id, name, target_ip FROM servers WHERE enabled = 1")?;

        let server_rows: Vec<(i64, String, String)> = server_stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .filter_map(|r| r.ok())
            .collect();

        let mut servers = Vec::new();
        for (id, _name, target_ip) in server_rows {
            // Allowed countries
            let mut country_stmt = conn.prepare(
                "SELECT country_code FROM server_allowed_countries WHERE server_id = ?1",
            )?;
            let countries: Vec<String> = country_stmt
                .query_map(params![id], |row| row.get(0))?
                .filter_map(|r| r.ok())
                .collect();

            // Port mappings
            let mut mapping_stmt = conn.prepare(
                "SELECT name, listen_addr, target_port FROM mappings WHERE server_id = ?1",
            )?;
            let mappings: Vec<Mapping> = mapping_stmt
                .query_map(params![id], |row| {
                    Ok(Mapping {
                        name: row.get(0)?,
                        listen_addr: row.get(1)?,
                        target_port: row.get(2)?,
                    })
                })?
                .filter_map(|r| r.ok())
                .collect();

            servers.push(ServerConfig {
                target_ip,
                allowed_countries: if countries.is_empty() {
                    None
                } else {
                    Some(countries)
                },
                mappings,
            });
        }

        Ok(servers)
    }

    /// List all servers (including disabled) for display/menu.
    pub fn list_all_servers(&self) -> Result<Vec<ServerInfo>> {
        let conn = self.lock_conn()?;

        let mut stmt = conn.prepare(
            "SELECT s.id, s.name, s.target_ip, s.enabled, s.created_at,
                    (SELECT COUNT(*) FROM mappings WHERE server_id = s.id) as mapping_count
             FROM servers s ORDER BY s.id",
        )?;

        let servers = stmt
            .query_map([], |row| {
                Ok(ServerInfo {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    target_ip: row.get(2)?,
                    enabled: row.get::<_, i32>(3)? != 0,
                    created_at: row.get(4)?,
                    mapping_count: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(servers)
    }

    /// Check if servers table has any records.
    pub fn has_servers(&self) -> bool {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return false,
        };
        conn.query_row("SELECT COUNT(*) FROM servers", [], |row| {
            row.get::<_, usize>(0)
        })
        .unwrap_or(0)
            > 0
    }

    /// Migrate servers from config.json into the database.
    pub fn migrate_servers_from_config(&self, servers: &[ServerConfig]) -> Result<usize> {
        let mut count = 0;
        for (i, srv) in servers.iter().enumerate() {
            let name = format!("Server {}", i + 1);
            let countries = srv.allowed_countries.as_deref().unwrap_or(&[]);
            self.add_server(&name, &srv.target_ip, countries, &srv.mappings)?;
            count += 1;
        }
        if count > 0 {
            info!(count, "Migrated servers from config.json to SQLite");
        }
        Ok(count)
    }
}
