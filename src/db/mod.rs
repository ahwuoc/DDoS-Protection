mod ip;
mod server;

pub use ip::*;
pub use server::*;

use anyhow::Result;
use rusqlite::Connection;
use std::sync::Mutex;
use tracing::info;

const DB_PATH: &str = "firewall.db";

/// Thread-safe SQLite database wrapper.
pub struct IpDatabase {
    pub(crate) conn: Mutex<Connection>,
}

impl IpDatabase {
    /// Open (or create) the SQLite database and initialize all tables.
    pub fn open() -> Result<Self> {
        let conn = Connection::open(DB_PATH)?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = 2000;
             PRAGMA temp_store = MEMORY;
             PRAGMA foreign_keys = ON;",
        )?;

        Self::init_schema(&conn)?;

        info!("SQLite database initialized at {DB_PATH}");
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create all tables if they don't exist.
    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS whitelist (
                ip         TEXT PRIMARY KEY,
                country    TEXT DEFAULT '??',
                asn_org    TEXT DEFAULT 'Unknown',
                reason     TEXT DEFAULT 'auto-whitelisted',
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            );

            CREATE TABLE IF NOT EXISTS blacklist (
                ip         TEXT PRIMARY KEY,
                strikes    INTEGER DEFAULT 0,
                country    TEXT DEFAULT '??',
                asn_org    TEXT DEFAULT 'Unknown',
                reason     TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            );

            CREATE TABLE IF NOT EXISTS servers (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL DEFAULT '',
                target_ip  TEXT NOT NULL,
                enabled    INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            );

            CREATE TABLE IF NOT EXISTS server_allowed_countries (
                server_id    INTEGER NOT NULL,
                country_code TEXT NOT NULL,
                PRIMARY KEY (server_id, country_code),
                FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS mappings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id   INTEGER NOT NULL,
                name        TEXT NOT NULL,
                listen_addr TEXT NOT NULL UNIQUE,
                target_port INTEGER NOT NULL,
                FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
            );",
        )?;

        Ok(())
    }

    /// Helper: lock the DB connection.
    pub(crate) fn lock_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|e| anyhow::anyhow!("DB lock: {e}"))
    }
}
