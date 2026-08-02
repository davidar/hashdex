use crate::coord::Coord;
use crate::finding::Finding;
use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Local observation cache. Hits are kept long (they are historical
/// observations — the seed of the ledger); misses expire quickly so new
/// upstream data becomes visible.
const HIT_TTL_SECS: u64 = 30 * 24 * 3600;
const MISS_TTL_SECS: u64 = 3 * 24 * 3600;

pub struct Cache {
    conn: Connection,
}

pub enum Cached {
    Hit(Finding),
    Miss,
    Absent,
}

impl Cache {
    pub fn open() -> Result<Cache> {
        let dir = cache_dir();
        std::fs::create_dir_all(&dir)?;
        let conn = Connection::open(dir.join("cache.db"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS observations (
                backend    TEXT NOT NULL,
                coordinate TEXT NOT NULL,
                hit        INTEGER NOT NULL,
                finding    TEXT,
                fetched_at INTEGER NOT NULL,
                PRIMARY KEY (backend, coordinate)
            );",
        )?;
        Ok(Cache { conn })
    }

    pub fn get(&self, backend: &str, coord: &Coord) -> Cached {
        let row: Option<(i64, Option<String>, u64)> = self
            .conn
            .query_row(
                "SELECT hit, finding, fetched_at FROM observations
                 WHERE backend = ?1 AND coordinate = ?2",
                params![backend, coord.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok();
        let Some((hit, finding, fetched_at)) = row else {
            return Cached::Absent;
        };
        let age = now().saturating_sub(fetched_at);
        if hit != 0 {
            if age > HIT_TTL_SECS {
                return Cached::Absent;
            }
            match finding.and_then(|f| serde_json::from_str(&f).ok()) {
                Some(f) => Cached::Hit(f),
                None => Cached::Absent,
            }
        } else if age > MISS_TTL_SECS {
            Cached::Absent
        } else {
            Cached::Miss
        }
    }

    pub fn put(&self, backend: &str, coord: &Coord, finding: Option<&Finding>) {
        let json = finding.and_then(|f| serde_json::to_string(f).ok());
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO observations
             (backend, coordinate, hit, finding, fetched_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                backend,
                coord.to_string(),
                finding.is_some() as i64,
                json,
                now()
            ],
        );
    }
}

fn cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("hashdex")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
