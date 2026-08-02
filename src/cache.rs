use crate::coord::Coord;
use crate::finding::Finding;
use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Local observation store. Hits never expire — they are historical
/// observations, the evidence the walk and future derived artifacts are
/// rebuilt from (DESIGN.md layer 1). Misses expire quickly so new
/// upstream data becomes visible; refresh replaces a hit's row but the
/// fact was true when observed.
const MISS_TTL_SECS: u64 = 3 * 24 * 3600;

pub struct Cache {
    conn: Connection,
}

/// Freshness verdict for one (backend, coordinate): should resolve
/// re-ask the network? The findings themselves are read back through
/// `findings_for` (the walk), not through this.
pub enum Cached {
    Hit,
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
            );
            CREATE TABLE IF NOT EXISTS observation_coords (
                scheme     TEXT NOT NULL,
                digest     BLOB NOT NULL,
                backend    TEXT NOT NULL,
                coordinate TEXT NOT NULL,
                PRIMARY KEY (scheme, digest, backend, coordinate)
            ) WITHOUT ROWID;",
        )?;
        let cache = Cache { conn };
        cache.backfill_coords()?;
        Ok(cache)
    }

    /// One-time migration: index the co-observed coordinates of hits
    /// stored before observation_coords existed.
    fn backfill_coords(&self) -> Result<()> {
        let empty: bool = self.conn.query_row(
            "SELECT NOT EXISTS (SELECT 1 FROM observation_coords)
             AND EXISTS (SELECT 1 FROM observations WHERE hit = 1)",
            [],
            |r| r.get(0),
        )?;
        if !empty {
            return Ok(());
        }
        let rows: Vec<(String, String, String)> = {
            let mut stmt = self.conn.prepare(
                "SELECT backend, coordinate, finding FROM observations
                 WHERE hit = 1 AND finding IS NOT NULL",
            )?;
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            mapped.collect::<std::result::Result<_, _>>()?
        };
        for (backend, coordinate, json) in rows {
            if let Ok(finding) = serde_json::from_str::<Finding>(&json) {
                self.index_coords(&backend, &coordinate, &finding);
            }
        }
        Ok(())
    }

    /// Register every coordinate a finding co-observes (plus the queried
    /// one) so the walk can reach this observation from any of them.
    fn index_coords(&self, backend: &str, coordinate: &str, finding: &Finding) {
        let mut coords: Vec<Coord> = finding
            .coords
            .iter()
            .filter_map(|c| Coord::parse(c).ok())
            .collect();
        if let Ok(c) = Coord::parse(coordinate) {
            coords.push(c);
        }
        for c in coords {
            let _ = self.conn.execute(
                "INSERT OR IGNORE INTO observation_coords
                 (scheme, digest, backend, coordinate) VALUES (?1, ?2, ?3, ?4)",
                params![c.scheme.as_str(), c.digest, backend, coordinate],
            );
        }
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
        if hit != 0 {
            if finding.is_some() {
                Cached::Hit
            } else {
                Cached::Absent
            }
        } else if now().saturating_sub(fetched_at) > MISS_TTL_SECS {
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
        if let Some(finding) = finding {
            self.index_coords(backend, &coord.to_string(), finding);
        }
    }

    /// Every cached finding that co-observed this digest — reachable via
    /// any of its coordinates, not just the one originally queried.
    pub fn findings_for(&self, coord: &Coord) -> Vec<Finding> {
        let Ok(mut stmt) = self.conn.prepare(
            "SELECT DISTINCT o.finding FROM observation_coords oc
             JOIN observations o
               ON o.backend = oc.backend AND o.coordinate = oc.coordinate
             WHERE oc.scheme = ?1 AND oc.digest = ?2
               AND o.hit = 1 AND o.finding IS NOT NULL",
        ) else {
            return Vec::new();
        };
        let rows = stmt.query_map(params![coord.scheme.as_str(), coord.digest], |r| {
            r.get::<_, String>(0)
        });
        match rows {
            Ok(rows) => rows
                .flatten()
                .filter_map(|json| serde_json::from_str(&json).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
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
