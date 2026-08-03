use anyhow::Result;
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::Path;

/// Persistent index of local file hashes, updatedb-style: `hdx scan`
/// refreshes it, (size, mtime) staleness-checks it, `hdx locate` queries
/// it. This is user-initiated hashing of the user's own files — the
/// admission-rule exception — and it never leaves the machine.
pub struct LocalIndex {
    conn: Connection,
}

pub struct CachedEntry {
    pub size: u64,
    pub mtime_ns: i64,
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
}

/// A freshly hashed file bound for the index: (path, size, mtime_ns, sha1, sha256).
pub type FreshEntry = (String, u64, i64, [u8; 20], [u8; 32]);

fn db_path() -> std::path::PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("hashdex")
        .join("local.db")
}

impl LocalIndex {
    pub fn open() -> Result<LocalIndex> {
        let path = db_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS local_files (
                path     TEXT PRIMARY KEY,
                size     INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                sha1     BLOB NOT NULL,
                sha256   BLOB NOT NULL,
                scanned_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS local_files_sha1 ON local_files(sha1);
            CREATE INDEX IF NOT EXISTS local_files_sha256 ON local_files(sha256);",
        )?;
        // Scan roots canonicalize before indexing now; rows recorded
        // under relative spellings by older builds are unreachable
        // (never matched, never aged out) and only bloat locate.
        let orphaned = conn.execute("DELETE FROM local_files WHERE path NOT LIKE '/%'", [])?;
        if orphaned > 0 {
            eprintln!("local index: purged {orphaned} relative-path entries; compacting…");
            conn.execute_batch("VACUUM")?;
        }
        Ok(LocalIndex { conn })
    }

    /// Load every cached entry under `root` into memory so scan workers
    /// can consult it without touching sqlite from threads.
    pub fn load_under(&self, root: &Path) -> Result<HashMap<String, CachedEntry>> {
        let mut prefix = root.to_string_lossy().into_owned();
        let mut out = HashMap::new();
        if root.is_file() {
            // exact-path lookup
            let mut stmt = self.conn.prepare(
                "SELECT path, size, mtime_ns, sha1, sha256 FROM local_files WHERE path = ?1",
            )?;
            let mut rows = stmt.query([&prefix])?;
            while let Some(row) = rows.next()? {
                insert_row(&mut out, row)?;
            }
            return Ok(out);
        }
        if !prefix.ends_with('/') {
            prefix.push('/');
        }
        // Range scan on the path PK: [prefix, prefix+0xFF).
        let hi = format!("{prefix}\u{10FFFF}");
        let mut stmt = self.conn.prepare(
            "SELECT path, size, mtime_ns, sha1, sha256 FROM local_files
             WHERE path >= ?1 AND path < ?2",
        )?;
        let mut rows = stmt.query([&prefix, &hi])?;
        while let Some(row) = rows.next()? {
            insert_row(&mut out, row)?;
        }
        Ok(out)
    }

    /// Upsert freshly hashed files and drop entries whose paths were
    /// walked over but no longer exist, all in one transaction.
    pub fn commit_scan(&mut self, fresh: &[FreshEntry], stale_paths: &[String]) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let tx = self.conn.transaction()?;
        {
            let mut up = tx.prepare(
                "INSERT INTO local_files (path, size, mtime_ns, sha1, sha256, scanned_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(path) DO UPDATE SET
                    size = excluded.size, mtime_ns = excluded.mtime_ns,
                    sha1 = excluded.sha1, sha256 = excluded.sha256,
                    scanned_at = excluded.scanned_at",
            )?;
            for (path, size, mtime_ns, sha1, sha256) in fresh {
                up.execute(rusqlite::params![
                    path,
                    *size as i64,
                    mtime_ns,
                    &sha1[..],
                    &sha256[..],
                    now
                ])?;
            }
            let mut del = tx.prepare("DELETE FROM local_files WHERE path = ?1")?;
            for path in stale_paths {
                del.execute([path])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// All indexed paths whose sha1 or sha256 equals `digest`.
    pub fn locate(&self, digest: &[u8]) -> Result<Vec<(String, u64)>> {
        let col = match digest.len() {
            20 => "sha1",
            32 => "sha256",
            n => anyhow::bail!("locate: need a sha1 or sha256 digest, got {n} bytes"),
        };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT path, size FROM local_files WHERE {col} = ?1"
        ))?;
        let rows = stmt.query_map([digest], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn stats(&self) -> Result<(u64, u64)> {
        let (n, bytes): (i64, Option<i64>) =
            self.conn
                .query_row("SELECT COUNT(*), SUM(size) FROM local_files", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
        Ok((n as u64, bytes.unwrap_or(0) as u64))
    }
}

fn insert_row(out: &mut HashMap<String, CachedEntry>, row: &rusqlite::Row) -> Result<()> {
    let path: String = row.get(0)?;
    let size: i64 = row.get(1)?;
    let mtime_ns: i64 = row.get(2)?;
    let sha1: Vec<u8> = row.get(3)?;
    let sha256: Vec<u8> = row.get(4)?;
    if let (Ok(sha1), Ok(sha256)) = (sha1.try_into(), sha256.try_into()) {
        out.insert(
            path,
            CachedEntry {
                size: size as u64,
                mtime_ns,
                sha1,
                sha256,
            },
        );
    }
    Ok(())
}
