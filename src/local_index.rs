use anyhow::Result;
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::Path;

/// Bump when the member-row shape changes — or when the walker learns
/// a new container format, so descents cached before it knew (the
/// container closed as an opaque file) don't replay stale trees
/// forever. Rows from other versions are invisible (never replayed,
/// overwritten on the next descent). 2: erofs descent added. 3: FAT
/// filesystems, and the El Torito boot images an iso keeps outside its
/// directory tree. 4: cpio archives continue past their trailer, so an
/// initramfs' compressed body is a member instead of invisible bytes.
const CONTAINER_SCHEMA: i64 = 4;

/// One cached member of a descended container, keyed by the
/// container's sha256 — content-addressed, so it NEVER invalidates: a
/// renamed or copied container replays for free, and a changed one
/// simply has a different key. Structure and digests are cached;
/// bloom matches and verdicts are recomputed at scan time (filters
/// and datasets change — knowledge is query-time policy).
pub struct CachedMember {
    /// Path within the container ("payload!usr/bin/hello").
    pub rel: String,
    /// Parent member's idx within this container; None = direct child
    /// of the container itself.
    pub parent: Option<usize>,
    pub ord: usize,
    /// Tree depth below the container (direct children = 1).
    pub depth: usize,
    pub kind: String,
    pub size: u64,
    pub children: usize,
    pub note: Option<String>,
    pub md5: Option<[u8; 16]>,
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
    pub sha512: Option<[u8; 64]>,
    pub blake2s: Option<[u8; 32]>,
    pub sha1_git: Option<[u8; 20]>,
}

/// The container's own row in the done-marker table.
pub struct CachedContainer {
    pub kind: String,
    pub children: usize,
    pub note: Option<String>,
}

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
            CREATE INDEX IF NOT EXISTS local_files_sha256 ON local_files(sha256);
            CREATE TABLE IF NOT EXISTS container_members (
                csha256  BLOB NOT NULL,
                descent  INTEGER NOT NULL,
                idx      INTEGER NOT NULL,
                parent   INTEGER,
                ord      INTEGER NOT NULL,
                depth    INTEGER NOT NULL,
                rel      TEXT NOT NULL,
                kind     TEXT NOT NULL,
                size     INTEGER NOT NULL,
                children INTEGER NOT NULL,
                note     TEXT,
                md5      BLOB,
                sha1     BLOB NOT NULL,
                sha256   BLOB NOT NULL,
                sha512   BLOB,
                blake2s  BLOB,
                sha1_git BLOB,
                PRIMARY KEY (csha256, descent, idx)
            );
            CREATE TABLE IF NOT EXISTS container_done (
                csha256  BLOB NOT NULL,
                descent  INTEGER NOT NULL,
                members  INTEGER NOT NULL,
                kind     TEXT NOT NULL,
                children INTEGER NOT NULL,
                note     TEXT,
                schema_version INTEGER NOT NULL,
                PRIMARY KEY (csha256, descent)
            );",
        )?;
        // Scan roots canonicalize before indexing now; rows recorded
        // under relative spellings by older builds are unreachable
        // (never matched, never aged out) and only bloat locate.
        // Announce BEFORE the slow parts: the delete walks the whole
        // table and the vacuum rewrites the file.
        let orphaned: i64 = conn.query_row(
            "SELECT COUNT(*) FROM local_files WHERE path NOT LIKE '/%'",
            [],
            |r| r.get(0),
        )?;
        if orphaned > 0 {
            eprintln!("local index: purging {orphaned} relative-path entries (one-time)…");
            conn.execute("DELETE FROM local_files WHERE path NOT LIKE '/%'", [])?;
            eprintln!("local index: compacting…");
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

    /// Read-only handle for worker threads (replay lookups run inside
    /// the scan while the main connection keeps flushing fresh
    /// hashes; WAL makes the two safe together).
    pub fn open_read() -> Result<LocalIndex> {
        let conn = Connection::open_with_flags(
            db_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        Ok(LocalIndex { conn })
    }

    /// A complete cached descent of the container with this sha256
    /// under this policy, or None. Members come back in idx order
    /// (DFS — parents before children).
    pub fn load_container(
        &self,
        csha256: &[u8; 32],
        descent: i64,
    ) -> Result<Option<(CachedContainer, Vec<CachedMember>)>> {
        let done: Option<(i64, CachedContainer)> = self
            .conn
            .query_row(
                "SELECT members, kind, children, note FROM container_done
                 WHERE csha256 = ?1 AND descent = ?2 AND schema_version = ?3",
                rusqlite::params![&csha256[..], descent, CONTAINER_SCHEMA],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        CachedContainer {
                            kind: r.get(1)?,
                            children: r.get::<_, i64>(2)? as usize,
                            note: r.get(3)?,
                        },
                    ))
                },
            )
            .map(Some)
            .unwrap_or_else(|_| None);
        let Some((count, container)) = done else {
            return Ok(None);
        };
        let mut stmt = self.conn.prepare(
            "SELECT parent, ord, depth, rel, kind, size, children, note,
                    md5, sha1, sha256, sha512, blake2s, sha1_git
             FROM container_members
             WHERE csha256 = ?1 AND descent = ?2 ORDER BY idx",
        )?;
        let rows = stmt.query_map(rusqlite::params![&csha256[..], descent], |r| {
            Ok(CachedMember {
                parent: r.get::<_, Option<i64>>(0)?.map(|p| p as usize),
                ord: r.get::<_, i64>(1)? as usize,
                depth: r.get::<_, i64>(2)? as usize,
                rel: r.get(3)?,
                kind: r.get(4)?,
                size: r.get::<_, i64>(5)? as u64,
                children: r.get::<_, i64>(6)? as usize,
                note: r.get(7)?,
                md5: opt_digest(r.get::<_, Option<Vec<u8>>>(8)?),
                sha1: digest(r.get::<_, Vec<u8>>(9)?).unwrap_or([0; 20]),
                sha256: digest(r.get::<_, Vec<u8>>(10)?).unwrap_or([0; 32]),
                sha512: opt_digest(r.get::<_, Option<Vec<u8>>>(11)?),
                blake2s: opt_digest(r.get::<_, Option<Vec<u8>>>(12)?),
                sha1_git: opt_digest(r.get::<_, Option<Vec<u8>>>(13)?),
            })
        })?;
        let members: Vec<CachedMember> = rows.collect::<std::result::Result<_, _>>()?;
        if members.len() as i64 != count {
            // A torn write (or manual surgery): treat as absent.
            return Ok(None);
        }
        Ok(Some((container, members)))
    }

    /// Whether a complete cached descent exists (done-marker only —
    /// the cheap pre-store check).
    pub fn has_container(&self, csha256: &[u8; 32], descent: i64) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM container_done
                 WHERE csha256 = ?1 AND descent = ?2 AND schema_version = ?3",
                rusqlite::params![&csha256[..], descent, CONTAINER_SCHEMA],
                |_| Ok(()),
            )
            .is_ok()
    }

    /// Store one container's complete descent. Idempotent: the same
    /// content always produces the same rows, so replacement is
    /// harmless.
    pub fn store_container(
        &mut self,
        csha256: &[u8; 32],
        descent: i64,
        container: &CachedContainer,
        members: &[CachedMember],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            tx.execute(
                "DELETE FROM container_members WHERE csha256 = ?1 AND descent = ?2",
                rusqlite::params![&csha256[..], descent],
            )?;
            let mut ins = tx.prepare(
                "INSERT INTO container_members
                 (csha256, descent, idx, parent, ord, depth, rel, kind, size, children, note,
                  md5, sha1, sha256, sha512, blake2s, sha1_git)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            )?;
            for (idx, m) in members.iter().enumerate() {
                ins.execute(rusqlite::params![
                    &csha256[..],
                    descent,
                    idx as i64,
                    m.parent.map(|p| p as i64),
                    m.ord as i64,
                    m.depth as i64,
                    m.rel,
                    m.kind,
                    m.size as i64,
                    m.children as i64,
                    m.note,
                    m.md5.as_ref().map(|d| &d[..]),
                    &m.sha1[..],
                    &m.sha256[..],
                    m.sha512.as_ref().map(|d| &d[..]),
                    m.blake2s.as_ref().map(|d| &d[..]),
                    m.sha1_git.as_ref().map(|d| &d[..]),
                ])?;
            }
            tx.execute(
                "INSERT OR REPLACE INTO container_done
                 (csha256, descent, members, kind, children, note, schema_version)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![
                    &csha256[..],
                    descent,
                    members.len() as i64,
                    container.kind,
                    container.children as i64,
                    container.note,
                    CONTAINER_SCHEMA
                ],
            )?;
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

fn digest<const N: usize>(v: Vec<u8>) -> Option<[u8; N]> {
    v.try_into().ok()
}

fn opt_digest<const N: usize>(v: Option<Vec<u8>>) -> Option<[u8; N]> {
    v.and_then(|v| v.try_into().ok())
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
