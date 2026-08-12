//! peek's minting pool. The walker thread only parses formats and
//! streams bytes; everything CPU-heavy — the six digest hashers and
//! the bloom probes — runs on a worker pool. Each member gets one
//! hash job per scheme (so even a single huge file hashes six-wide),
//! chunks are Arc-shared across the member's jobs, and a global byte
//! budget keeps the amount of un-hashed data in flight bounded.
//!
//! Members backed by a seekable source (a `View`) don't even cost the
//! walker their read: a read task on the same pool streams the
//! extents into the hash jobs while the walker descends.

use crate::coord::{Coord, Scheme};
use crate::filter::NamedFilter;
use crate::peek_source::View;
use crate::scan_cmd::{hex_lower, hex_upper, Ticker, EXPENSIVE_FILTER_BYTES, IDENTITY_MIN_BYTES};
use sha2::Digest as _;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// Chunk accumulation size for stream feeds (tar readers hand us
/// 512-byte blocks; hashing wants bigger batches).
const CHUNK: usize = 256 << 10;
/// Un-hashed bytes allowed in flight before feeders block. Chunks
/// shared by a member's six jobs are charged once per job, so the
/// real buffered bytes stay well under this.
const BUDGET: i64 = 512 << 20;

/// All six coordinates of one member, inline — a Vec<Coord> per
/// member costs seven allocations and half a million members is real
/// memory.
pub struct Digests {
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
    pub sha512: [u8; 64],
    pub blake2s: [u8; 32],
    pub sha1_git: Option<[u8; 20]>,
}

impl Digests {
    pub fn coords(&self) -> Vec<Coord> {
        let mut coords = vec![
            Coord {
                scheme: Scheme::Md5,
                digest: self.md5.to_vec(),
            },
            Coord {
                scheme: Scheme::Sha1,
                digest: self.sha1.to_vec(),
            },
            Coord {
                scheme: Scheme::Sha256,
                digest: self.sha256.to_vec(),
            },
            Coord {
                scheme: Scheme::Sha512,
                digest: self.sha512.to_vec(),
            },
            Coord {
                scheme: Scheme::Blake2s256,
                digest: self.blake2s.to_vec(),
            },
        ];
        if let Some(g) = self.sha1_git {
            coords.push(Coord {
                scheme: Scheme::Sha1Git,
                digest: g.to_vec(),
            });
        }
        coords
    }
}

pub struct Member {
    pub path: String,
    pub depth: usize,
    /// Slot of the enclosing member (None for a root). Rollups walk
    /// these chains and rendering rebuilds the tree from them, so
    /// nothing downstream depends on the slot order of the member
    /// table.
    pub parent: Option<usize>,
    pub kind: &'static str,
    pub size: u64,
    pub digests: Digests,
    pub matched: Vec<String>,
    pub children: usize,
    pub note: Option<String>,
}

// ---------------------------------------------------------------- jobs

/// One digest scheme's running state. sha1_git carries the
/// length-prefixed header, so it only exists when the enclosing
/// format stated the member's length.
enum HState {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
    Blake2s(blake2::Blake2s256),
    Sha1Git(sha1::Sha1),
}

impl HState {
    fn update(&mut self, b: &[u8]) {
        match self {
            HState::Md5(h) => h.update(b),
            HState::Sha1(h) | HState::Sha1Git(h) => h.update(b),
            HState::Sha256(h) => h.update(b),
            HState::Sha512(h) => h.update(b),
            HState::Blake2s(h) => h.update(b),
        }
    }

    fn finalize(self, out: &mut Partial) {
        match self {
            HState::Md5(h) => out.md5 = Some(h.finalize().into()),
            HState::Sha1(h) => out.sha1 = Some(h.finalize().into()),
            HState::Sha256(h) => out.sha256 = Some(h.finalize().into()),
            HState::Sha512(h) => out.sha512 = Some(h.finalize().into()),
            HState::Blake2s(h) => out.blake2s = Some(h.finalize().into()),
            HState::Sha1Git(h) => out.sha1_git = Some(h.finalize().into()),
        }
    }
}

#[derive(Default)]
struct Partial {
    md5: Option<[u8; 16]>,
    sha1: Option<[u8; 20]>,
    sha256: Option<[u8; 32]>,
    sha512: Option<[u8; 64]>,
    blake2s: Option<[u8; 32]>,
    sha1_git: Option<[u8; 20]>,
}

struct JobState {
    chunks: VecDeque<Arc<[u8]>>,
    /// Taken out while a worker hashes; `queued` guards exclusivity.
    hasher: Option<HState>,
    closed: bool,
    queued: bool,
}

struct Job {
    state: Mutex<JobState>,
    build: Arc<Build>,
}

/// Assembly point for one member: filled in by its hash jobs (one per
/// scheme) plus the walker's metadata close; the last contributor
/// probes the filters and seals the member into its slot.
struct Build {
    slot: usize,
    size: AtomicU64,
    meta: Mutex<Option<Meta>>,
    parts: Mutex<Partial>,
    remaining: AtomicUsize,
}

struct Meta {
    path: String,
    depth: usize,
    parent: Option<usize>,
    kind: &'static str,
    children: usize,
    note: Option<String>,
}

impl Build {
    fn finish_part(&self, pool: &Pool) {
        if self.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.seal(pool);
        }
    }

    fn add_note(&self, note: String) {
        let mut meta = self.meta.lock().unwrap();
        if let Some(m) = meta.as_mut() {
            m.note = Some(match m.note.take() {
                Some(prev) => format!("{prev}; {note}"),
                None => note,
            });
        }
    }

    fn seal(&self, pool: &Pool) {
        let meta = self.meta.lock().unwrap().take().expect("sealed twice");
        let p = std::mem::take(&mut *self.parts.lock().unwrap());
        let digests = Digests {
            md5: p.md5.expect("md5 part"),
            sha1: p.sha1.expect("sha1 part"),
            sha256: p.sha256.expect("sha256 part"),
            sha512: p.sha512.expect("sha512 part"),
            blake2s: p.blake2s.expect("blake2s part"),
            sha1_git: p.sha1_git,
        };
        let size = self.size.load(Ordering::Acquire);
        // Probe order mirrors scan: cheapest filter first, RAM-dwarfing
        // ones skipped once a smaller filter already matched; sub-floor
        // members never probe.
        let mut matched: Vec<String> = Vec::new();
        if size >= IDENTITY_MIN_BYTES {
            let sha1_hex = hex_upper(&digests.sha1);
            let sha256_hex = hex_lower(&digests.sha256);
            for f in &pool.probe_order {
                if f.bytes >= EXPENSIVE_FILTER_BYTES && !matched.is_empty() {
                    continue;
                }
                let key: &[u8] = match f.scheme {
                    Scheme::Sha1 => sha1_hex.as_bytes(),
                    Scheme::Sha256 => sha256_hex.as_bytes(),
                    _ => continue,
                };
                if f.bloom.check(key) {
                    matched.push(f.name.clone());
                }
            }
            matched.sort();
            matched.dedup();
        }
        let member = Member {
            path: meta.path,
            depth: meta.depth,
            parent: meta.parent,
            kind: meta.kind,
            size,
            digests,
            matched,
            children: meta.children,
            note: meta.note,
        };
        pool.members.lock().unwrap()[self.slot] = Some(member);
        let sealed = pool.sealed.fetch_add(1, Ordering::AcqRel) + 1;
        {
            let _g = pool.idle_m.lock().unwrap();
            pool.idle_cv.notify_all();
        }
        pool.ticker
            .update(64, sealed, || format!("descending… {sealed} members"));
    }
}

// -------------------------------------------------------------- handles

/// The byte-feeding half of a member: owned by the walker for stream
/// members, moved into a pool read task for view-backed ones. Must be
/// closed (Drop closes it un-fed as a safety net so the pool can
/// always drain).
pub(crate) struct Feed {
    jobs: Vec<Arc<Job>>,
    build: Arc<Build>,
    buf: Vec<u8>,
}

impl Feed {
    pub(crate) fn push(&mut self, pool: &Pool, bytes: &[u8]) {
        self.build
            .size
            .fetch_add(bytes.len() as u64, Ordering::AcqRel);
        let mut bytes = bytes;
        while !bytes.is_empty() {
            let room = CHUNK - self.buf.len();
            let take = room.min(bytes.len());
            self.buf.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buf.len() >= CHUNK {
                self.flush(pool);
            }
        }
    }

    fn flush(&mut self, pool: &Pool) {
        if self.buf.is_empty() {
            return;
        }
        let chunk: Arc<[u8]> = std::mem::take(&mut self.buf).into();
        pool.acquire(chunk.len() * self.jobs.len());
        for job in &self.jobs {
            let mut st = job.state.lock().unwrap();
            st.chunks.push_back(chunk.clone());
            if !st.queued {
                st.queued = true;
                drop(st);
                pool.enqueue(Task::Hash(job.clone()));
            }
        }
    }

    pub(crate) fn close(mut self, pool: &Pool) {
        self.flush(pool);
        for job in self.jobs.drain(..) {
            let mut st = job.state.lock().unwrap();
            st.closed = true;
            if !st.queued {
                st.queued = true;
                drop(st);
                pool.enqueue(Task::Hash(job.clone()));
            }
        }
    }
}

/// The metadata half: the walker closes it once it knows how many
/// children the member had and whether the descent left a note.
pub(crate) struct MetaClose {
    build: Arc<Build>,
}

impl MetaClose {
    /// The member's slot — the walker passes it as the parent of
    /// everything it creates while descending this member.
    pub(crate) fn slot(&self) -> usize {
        self.build.slot
    }

    pub(crate) fn close(self, pool: &Pool, children: usize, note: Option<String>) {
        {
            let mut meta = self.build.meta.lock().unwrap();
            let m = meta.as_mut().expect("meta closed twice");
            m.children = children;
        }
        if let Some(n) = note {
            self.build.add_note(n);
        }
        // The dead-member arithmetic (see `discard`) counts a member
        // as sure-to-seal exactly when its meta was closed.
        pool.metas_closed.fetch_add(1, Ordering::AcqRel);
        self.build.finish_part(pool);
    }
}

// ---------------------------------------------------------------- pool

enum Task {
    Hash(Arc<Job>),
    /// Stream a view's extents into the member's hash jobs — the
    /// walker never spends its own time reading view-backed members.
    Read(View, Feed),
}

pub(crate) struct Pool<'f> {
    queue: Mutex<VecDeque<Task>>,
    work_cv: Condvar,
    closed: AtomicBool,
    budget: Mutex<i64>,
    budget_cv: Condvar,
    /// Concurrent read tasks are capped so hash workers always
    /// outnumber them — readers block on the byte budget, hashers
    /// are what free it.
    readers: AtomicUsize,
    max_readers: usize,
    pub(crate) members: Mutex<Vec<Option<Member>>>,
    created: AtomicUsize,
    sealed: AtomicUsize,
    /// Metadata closes, incremented by `MetaClose::close`. A member
    /// whose meta closed always seals eventually (its feed is closed
    /// by the walker or a read task); one whose meta was dropped in
    /// an unwind never will. The walker differences this against
    /// `created` to count the dead exactly.
    metas_closed: AtomicUsize,
    /// Members abandoned by a conservative retry whose handles were
    /// dropped un-closed — they will never seal, and wait_idle must
    /// not hold out for them.
    dead: AtomicUsize,
    idle_m: Mutex<()>,
    idle_cv: Condvar,
    probe_order: Vec<&'f NamedFilter>,
    ticker: &'f Ticker,
}

impl<'f> Pool<'f> {
    pub(crate) fn new(
        probe_order: Vec<&'f NamedFilter>,
        ticker: &'f Ticker,
        threads: usize,
    ) -> Pool<'f> {
        Pool {
            queue: Mutex::new(VecDeque::new()),
            work_cv: Condvar::new(),
            closed: AtomicBool::new(false),
            budget: Mutex::new(0),
            budget_cv: Condvar::new(),
            readers: AtomicUsize::new(0),
            max_readers: (threads / 2).max(1),
            members: Mutex::new(Vec::new()),
            created: AtomicUsize::new(0),
            sealed: AtomicUsize::new(0),
            metas_closed: AtomicUsize::new(0),
            dead: AtomicUsize::new(0),
            idle_m: Mutex::new(()),
            idle_cv: Condvar::new(),
            probe_order,
            ticker,
        }
    }

    /// Reserve the next member slot and set up its hash jobs.
    pub(crate) fn member(
        &self,
        path: String,
        depth: usize,
        parent: Option<usize>,
        kind: &'static str,
        len: Option<u64>,
    ) -> (MetaClose, Feed) {
        let slot = {
            let mut m = self.members.lock().unwrap();
            m.push(None);
            m.len() - 1
        };
        self.created.fetch_add(1, Ordering::AcqRel);
        let mut hashers = vec![
            HState::Md5(md5::Md5::new()),
            HState::Sha1(sha1::Sha1::new()),
            HState::Sha256(sha2::Sha256::new()),
            HState::Sha512(sha2::Sha512::new()),
            HState::Blake2s(blake2::Blake2s256::new()),
        ];
        if let Some(len) = len {
            let mut g = sha1::Sha1::new();
            g.update(format!("blob {len}\0").as_bytes());
            hashers.push(HState::Sha1Git(g));
        }
        let build = Arc::new(Build {
            slot,
            size: AtomicU64::new(0),
            meta: Mutex::new(Some(Meta {
                path,
                depth,
                parent,
                kind,
                children: 0,
                note: None,
            })),
            parts: Mutex::new(Partial::default()),
            // One part per hash job, plus the walker's metadata close.
            remaining: AtomicUsize::new(hashers.len() + 1),
        });
        let jobs = hashers
            .into_iter()
            .map(|h| {
                Arc::new(Job {
                    state: Mutex::new(JobState {
                        chunks: VecDeque::new(),
                        hasher: Some(h),
                        closed: false,
                        queued: false,
                    }),
                    build: build.clone(),
                })
            })
            .collect();
        (
            MetaClose {
                build: build.clone(),
            },
            Feed {
                jobs,
                build,
                buf: Vec::new(),
            },
        )
    }

    /// Hand a view-backed member's bytes to the pool: a worker reads
    /// the extents and feeds the hash jobs.
    pub(crate) fn read_task(&self, view: View, feed: Feed) {
        self.enqueue(Task::Read(view.rewound(), feed));
    }

    fn enqueue(&self, task: Task) {
        self.queue.lock().unwrap().push_back(task);
        self.work_cv.notify_one();
    }

    fn acquire(&self, n: usize) {
        let mut b = self.budget.lock().unwrap();
        // An oversized single chunk is allowed through an empty budget
        // rather than deadlocking on an unreachable ceiling; a closed
        // pool stops enforcing the budget entirely — shutdown must
        // never wait on hashers that may already have exited.
        while *b > 0 && *b + n as i64 > BUDGET && !self.closed.load(Ordering::Acquire) {
            b = self
                .budget_cv
                .wait_timeout(b, std::time::Duration::from_millis(100))
                .unwrap()
                .0;
        }
        *b += n as i64;
    }

    fn release(&self, n: usize) {
        let mut b = self.budget.lock().unwrap();
        *b -= n as i64;
        drop(b);
        self.budget_cv.notify_all();
    }

    pub(crate) fn worker(&self) {
        loop {
            let task = {
                let mut q = self.queue.lock().unwrap();
                loop {
                    // Hash tasks run unconditionally; read tasks only
                    // while under the reader cap.
                    let can_read = self.readers.load(Ordering::Acquire) < self.max_readers;
                    let idx = q.iter().position(|t| match t {
                        Task::Hash(_) => true,
                        Task::Read(..) => can_read,
                    });
                    if let Some(i) = idx {
                        let t = q.remove(i).unwrap();
                        if matches!(t, Task::Read(..)) {
                            self.readers.fetch_add(1, Ordering::AcqRel);
                        }
                        break t;
                    }
                    if self.closed.load(Ordering::Acquire) && q.is_empty() {
                        return;
                    }
                    let (guard, _) = self
                        .work_cv
                        .wait_timeout(q, std::time::Duration::from_millis(100))
                        .unwrap();
                    q = guard;
                    if self.closed.load(Ordering::Acquire) && q.is_empty() {
                        return;
                    }
                }
            };
            match task {
                Task::Hash(job) => self.run_hash(&job),
                Task::Read(view, feed) => {
                    self.run_read(view, feed);
                    self.readers.fetch_sub(1, Ordering::AcqRel);
                    self.work_cv.notify_all();
                }
            }
        }
    }

    fn run_hash(&self, job: &Job) {
        let mut st = job.state.lock().unwrap();
        loop {
            if st.chunks.is_empty() {
                if st.closed {
                    if let Some(h) = st.hasher.take() {
                        st.queued = false;
                        drop(st);
                        h.finalize(&mut job.build.parts.lock().unwrap());
                        job.build.finish_part(self);
                        return;
                    }
                }
                st.queued = false;
                return;
            }
            let chunks: Vec<Arc<[u8]>> = st.chunks.drain(..).collect();
            let mut h = st.hasher.take().expect("hasher present while queued");
            drop(st);
            let mut freed = 0usize;
            for c in &chunks {
                h.update(c);
                freed += c.len();
            }
            self.release(freed);
            st = job.state.lock().unwrap();
            st.hasher = Some(h);
        }
    }

    fn run_read(&self, mut view: View, mut feed: Feed) {
        let mut buf = vec![0u8; 1 << 20];
        loop {
            // An aborted descent (error, conservative retry) closes the
            // pool without waiting; don't finish a multi-GB read whose
            // member is about to be discarded.
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            match std::io::Read::read(&mut view, &mut buf) {
                Ok(0) => break,
                Ok(n) => feed.push(self, &buf[..n]),
                Err(e) => {
                    feed.build.add_note(format!("read failed mid-member: {e}"));
                    break;
                }
            }
        }
        feed.close(self);
    }

    /// Metadata closes so far — captured by the walker before a
    /// subtree so a retry can compute the exact number of abandoned
    /// members afterwards.
    pub(crate) fn metas_closed(&self) -> usize {
        self.metas_closed.load(Ordering::Acquire)
    }

    /// Members that will never seal (their handles were dropped
    /// un-closed in a retry unwind). The count must be EXACT — an
    /// overestimate would let `wait_idle` return while genuine
    /// members' read tasks are still in flight, and closing the pool
    /// cancels reads.
    pub(crate) fn add_dead(&self, n: usize) {
        self.dead.fetch_add(n, Ordering::AcqRel);
        let _g = self.idle_m.lock().unwrap();
        self.idle_cv.notify_all();
    }

    /// Block until every member that still can seal has sealed. Only
    /// call after the descent returned (nothing is being created).
    pub(crate) fn wait_idle(&self) {
        let mut g = self.idle_m.lock().unwrap();
        loop {
            let expected = self.created.load(Ordering::Acquire) - self.dead.load(Ordering::Acquire);
            if self.sealed.load(Ordering::Acquire) >= expected {
                return;
            }
            g = self.idle_cv.wait(g).unwrap();
        }
    }

    /// Let workers exit once the queue drains.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.work_cv.notify_all();
    }
}
