//! Hand-rolled erofs reader for the hashoscope. Parses the on-disk
//! format directly (superblock @1024, compact/extended inodes,
//! dirents, z-compression maps) because no maintained Rust crate
//! reads erofs. The layout mirrors the kernel's fs/erofs/erofs_fs.h
//! and erofs-utils' lib/zmap.c + lib/decompress.c semantics — where
//! this file looks odd (the compacted-index bit math, the
//! leading-zero input margin, the fixed-output MicroLZMA calls),
//! it is deliberately transliterated from those references.
//!
//! Compressed data comes in per-file pclusters (LZ4 / MicroLZMA /
//! DEFLATE / zstd, plus raw "plain" ones), and images built with
//! `-Eall-fragments` (Fedora live media) put every file's data in one
//! shared z-mapped "packed inode" instead — files then carry only an
//! offset into that stream, so a small LRU of decompressed packed
//! pclusters serves many files each.

use crate::peek_source::View;
use anyhow::{bail, ensure, Context, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

const EROFS_SUPER_OFFSET: u64 = 1024;
const EROFS_MAGIC: u32 = 0xE0F5_E1E2;

// feature_incompat bits (erofs_fs.h)
const FEAT_48BIT: u32 = 0x80;
const FEAT_METABOX: u32 = 0x100;
const FEAT_KNOWN: u32 = 0x1ff;

// z_erofs_map_header h_advise bits
const ADV_COMPACTED_2B: u16 = 0x0001;
const ADV_EXTENTS: u16 = 0x0001; // FULL-layout meaning of the same bit
const ADV_BIG_PCLUSTER_1: u16 = 0x0002;
const ADV_BIG_PCLUSTER_2: u16 = 0x0004;
const ADV_INLINE_PCLUSTER: u16 = 0x0008;
const ADV_INTERLACED: u16 = 0x0010;
const ADV_FRAGMENT: u16 = 0x0020;

// lcluster types
const LCL_PLAIN: u8 = 0;
const LCL_HEAD1: u8 = 1;
const LCL_NONHEAD: u8 = 2;
const LCL_HEAD2: u8 = 3;

/// First-NONHEAD delta[0] flag: the value is the pcluster's
/// compressed block count, not a distance.
const CBLKCNT: u32 = 1 << 11;

/// Format bounds: a pcluster never stores more than this many bytes,
/// nor spans more than this many logical ones.
pub(crate) const PCLUSTER_MAX_SIZE: u64 = 1 << 20;
pub(crate) const PCLUSTER_MAX_DSIZE: u64 = 12 << 20;
const LZMA_MAX_DICT: u32 = 8 << 20;

/// feature_incompat bit that says `available_compr_algs` is a bitmap
/// (rather than an lz4 max distance) and per-algorithm configuration
/// blocks follow the superblock.
const FEAT_COMPR_CFGS: u32 = 0x2;
/// Bit position of MicroLZMA in `available_compr_algs`.
const ALG_LZMA: u32 = 1;
/// Size of `struct erofs_super_block` — where the compression
/// configuration blocks begin.
const SUPER_SIZE: u64 = 128;

/// Decompressed packed-inode pclusters kept around: files packed as
/// fragments share pclusters with their neighbors, and the walker
/// visits them in packed order, so a modest cache turns the packed
/// stream into one sequential decompression pass.
const PACKED_CACHE_BYTES: usize = 64 << 20;

const DIR_MAX_BYTES: u64 = 64 << 20;
const DIR_MAX_DEPTH: usize = 64;

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn align8(n: u64) -> u64 {
    n.next_multiple_of(8)
}

fn read_exact_at(view: &View, buf: &mut [u8], off: u64) -> Result<()> {
    ensure!(
        view.read_full_at(buf, off)? == buf.len(),
        "truncated read of {} bytes at offset {off}",
        buf.len()
    );
    Ok(())
}

// -------------------------------------------------------------- image

pub(crate) struct Erofs {
    view: View,
    blkszbits: u32,
    meta_base: u64,
    root_nid: u64,
    packed_nid: u64,
    /// `available_compr_algs` bitmap, and whether the superblock says
    /// to read it as one (old images overload the field).
    compr_algs: u16,
    compr_cfgs: bool,
    packed: Mutex<Option<Arc<ZPlan>>>,
    cache: Mutex<PackedCache>,
}

#[derive(Default)]
struct PackedCache {
    map: HashMap<u64, Arc<Vec<u8>>>,
    order: VecDeque<u64>,
    bytes: usize,
}

pub(crate) struct Inode {
    base: u64,
    isize: u64,
    xattr: u64,
    pub(crate) mode: u16,
    pub(crate) size: u64,
    layout: u8,
    u: u32,
}

impl Inode {
    /// End of the on-disk inode incl. inline xattrs — inline data, the
    /// z map header, and chunk tables all start (aligned) from here.
    fn end(&self) -> u64 {
        self.base + self.isize + self.xattr
    }
}

/// How a file's bytes are reachable. `Ranged` extents are plain byte
/// ranges of the image (flat and chunk-based inodes) — the walker
/// turns them into views, which keeps them splice-able for recipes.
/// Everything behind compression streams through a [`ZReader`].
pub(crate) enum Plan {
    Ranged(Vec<(u64, u64)>),
    Streamed(ZPlan),
}

impl Plan {
    /// The offset in the packed inode's stream where ALL of this
    /// file's bytes live, when they live there contiguously — the
    /// `-Eall-fragments` shape (Fedora live media). Files with
    /// pclusters of their own, or with only a packed tail, return
    /// None: recipes can only attribute a fragment span to a member
    /// when the member IS that span.
    pub(crate) fn packed_whole(&self) -> Option<u64> {
        let Plan::Streamed(zp) = self else {
            return None;
        };
        match &zp.exts[..] {
            [ZExt {
                la: 0,
                llen,
                src: ZSrc::Packed { off },
            }] if *llen == zp.size => Some(*off),
            _ => None,
        }
    }
}

/// One stored pcluster of the packed inode: `plen` bytes at image
/// offset `pa` decode to the `llen` bytes at `la` of the packed
/// stream. `lzma` marks the ones a `microlzma@0` node can rebuild.
pub(crate) struct PCluster {
    pub(crate) la: u64,
    pub(crate) llen: u64,
    pub(crate) pa: u64,
    pub(crate) plen: u64,
    pub(crate) lzma: bool,
    alg: Alg,
    partial: bool,
}

/// What mkfs recorded about the image's MicroLZMA compressor. The
/// dictionary size is read, never assumed: it is an encoder input, and
/// a wrong one produces different bytes.
pub(crate) struct LzmaCfg {
    pub(crate) dict_size: u32,
    pub(crate) format: u16,
}

pub(crate) struct ZPlan {
    size: u64,
    exts: Vec<ZExt>,
}

struct ZExt {
    la: u64,
    llen: u64,
    src: ZSrc,
}

enum ZSrc {
    /// A pcluster of this inode: decode `plen` bytes at `pa`.
    Raw {
        pa: u64,
        plen: u64,
        alg: Alg,
        partial: bool,
    },
    /// Bytes `[off, off+llen)` of the packed inode's stream.
    Packed { off: u64 },
    /// A hole — reads as zeros.
    Zero,
}

#[derive(Clone, Copy)]
enum Alg {
    /// Stored raw; logical bytes are the pcluster bytes verbatim.
    Shifted,
    /// Stored raw but rotated: the data begins `skip` bytes in and
    /// wraps around to the front (in-place decompression aid).
    Interlaced {
        skip: u32,
    },
    Lz4,
    Lzma,
    Deflate,
    Zstd,
}

/// One regular file found by the directory walk, with its data plan
/// resolved. `order` sorts the streamed files so packed-inode reads
/// run front to back (files sharing a pcluster land adjacent).
pub(crate) struct FileItem {
    pub(crate) path: String,
    pub(crate) leaf: String,
    pub(crate) size: u64,
    pub(crate) plan: Plan,
    pub(crate) order: (u8, u64),
}

impl Erofs {
    pub(crate) fn open(view: View) -> Result<Erofs> {
        let mut sb = [0u8; 128];
        read_exact_at(&view, &mut sb, EROFS_SUPER_OFFSET).context("erofs superblock")?;
        ensure!(le32(&sb, 0) == EROFS_MAGIC, "not an erofs image");
        let blkszbits = sb[12] as u32;
        ensure!(
            (9..=16).contains(&blkszbits),
            "implausible erofs block size"
        );
        let incompat = le32(&sb, 80);
        ensure!(
            incompat & !FEAT_KNOWN == 0,
            "unknown erofs incompat features {:#x}",
            incompat & !FEAT_KNOWN
        );
        ensure!(
            incompat & (FEAT_48BIT | FEAT_METABOX) == 0,
            "unsupported erofs feature (48-bit or metabox)"
        );
        ensure!(le16(&sb, 86) == 0, "multi-device erofs is not supported");
        let dirblkbits = sb[90] as u32;
        ensure!(
            dirblkbits == 0 || dirblkbits == blkszbits,
            "unsupported erofs directory block size"
        );
        Ok(Erofs {
            meta_base: (le32(&sb, 40) as u64) << blkszbits,
            root_nid: le16(&sb, 14) as u64,
            packed_nid: le64(&sb, 96),
            compr_algs: le16(&sb, 84),
            compr_cfgs: incompat & FEAT_COMPR_CFGS != 0,
            view,
            blkszbits,
            packed: Mutex::new(None),
            cache: Mutex::new(PackedCache::default()),
        })
    }

    fn blksz(&self) -> u64 {
        1 << self.blkszbits
    }

    pub(crate) fn inode(&self, nid: u64) -> Result<Inode> {
        let base = self.meta_base + nid * 32;
        let mut buf = [0u8; 64];
        ensure!(
            self.view.read_full_at(&mut buf, base)? >= 32,
            "truncated inode at nid {nid}"
        );
        let fmt = le16(&buf, 0);
        let layout = ((fmt >> 1) & 7) as u8;
        ensure!(
            layout <= 4,
            "reserved inode datalayout {layout} at nid {nid}"
        );
        let extended = fmt & 1 == 1;
        let isize = if extended { 64 } else { 32 };
        let icount = le16(&buf, 2) as u64;
        let xattr = if icount == 0 {
            0
        } else {
            12 + (icount - 1) * 4
        };
        let size = if extended {
            le64(&buf, 8)
        } else {
            le32(&buf, 8) as u64
        };
        Ok(Inode {
            base,
            isize,
            xattr,
            mode: le16(&buf, 4),
            size,
            layout,
            u: le32(&buf, 16),
        })
    }

    // ---------------------------------------------------------- files

    /// Every regular file under the root, in directory-walk order.
    /// Oddities (unsupported compression, unreadable subtrees, loops)
    /// become notes, never silent drops.
    pub(crate) fn files(&self) -> Result<(Vec<FileItem>, Vec<String>)> {
        let mut files = Vec::new();
        let mut notes = Vec::new();
        let mut visited = HashSet::new();
        let root = self.inode(self.root_nid).context("erofs root inode")?;
        ensure!(
            root.mode & 0o170000 == 0o040000,
            "erofs root is not a directory"
        );
        self.walk_dir(&root, "", 0, &mut files, &mut notes, &mut visited)?;
        Ok((files, notes))
    }

    fn walk_dir(
        &self,
        dir: &Inode,
        prefix: &str,
        depth: usize,
        files: &mut Vec<FileItem>,
        notes: &mut Vec<String>,
        visited: &mut HashSet<u64>,
    ) -> Result<()> {
        if depth > DIR_MAX_DEPTH {
            notes.push(format!(
                "{prefix}: directory tree deeper than {DIR_MAX_DEPTH} — pruned"
            ));
            return Ok(());
        }
        if !visited.insert(dir.base) {
            notes.push(format!("{prefix}: directory cycle — pruned"));
            return Ok(());
        }
        let entries = match self.read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                notes.push(format!("{prefix}: unreadable directory: {e:#}"));
                return Ok(());
            }
        };
        for (name, nid, ftype) in entries {
            if name == "." || name == ".." {
                continue;
            }
            match ftype {
                2 => {
                    let sub = match self.inode(nid) {
                        Ok(i) if i.mode & 0o170000 == 0o040000 => i,
                        Ok(_) => {
                            notes.push(format!("{prefix}{name}: dirent/inode type mismatch"));
                            continue;
                        }
                        Err(e) => {
                            notes.push(format!("{prefix}{name}: {e:#}"));
                            continue;
                        }
                    };
                    self.walk_dir(
                        &sub,
                        &format!("{prefix}{name}/"),
                        depth + 1,
                        files,
                        notes,
                        visited,
                    )?;
                }
                1 => {
                    let path = format!("{prefix}{name}");
                    match self.file_plan(nid) {
                        Ok((plan, size)) => {
                            let order = match &plan {
                                Plan::Streamed(zp) => match zp.exts.first() {
                                    Some(ZExt {
                                        src: ZSrc::Packed { off },
                                        ..
                                    }) => (1, *off),
                                    Some(ZExt {
                                        src: ZSrc::Raw { pa, .. },
                                        ..
                                    }) => (0, *pa),
                                    _ => (0, 0),
                                },
                                Plan::Ranged(_) => (0, 0),
                            };
                            files.push(FileItem {
                                leaf: name.clone(),
                                path,
                                size,
                                plan,
                                order,
                            });
                        }
                        Err(e) => notes.push(format!("{path}: {e:#}")),
                    }
                }
                // Symlinks, devices, fifos, sockets: no file bytes to mint.
                _ => {}
            }
        }
        Ok(())
    }

    fn file_plan(&self, nid: u64) -> Result<(Plan, u64)> {
        let ino = self.inode(nid)?;
        ensure!(
            ino.mode & 0o170000 == 0o100000,
            "dirent says regular file, inode mode {:o} disagrees",
            ino.mode
        );
        Ok((self.plan(&ino)?, ino.size))
    }

    // ----------------------------------------------------------- data

    /// Resolve how an inode's bytes are laid out.
    fn plan(&self, ino: &Inode) -> Result<Plan> {
        const NULL_ADDR: u32 = u32::MAX;
        let blksz = self.blksz();
        match ino.layout {
            // Flat: contiguous blocks, optionally with the tail inline
            // right after the inode metadata.
            0 | 2 => {
                if ino.size == 0 {
                    return Ok(Plan::Ranged(Vec::new()));
                }
                let inline = ino.layout == 2;
                if !inline && ino.u == NULL_ADDR {
                    return Ok(Plan::Streamed(ZPlan {
                        size: ino.size,
                        exts: vec![ZExt {
                            la: 0,
                            llen: ino.size,
                            src: ZSrc::Zero,
                        }],
                    }));
                }
                let nblocks = ino.size.div_ceil(blksz);
                let head = if inline {
                    (nblocks - 1) * blksz
                } else {
                    ino.size
                };
                let mut exts = Vec::new();
                if head > 0 {
                    exts.push(((ino.u as u64) << self.blkszbits, head));
                }
                if inline {
                    exts.push((ino.end(), ino.size - head));
                }
                Ok(Plan::Ranged(exts))
            }
            4 => self.plan_chunked(ino),
            1 | 3 => Ok(Plan::Streamed(self.build_zplan(ino)?)),
            _ => unreachable!("layout validated at inode parse"),
        }
    }

    /// Chunk-based inodes: a table of chunk start blocks right after
    /// the inode. Null chunks are holes; hole-free files stay ranged.
    fn plan_chunked(&self, ino: &Inode) -> Result<Plan> {
        const NULL_ADDR: u32 = u32::MAX;
        let format = (ino.u & 0xffff) as u16;
        ensure!(format & 0x0040 == 0, "48-bit chunk indexes unsupported");
        let chunkbits = self.blkszbits + (format & 0x1f) as u32;
        let chunksz = 1u64 << chunkbits;
        let indexes = format & 0x0020 != 0;
        let unit: u64 = if indexes { 8 } else { 4 };
        let nchunks = ino.size.div_ceil(chunksz) as usize;
        let mut table = vec![0u8; unit as usize * nchunks];
        read_exact_at(&self.view, &mut table, ino.end().next_multiple_of(unit))
            .context("chunk table")?;
        let mut exts: Vec<(u64, u64, bool)> = Vec::with_capacity(nchunks);
        for c in 0..nchunks {
            let la = c as u64 * chunksz;
            let llen = chunksz.min(ino.size - la);
            let e = &table[c * unit as usize..];
            let startblk = if indexes {
                ensure!(le16(e, 2) == 0, "multi-device chunk unsupported");
                le32(e, 4)
            } else {
                le32(e, 0)
            };
            let hole = startblk == NULL_ADDR;
            exts.push(((startblk as u64) << self.blkszbits, llen, hole));
        }
        if exts.iter().any(|&(_, _, hole)| hole) {
            // Holes can't be expressed as image ranges — stream, with
            // mapped chunks as verbatim copies.
            let mut la = 0;
            let z = exts
                .into_iter()
                .map(|(pa, llen, hole)| {
                    let e = ZExt {
                        la,
                        llen,
                        src: if hole {
                            ZSrc::Zero
                        } else {
                            ZSrc::Raw {
                                pa,
                                plen: llen,
                                alg: Alg::Shifted,
                                partial: false,
                            }
                        },
                    };
                    la += llen;
                    e
                })
                .collect();
            Ok(Plan::Streamed(ZPlan {
                size: ino.size,
                exts: z,
            }))
        } else {
            Ok(Plan::Ranged(
                exts.into_iter().map(|(pa, llen, _)| (pa, llen)).collect(),
            ))
        }
    }

    /// Read a whole (small) inode into memory — directory data.
    fn read_all(&self, ino: &Inode, cap: u64) -> Result<Vec<u8>> {
        ensure!(ino.size <= cap, "implausibly large ({} bytes)", ino.size);
        match self.plan(ino)? {
            Plan::Ranged(exts) => {
                let mut out = Vec::with_capacity(ino.size as usize);
                for (pa, len) in exts {
                    let at = out.len();
                    out.resize(at + len as usize, 0);
                    read_exact_at(&self.view, &mut out[at..], pa)?;
                }
                Ok(out)
            }
            Plan::Streamed(zp) => {
                let mut out = Vec::with_capacity(ino.size as usize);
                std::io::Read::read_to_end(&mut self.zreader(&zp), &mut out)?;
                Ok(out)
            }
        }
    }

    fn read_dir(&self, ino: &Inode) -> Result<Vec<(String, u64, u8)>> {
        let data = self.read_all(ino, DIR_MAX_BYTES)?;
        let blksz = self.blksz() as usize;
        let mut out = Vec::new();
        for chunk in data.chunks(blksz) {
            if chunk.len() < 12 {
                ensure!(chunk.iter().all(|&b| b == 0), "malformed directory tail");
                continue;
            }
            let first_off = le16(chunk, 8) as usize;
            ensure!(
                first_off >= 12 && first_off.is_multiple_of(12) && first_off <= chunk.len(),
                "malformed directory block"
            );
            let count = first_off / 12;
            for j in 0..count {
                let d = &chunk[j * 12..];
                let nid = le64(d, 0);
                let nameoff = le16(d, 8) as usize;
                let ftype = d[10];
                let end = if j + 1 < count {
                    le16(&chunk[(j + 1) * 12..], 8) as usize
                } else {
                    chunk.len()
                };
                ensure!(
                    nameoff >= first_off && end >= nameoff && end <= chunk.len(),
                    "malformed dirent name offsets"
                );
                let mut name = &chunk[nameoff..end];
                if j + 1 == count {
                    // The last name runs to the block end; padding is
                    // NUL bytes (names never contain NUL).
                    if let Some(z) = name.iter().position(|&b| b == 0) {
                        name = &name[..z];
                    }
                }
                ensure!(!name.is_empty(), "empty dirent name");
                out.push((String::from_utf8_lossy(name).into_owned(), nid, ftype));
            }
        }
        Ok(out)
    }

    // -------------------------------------------------------- z plans

    /// Build the full extent map of a compressed inode by scanning its
    /// lcluster indexes front to back (the kernel maps lazily with
    /// lookback; reading whole files lets us do one simple pass).
    fn build_zplan(&self, ino: &Inode) -> Result<ZPlan> {
        let hpos = align8(ino.end());
        let mut h = [0u8; 8];
        read_exact_at(&self.view, &mut h, hpos).context("z map header")?;
        let raw = le64(&h, 0);
        // Top bit of the 8-byte header: the whole file lives in the
        // packed inode at the offset in the remaining 63 bits.
        if raw >> 63 == 1 {
            return Ok(ZPlan {
                size: ino.size,
                exts: vec![ZExt {
                    la: 0,
                    llen: ino.size,
                    src: ZSrc::Packed {
                        off: raw ^ (1 << 63),
                    },
                }],
            });
        }
        let advise = le16(&h, 4);
        let algtype = h[6];
        let clusterbits = h[7];
        let lcb = self.blkszbits + (clusterbits & 15) as u32;
        ensure!(
            lcb <= 14 || ino.layout == 1,
            "oversized lclusters in compact index"
        );
        if ino.layout == 1 && advise & ADV_EXTENTS != 0 {
            bail!("erofs extent-metadata layout not supported");
        }
        if ino.layout == 3 {
            ensure!(
                clusterbits & 15 == 0,
                "compact indexes with lclusters larger than blocks"
            );
        }
        let frag = advise & ADV_FRAGMENT != 0;
        let inline = advise & ADV_INLINE_PCLUSTER != 0;
        let idata_size = le16(&h, 2) as u64;
        let bigpcl1 = advise & ADV_BIG_PCLUSTER_1 != 0;
        let bigpcl2 = advise & ADV_BIG_PCLUSTER_2 != 0;
        if ino.size == 0 {
            return Ok(ZPlan {
                size: 0,
                exts: Vec::new(),
            });
        }

        struct Head {
            lcn: u64,
            la: u64,
            ty: u8,
            pblk: u32,
            cblks: Option<u32>,
            next_nonhead: bool,
            partial: bool,
            hole: bool,
        }
        let nlcl = ino.size.div_ceil(1 << lcb);
        let idx = self.load_indexes(ino, hpos, advise, nlcl, lcb)?;
        let mut heads: Vec<Head> = Vec::new();
        for lcn in 0..nlcl {
            let l = idx.get(lcn)?;
            if l.ty == LCL_NONHEAD {
                if let Some(h) = heads.last_mut() {
                    if lcn == h.lcn + 1 {
                        h.next_nonhead = true;
                        h.cblks = l.cblkcnt;
                    }
                }
            } else {
                ensure!(
                    (l.clusterofs as u64) < (1 << lcb),
                    "corrupt clusterofs at lcn {lcn}"
                );
                let la = (lcn << lcb) | l.clusterofs as u64;
                if la >= ino.size {
                    // EOF terminator head: exists only to mark where
                    // the previous pcluster's data ends (at i_size) —
                    // it owns no data of its own.
                    break;
                }
                heads.push(Head {
                    lcn,
                    la,
                    ty: l.ty,
                    pblk: l.blkaddr,
                    cblks: None,
                    next_nonhead: false,
                    partial: l.partial,
                    hole: l.hole,
                });
            }
        }
        ensure!(
            heads.first().map(|h| h.la) == Some(0),
            "compressed file does not start with a head lcluster"
        );

        let alg_of = |code: u8| -> Result<Alg> {
            Ok(match code {
                0 => Alg::Lz4,
                1 => Alg::Lzma,
                2 => Alg::Deflate,
                3 => Alg::Zstd,
                n => bail!("unsupported erofs compression algorithm {n}"),
            })
        };
        let mut fragoff = le32(&h, 0) as u64;
        let mut exts = Vec::with_capacity(heads.len());
        for i in 0..heads.len() {
            let head = &heads[i];
            let end_la = heads.get(i + 1).map(|n| n.la).unwrap_or(ino.size);
            ensure!(end_la > head.la, "empty pcluster at lcn {}", head.lcn);
            let llen = end_la - head.la;
            ensure!(llen <= PCLUSTER_MAX_DSIZE, "oversized pcluster span");
            let last = i + 1 == heads.len();
            let alg = match head.ty {
                LCL_PLAIN if advise & ADV_INTERLACED != 0 => Alg::Interlaced {
                    skip: (head.la & (self.blksz() - 1)) as u32,
                },
                LCL_PLAIN => Alg::Shifted,
                LCL_HEAD2 => alg_of(algtype >> 4)?,
                _ => alg_of(algtype & 15)?,
            };
            let src = if last && frag {
                // The tail extent's bytes live in the packed inode;
                // full-layout indexes carry the offset's high half in
                // the tail head's blkaddr slot.
                if ino.layout == 1 {
                    fragoff |= (head.pblk as u64) << 32;
                }
                ZSrc::Packed { off: fragoff }
            } else if last && inline {
                // ztailpacking: the tail pcluster's compressed bytes
                // sit inline right after the lcluster indexes.
                ZSrc::Raw {
                    pa: idx.end,
                    plen: idata_size,
                    alg,
                    partial: head.partial,
                }
            } else if head.hole {
                ZSrc::Zero
            } else {
                let one = (head.ty == LCL_HEAD1 && !bigpcl1)
                    || ((head.ty == LCL_PLAIN || head.ty == LCL_HEAD2) && !bigpcl2)
                    || ((head.lcn + 1) << lcb) >= ino.size;
                let blocks = if one {
                    1
                } else {
                    match head.cblks {
                        Some(n) => n,
                        None if head.next_nonhead => {
                            bail!("big pcluster without CBLKCNT at lcn {}", head.lcn)
                        }
                        None => 1,
                    }
                };
                if blocks == 0 {
                    ZSrc::Zero
                } else {
                    let plen = (blocks as u64) << self.blkszbits;
                    ensure!(plen <= PCLUSTER_MAX_SIZE, "oversized pcluster");
                    if matches!(alg, Alg::Shifted | Alg::Interlaced { .. }) {
                        ensure!(llen <= plen, "plain pcluster shorter than its span");
                    }
                    ZSrc::Raw {
                        pa: (head.pblk as u64) << self.blkszbits,
                        plen,
                        alg,
                        partial: head.partial,
                    }
                }
            };
            exts.push(ZExt {
                la: head.la,
                llen,
                src,
            });
        }
        Ok(ZPlan {
            size: ino.size,
            exts,
        })
    }

    /// Slurp an inode's whole lcluster index area and wrap it in a
    /// decoder (full 8-byte records, or the compacted 4B/2B bit-packed
    /// packs — transliterated from zmap.c).
    fn load_indexes(
        &self,
        ino: &Inode,
        hpos: u64,
        advise: u16,
        nlcl: u64,
        lcb: u32,
    ) -> Result<Indexes> {
        if ino.layout == 1 {
            // Full: fixed 8-byte records after the header + 8 reserved.
            let start = hpos + 8 + 8;
            let mut buf = vec![0u8; (nlcl * 8) as usize];
            read_exact_at(&self.view, &mut buf, start).context("full lcluster indexes")?;
            return Ok(Indexes {
                buf,
                end: start + nlcl * 8,
                kind: IndexKind::Full,
            });
        }
        // Compact: an initial run of 4-byte-amortized packs aligning to
        // 32 bytes, then 2-byte packs (if COMPACTED_2B), then 4-byte
        // again. totalidx is in blocks — identical to lclusters here
        // (compact requires lclusterbits == blkszbits, checked above).
        let ebase = hpos + 8;
        let totalidx = ino.size.div_ceil(self.blksz());
        let c4init = ((32 - ebase % 32) / 4) & 7;
        let c2b = if advise & ADV_COMPACTED_2B != 0 && c4init < totalidx {
            (totalidx - c4init) & !15
        } else {
            0
        };
        let pos_of = |mut lcn: u64| -> (u64, u32) {
            let mut pos = ebase;
            let mut shift = 2u32;
            if lcn >= c4init {
                pos += c4init * 4;
                lcn -= c4init;
                if lcn < c2b {
                    shift = 1;
                } else {
                    pos += c2b * 2;
                    lcn -= c2b;
                }
            }
            (pos + (lcn << shift), shift)
        };
        let (last_pos, last_shift) = pos_of(nlcl - 1);
        let vcnt_sz = |shift: u32| -> u64 {
            let vcnt: u64 = if shift == 2 { 2 } else { 16 };
            vcnt << shift
        };
        let end = (last_pos & !(vcnt_sz(last_shift) - 1)) + vcnt_sz(last_shift);
        let mut buf = vec![0u8; (end - ebase) as usize];
        read_exact_at(&self.view, &mut buf, ebase).context("compact lcluster indexes")?;
        Ok(Indexes {
            buf,
            end,
            kind: IndexKind::Compact {
                ebase,
                lclusterbits: lcb,
                totalidx,
                c4init,
                c2b,
                big: advise & ADV_BIG_PCLUSTER_1 != 0,
            },
        })
    }

    // --------------------------------------------------------- reads

    pub(crate) fn zreader<'a>(&'a self, plan: &'a ZPlan) -> ZReader<'a> {
        ZReader {
            fs: self,
            plan,
            pos: 0,
            idx: 0,
            cur: None,
        }
    }

    fn packed_plan(&self) -> Result<Arc<ZPlan>> {
        let mut slot = self.packed.lock().unwrap();
        if let Some(p) = slot.as_ref() {
            return Ok(p.clone());
        }
        ensure!(self.packed_nid != 0, "fragment data but no packed inode");
        let ino = self.inode(self.packed_nid).context("erofs packed inode")?;
        let plan = self.build_zplan(&ino).context("packed inode map")?;
        ensure!(
            !plan
                .exts
                .iter()
                .any(|e| matches!(e.src, ZSrc::Packed { .. })),
            "packed inode recurses into itself"
        );
        let plan = Arc::new(plan);
        *slot = Some(plan.clone());
        Ok(plan)
    }

    /// Every stored pcluster of the packed inode, in stream order, and
    /// the stream's total length. Holes (a packed inode written with
    /// gaps) carry no stored bytes and are simply absent — each
    /// pcluster names its own `la`, so the list needs no continuity.
    pub(crate) fn packed_pclusters(&self) -> Result<(Vec<PCluster>, u64)> {
        if self.packed_nid == 0 {
            return Ok((Vec::new(), 0));
        }
        let plan = self.packed_plan()?;
        let mut out = Vec::with_capacity(plan.exts.len());
        for e in &plan.exts {
            match &e.src {
                ZSrc::Raw {
                    pa,
                    plen,
                    alg,
                    partial,
                } => out.push(PCluster {
                    la: e.la,
                    llen: e.llen,
                    pa: *pa,
                    plen: *plen,
                    lzma: matches!(alg, Alg::Lzma),
                    alg: *alg,
                    partial: *partial,
                }),
                ZSrc::Zero => {}
                ZSrc::Packed { .. } => unreachable!("checked when the packed map was built"),
            }
        }
        Ok((out, plan.size))
    }

    /// The logical bytes of one packed pcluster, decoded straight from
    /// the image (no LRU: recipe minting sweeps the stream once).
    pub(crate) fn decode_pcluster(&self, pc: &PCluster) -> Result<Vec<u8>> {
        self.decode_raw(pc.pa, pc.plen, pc.llen, pc.alg, pc.partial)
    }

    /// The image's MicroLZMA configuration, from the per-algorithm
    /// blocks that follow the superblock: each is a `le16` length then
    /// that many bytes, in `available_compr_algs` bit order.
    pub(crate) fn lzma_cfg(&self) -> Result<Option<LzmaCfg>> {
        if !self.compr_cfgs {
            return Ok(None);
        }
        let mut off = EROFS_SUPER_OFFSET + SUPER_SIZE;
        let mut algs = self.compr_algs;
        for bit in 0..16 {
            if algs == 0 {
                break;
            }
            if algs & 1 != 0 {
                let mut len = [0u8; 2];
                read_exact_at(&self.view, &mut len, off).context("compression config")?;
                let size = le16(&len, 0) as u64;
                off += 2;
                if bit == ALG_LZMA {
                    ensure!(size >= 6, "truncated lzma configuration ({size} bytes)");
                    let mut cfg = vec![0u8; size as usize];
                    read_exact_at(&self.view, &mut cfg, off).context("lzma configuration")?;
                    return Ok(Some(LzmaCfg {
                        dict_size: le32(&cfg, 0),
                        format: le16(&cfg, 4),
                    }));
                }
                off += size;
            }
            algs >>= 1;
        }
        Ok(None)
    }

    /// Read from the packed inode's decompressed stream, through the
    /// pcluster LRU. Returns a short read at extent boundaries.
    fn packed_read(&self, off: u64, buf: &mut [u8]) -> Result<usize> {
        let plan = self.packed_plan()?;
        ensure!(off < plan.size, "fragment offset beyond the packed stream");
        let i = plan.exts.partition_point(|e| e.la + e.llen <= off);
        let e = &plan.exts[i];
        let within = off - e.la;
        let n = buf.len().min((e.llen - within) as usize);
        match &e.src {
            ZSrc::Zero => buf[..n].fill(0),
            ZSrc::Raw {
                pa,
                plen,
                alg,
                partial,
            } => {
                let chunk = self.packed_chunk(e.la, *pa, *plen, e.llen, *alg, *partial)?;
                buf[..n].copy_from_slice(&chunk[within as usize..within as usize + n]);
            }
            ZSrc::Packed { .. } => unreachable!("checked when the packed map was built"),
        }
        Ok(n)
    }

    fn packed_chunk(
        &self,
        la: u64,
        pa: u64,
        plen: u64,
        llen: u64,
        alg: Alg,
        partial: bool,
    ) -> Result<Arc<Vec<u8>>> {
        if let Some(hit) = self.cache.lock().unwrap().map.get(&la) {
            return Ok(hit.clone());
        }
        let bytes = Arc::new(self.decode_raw(pa, plen, llen, alg, partial)?);
        let mut c = self.cache.lock().unwrap();
        if c.map.insert(la, bytes.clone()).is_none() {
            c.bytes += bytes.len();
            c.order.push_back(la);
            while c.bytes > PACKED_CACHE_BYTES {
                let Some(old) = c.order.pop_front() else {
                    break;
                };
                if let Some(v) = c.map.remove(&old) {
                    c.bytes -= v.len();
                }
            }
        }
        Ok(bytes)
    }

    /// Fetch and decode one pcluster: `plen` stored bytes at `pa`
    /// yielding `llen` logical bytes.
    fn decode_raw(
        &self,
        pa: u64,
        plen: u64,
        llen: u64,
        alg: Alg,
        partial: bool,
    ) -> Result<Vec<u8>> {
        ensure!(
            plen <= PCLUSTER_MAX_SIZE && llen <= PCLUSTER_MAX_DSIZE,
            "implausible pcluster"
        );
        let mut input = vec![0u8; plen as usize];
        read_exact_at(&self.view, &mut input, pa).context("pcluster read")?;
        let llen = llen as usize;
        match alg {
            Alg::Shifted => Ok({
                input.truncate(llen);
                input
            }),
            Alg::Interlaced { skip } => {
                // Rotated raw storage (see z_erofs_decompress in
                // erofs-utils): data starts `skip` into the block and
                // wraps to the front.
                ensure!(
                    input.len() as u64 <= self.blksz(),
                    "interlaced pcluster too large"
                );
                let skip = skip as usize % input.len().max(1);
                let right = (input.len() - skip).min(llen);
                let mut out = Vec::with_capacity(llen);
                out.extend_from_slice(&input[skip..skip + right]);
                out.extend_from_slice(&input[..llen - right]);
                Ok(out)
            }
            // Compressed pclusters may be 0-padded at the front
            // (padding can't start a valid stream in any of these
            // formats — same margin scan as erofs-utils).
            Alg::Lz4 => {
                let src = &input[margin(&input)..];
                let mut cap = llen.max(1);
                loop {
                    let mut out = vec![0u8; cap];
                    match lz4_flex::block::decompress_into(src, &mut out) {
                        Ok(n) if n >= llen => {
                            out.truncate(llen);
                            return Ok(out);
                        }
                        Ok(n) => bail!("lz4 pcluster decoded short ({n} of {llen} bytes)"),
                        Err(e) if partial && cap < PCLUSTER_MAX_DSIZE as usize => {
                            let _ = e;
                            cap = (cap * 2).min(PCLUSTER_MAX_DSIZE as usize);
                        }
                        Err(e) => bail!("lz4 pcluster: {e}"),
                    }
                }
            }
            Alg::Lzma => microlzma_decode(&input[margin(&input)..], llen, !partial),
            Alg::Deflate => {
                let src = &input[margin(&input)..];
                let mut out = vec![0u8; llen];
                let mut d = flate2::Decompress::new(false);
                d.decompress(src, &mut out, flate2::FlushDecompress::Finish)
                    .context("deflate pcluster")?;
                ensure!(
                    d.total_out() as usize == llen,
                    "deflate pcluster decoded short"
                );
                Ok(out)
            }
            Alg::Zstd => {
                let src = &input[margin(&input)..];
                let mut out = vec![0u8; llen];
                let mut dec = zstd::stream::read::Decoder::new(src)?;
                std::io::Read::read_exact(&mut dec, &mut out).context("zstd pcluster")?;
                Ok(out)
            }
        }
    }
}

fn margin(input: &[u8]) -> usize {
    input.iter().take_while(|&&b| b == 0).count()
}

// ------------------------------------------------------------ indexes

struct Indexes {
    buf: Vec<u8>,
    /// First byte past the index area — where ztailpacking inline
    /// pcluster data begins.
    end: u64,
    kind: IndexKind,
}

enum IndexKind {
    Full,
    Compact {
        ebase: u64,
        lclusterbits: u32,
        totalidx: u64,
        c4init: u64,
        c2b: u64,
        big: bool,
    },
}

struct Lcl {
    ty: u8,
    clusterofs: u32,
    blkaddr: u32,
    cblkcnt: Option<u32>,
    partial: bool,
    hole: bool,
}

impl Indexes {
    fn get(&self, lcn: u64) -> Result<Lcl> {
        match &self.kind {
            IndexKind::Full => {
                let d = &self.buf[(lcn * 8) as usize..(lcn * 8 + 8) as usize];
                let advise = le16(d, 0);
                let ty = (advise & 3) as u8;
                if ty == LCL_NONHEAD {
                    let delta0 = le16(d, 4) as u32;
                    Ok(Lcl {
                        ty,
                        clusterofs: 0,
                        blkaddr: 0,
                        cblkcnt: (delta0 & CBLKCNT != 0).then_some(delta0 & !CBLKCNT),
                        partial: false,
                        hole: false,
                    })
                } else {
                    let hole = advise & (1 << 14) != 0;
                    Ok(Lcl {
                        ty,
                        clusterofs: le16(d, 2) as u32,
                        blkaddr: if hole { 0 } else { le32(d, 4) },
                        cblkcnt: None,
                        partial: advise & (1 << 15) != 0,
                        hole,
                    })
                }
            }
            IndexKind::Compact {
                ebase,
                lclusterbits,
                totalidx,
                c4init,
                c2b,
                big,
            } => self.get_compact(lcn, *ebase, *lclusterbits, *totalidx, *c4init, *c2b, *big),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn get_compact(
        &self,
        lcn: u64,
        ebase: u64,
        lclusterbits: u32,
        totalidx: u64,
        c4init: u64,
        c2b: u64,
        big: bool,
    ) -> Result<Lcl> {
        ensure!(lcn < totalidx && lclusterbits <= 14, "lcn out of range");
        let (pos, shift) = {
            let mut l = lcn;
            let mut p = ebase;
            let mut s = 2u32;
            if l >= c4init {
                p += c4init * 4;
                l -= c4init;
                if l < c2b {
                    s = 1;
                } else {
                    p += c2b * 2;
                    l -= c2b;
                }
            }
            (p + (l << s), s)
        };
        let vcnt: usize = if shift == 2 { 2 } else { 16 };
        let packsz = (vcnt << shift) as u64;
        let base = pos & !(packsz - 1);
        let pack = &self.buf[(base - ebase) as usize..(base - ebase + packsz) as usize];
        let lobits = lclusterbits.max(12);
        let encodebits = ((packsz as usize - 4) * 8 / vcnt) as u32;
        let i = ((pos - base) >> shift) as usize;

        let entry = |i: usize| -> (u32, u8) {
            let bitpos = encodebits as usize * i;
            let v = le32(pack, bitpos / 8) >> (bitpos & 7);
            ((v & ((1 << lobits) - 1)), ((v >> lobits) & 3) as u8)
        };
        let (lo, ty) = entry(i);
        if ty == LCL_NONHEAD {
            // lo is delta[0] (or CBLKCNT, or — as the last entry of a
            // pack — delta[1]); we only consume the CBLKCNT form.
            return Ok(Lcl {
                ty,
                clusterofs: 0,
                blkaddr: 0,
                cblkcnt: (lo & CBLKCNT != 0).then_some(lo & !CBLKCNT),
                partial: false,
                hole: false,
            });
        }
        // HEAD/PLAIN: walk back through the pack counting the physical
        // blocks used before this head; blkaddr = pack's base block +
        // that count (transliterated from z_erofs_load_compact_lcluster).
        let mut nblk: u64;
        let mut j = i as i64;
        if !big {
            nblk = 1;
            while j > 0 {
                j -= 1;
                let (lo, ty) = entry(j as usize);
                if ty == LCL_NONHEAD {
                    j -= lo as i64;
                }
                if j >= 0 {
                    nblk += 1;
                }
            }
        } else {
            nblk = 0;
            while j > 0 {
                j -= 1;
                let (lo, ty) = entry(j as usize);
                if ty == LCL_NONHEAD {
                    if lo & CBLKCNT != 0 {
                        j -= 1;
                        nblk += (lo & !CBLKCNT) as u64;
                        continue;
                    }
                    ensure!(lo > 1, "corrupt compact index (d0 <= 1 in big pcluster)");
                    j -= lo as i64 - 2;
                    continue;
                }
                nblk += 1;
            }
        }
        let blkbase = le32(pack, pack.len() - 4) as u64;
        Ok(Lcl {
            ty,
            clusterofs: lo,
            blkaddr: u32::try_from(blkbase + nblk).context("blkaddr overflow")?,
            cblkcnt: None,
            partial: false,
            hole: false,
        })
    }
}

// ------------------------------------------------------------- reader

/// Streams a compressed file's logical bytes: extents decode one at a
/// time (own pclusters buffered per reader; packed-inode reads go
/// through the image-wide LRU).
pub(crate) struct ZReader<'a> {
    fs: &'a Erofs,
    plan: &'a ZPlan,
    pos: u64,
    idx: usize,
    cur: Option<Vec<u8>>,
}

impl std::io::Read for ZReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.plan.size || buf.is_empty() {
            return Ok(0);
        }
        while self.idx < self.plan.exts.len() {
            let e = &self.plan.exts[self.idx];
            if self.pos < e.la + e.llen {
                break;
            }
            self.idx += 1;
            self.cur = None;
        }
        let err = |e: anyhow::Error| std::io::Error::other(format!("{e:#}"));
        let e = self
            .plan
            .exts
            .get(self.idx)
            .ok_or_else(|| std::io::Error::other("erofs extent map ends early"))?;
        if self.pos < e.la {
            return Err(std::io::Error::other("erofs extent map has a gap"));
        }
        let within = (self.pos - e.la) as usize;
        let n = buf.len().min((e.llen as usize) - within);
        match &e.src {
            ZSrc::Zero => buf[..n].fill(0),
            ZSrc::Packed { off } => {
                let got = self
                    .fs
                    .packed_read(*off + within as u64, &mut buf[..n])
                    .map_err(err)?;
                self.pos += got as u64;
                return Ok(got);
            }
            ZSrc::Raw {
                pa,
                plen,
                alg,
                partial,
            } => {
                if self.cur.is_none() {
                    self.cur = Some(
                        self.fs
                            .decode_raw(*pa, *plen, e.llen, *alg, *partial)
                            .map_err(err)?,
                    );
                }
                let cur = self.cur.as_ref().unwrap();
                buf[..n].copy_from_slice(&cur[within..within + n]);
            }
        }
        self.pos += n as u64;
        Ok(n)
    }
}

// ---------------------------------------------------------- microlzma

/// Decode one MicroLZMA pcluster (the erofs-specific liblzma format;
/// mkfs uses fixed-output encoding, so with `exact` the decoder knows
/// to cut a final match at the output boundary).
fn microlzma_decode(input: &[u8], out_len: usize, exact: bool) -> Result<Vec<u8>> {
    ensure!(!input.is_empty(), "empty lzma pcluster");
    let mut out = vec![0u8; out_len];
    unsafe {
        let mut strm: liblzma_sys::lzma_stream = std::mem::zeroed();
        let r = liblzma_sys::lzma_microlzma_decoder(
            &mut strm,
            input.len() as u64,
            out_len as u64,
            exact as u8,
            LZMA_MAX_DICT,
        );
        ensure!(
            r == liblzma_sys::LZMA_OK,
            "microlzma decoder init failed ({r})"
        );
        strm.next_in = input.as_ptr();
        strm.avail_in = input.len();
        strm.next_out = out.as_mut_ptr();
        strm.avail_out = out_len;
        let r = liblzma_sys::lzma_code(&mut strm, liblzma_sys::LZMA_FINISH);
        let left = strm.avail_out;
        liblzma_sys::lzma_end(&mut strm);
        ensure!(
            r == liblzma_sys::LZMA_STREAM_END && left == 0,
            "microlzma pcluster failed to decode (ret {r}, {left} bytes short)"
        );
    }
    Ok(out)
}

/// Encode one MicroLZMA pcluster the way mkfs.erofs does: FIXED
/// OUTPUT. mkfs hands the encoder the whole remaining stream and an
/// output buffer of the pcluster's size, and the encoder stops when
/// that buffer is full — cutting the final match mid-symbol. Feeding
/// exactly the pcluster's logical span instead would end the stream
/// cleanly and differ in its last few bytes, so callers must pass
/// MORE input than the span and let `consumed` say what was used.
/// Returns (compressed bytes, input bytes consumed).
pub(crate) fn microlzma_encode(
    input: &[u8],
    out_cap: usize,
    preset: u32,
    dict_size: u32,
) -> Result<(Vec<u8>, u64)> {
    ensure!(out_cap > 0, "zero-capacity pcluster");
    ensure!(
        (1 << 12..=LZMA_MAX_DICT).contains(&dict_size),
        "implausible lzma dictionary size {dict_size}"
    );
    let mut out = vec![0u8; out_cap];
    let (produced, consumed) = unsafe {
        let mut opts: liblzma_sys::lzma_options_lzma = std::mem::zeroed();
        ensure!(
            liblzma_sys::lzma_lzma_preset(&mut opts, preset) == 0,
            "lzma preset {preset} rejected"
        );
        opts.dict_size = dict_size;
        let mut strm: liblzma_sys::lzma_stream = std::mem::zeroed();
        let r = liblzma_sys::lzma_microlzma_encoder(&mut strm, &opts);
        ensure!(
            r == liblzma_sys::LZMA_OK,
            "microlzma encoder init failed ({r})"
        );
        strm.next_in = input.as_ptr();
        strm.avail_in = input.len();
        strm.next_out = out.as_mut_ptr();
        strm.avail_out = out_cap;
        // LZMA_OK here means "output full, input left over" — the
        // truncated shape mkfs stores; LZMA_STREAM_END means the input
        // ran out first (the last pcluster of a stream).
        let r = liblzma_sys::lzma_code(&mut strm, liblzma_sys::LZMA_FINISH);
        let got = (out_cap - strm.avail_out, strm.total_in);
        liblzma_sys::lzma_end(&mut strm);
        ensure!(
            r == liblzma_sys::LZMA_OK || r == liblzma_sys::LZMA_STREAM_END,
            "microlzma encode failed ({r})"
        );
        got
    };
    out.truncate(produced);
    Ok((out, consumed))
}

/// Leading zero bytes of a stored pcluster: erofs right-aligns
/// compressed data inside its blocks (the 0padding feature) so the
/// kernel can decompress in place. Rebuilding one means writing the
/// same padding back.
pub(crate) fn pcluster_padding(stored: &[u8]) -> usize {
    margin(stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of the committed test images (see `scan_descends_erofs_images`
    /// in tests/cli.rs for how they were built), decompressed.
    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/data/erofs/{name}.erofs.gz"));
        let gz = std::fs::read(path).expect("fixture image");
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut raw).unwrap();
        raw
    }

    /// Round-trip through liblzma's MicroLZMA coder pair — proves the
    /// unsafe FFI usage (init order, buffer wiring, FINISH semantics)
    /// against the same library mkfs.erofs links.
    #[test]
    fn microlzma_round_trip() {
        let data: Vec<u8> = (0..40_000u32)
            .flat_map(|i| ((i / 7) as u16).to_le_bytes())
            .collect();
        let comp = unsafe {
            let mut opts: liblzma_sys::lzma_options_lzma = std::mem::zeroed();
            assert_eq!(liblzma_sys::lzma_lzma_preset(&mut opts, 6), 0);
            opts.dict_size = LZMA_MAX_DICT;
            let mut strm: liblzma_sys::lzma_stream = std::mem::zeroed();
            assert_eq!(
                liblzma_sys::lzma_microlzma_encoder(&mut strm, &opts),
                liblzma_sys::LZMA_OK
            );
            let mut comp = vec![0u8; data.len() + 1024];
            strm.next_in = data.as_ptr();
            strm.avail_in = data.len();
            strm.next_out = comp.as_mut_ptr();
            strm.avail_out = comp.len();
            let r = liblzma_sys::lzma_code(&mut strm, liblzma_sys::LZMA_FINISH);
            assert_eq!(r, liblzma_sys::LZMA_STREAM_END);
            comp.truncate(comp.len() - strm.avail_out);
            liblzma_sys::lzma_end(&mut strm);
            comp
        };
        assert!(comp.len() < data.len());
        let back = microlzma_decode(&comp, data.len(), true).unwrap();
        assert_eq!(back, data);
    }

    /// Fixed-output encoding: with an output buffer too small for the
    /// whole input, the encoder fills it exactly, reports how much
    /// input those bytes represent, and the result decodes back to
    /// that prefix (`exact = false` — the last match is cut short).
    #[test]
    fn microlzma_fixed_output_truncates() {
        let data: Vec<u8> = (0..200_000u32)
            .flat_map(|i| ((i / 3) as u16).to_le_bytes())
            .collect();
        let (full, all) = microlzma_encode(&data, data.len(), 6, 1 << 20).unwrap();
        assert_eq!(all, data.len() as u64, "whole input fits");
        let cap = full.len() / 2;
        let (part, consumed) = microlzma_encode(&data, cap, 6, 1 << 20).unwrap();
        assert_eq!(part.len(), cap, "fixed output fills the buffer exactly");
        assert!(consumed > 0 && consumed < data.len() as u64, "{consumed}");
        let back = microlzma_decode(&part, consumed as usize, false).unwrap();
        assert_eq!(back, data[..consumed as usize]);
    }

    /// The packed inode's pclusters, against the all-fragments fixture:
    /// they tile the stream, each decodes to its stated span, and the
    /// image states the dictionary size the encoder needs.
    #[test]
    fn packed_pclusters_tile_the_stream() {
        let raw = fixture("frag");
        let len = raw.len() as u64;
        let view = View::new(
            Arc::new(crate::peek_source::PSource::Mem(raw.into())),
            &[(0, len)],
        );
        let fs = Erofs::open(view).unwrap();
        let (pcs, size) = fs.packed_pclusters().unwrap();
        assert!(pcs.len() > 1, "fixture should have several pclusters");
        let mut la = 0;
        for pc in &pcs {
            assert_eq!(pc.la, la, "pclusters tile the packed stream");
            assert_eq!(fs.decode_pcluster(pc).unwrap().len(), pc.llen as usize);
            la += pc.llen;
        }
        assert!(
            pcs.iter().filter(|p| p.lzma).count() > 1,
            "fixture should have several MicroLZMA pclusters: {:?}",
            pcs.iter()
                .map(|p| (p.llen, p.plen, p.lzma))
                .collect::<Vec<_>>()
        );
        assert_eq!(la, size, "pclusters cover the whole stream");
        let cfg = fs.lzma_cfg().unwrap().expect("lzma configuration");
        assert!(
            cfg.dict_size.is_power_of_two() && cfg.dict_size >= (1 << 12),
            "dict_size {}",
            cfg.dict_size
        );
    }

    /// The whole point of rung E: mkfs.erofs' stored pclusters come
    /// back byte-exact from the packed stream, at the preset and
    /// dictionary size the image itself states.
    #[test]
    fn packed_pclusters_re_encode_byte_exact() {
        let raw = fixture("frag");
        let len = raw.len() as u64;
        let view = View::new(
            Arc::new(crate::peek_source::PSource::Mem(raw.clone().into())),
            &[(0, len)],
        );
        let fs = Erofs::open(view).unwrap();
        let (pcs, _) = fs.packed_pclusters().unwrap();
        let cfg = fs.lzma_cfg().unwrap().unwrap();
        let stream: Vec<u8> = pcs
            .iter()
            .flat_map(|pc| fs.decode_pcluster(pc).unwrap())
            .collect();
        for pc in pcs.iter().filter(|p| p.lzma) {
            let stored = &raw[pc.pa as usize..(pc.pa + pc.plen) as usize];
            let pad = pcluster_padding(stored);
            // More input than the span: the encoder must run out of
            // OUTPUT, not input, or it ends the stream cleanly and the
            // tail bytes differ.
            let input = &stream[pc.la as usize..];
            let (out, consumed) =
                microlzma_encode(input, stored.len() - pad, 6, cfg.dict_size).unwrap();
            let mut candidate = vec![0u8; pad];
            candidate.extend_from_slice(&out);
            candidate.resize(stored.len(), 0);
            assert_eq!(candidate, stored, "pcluster at {} differs", pc.pa);
            assert_eq!(consumed, pc.llen, "pcluster at {} span", pc.pa);
        }
    }

    /// The interlaced transform matches erofs-utils' rotation copy.
    #[test]
    fn interlaced_rotation() {
        // A 16-byte "block": logical data starts at offset 5 and wraps.
        let stored: Vec<u8> = (0u8..16).collect();
        let fs_view = View::new(
            Arc::new(crate::peek_source::PSource::Mem(stored.clone().into())),
            &[(0, 16)],
        );
        let fs = Erofs {
            view: fs_view,
            blkszbits: 4, // 16-byte "blocks" for the test
            meta_base: 0,
            root_nid: 0,
            packed_nid: 0,
            compr_algs: 0,
            compr_cfgs: false,
            packed: Mutex::new(None),
            cache: Mutex::new(PackedCache::default()),
        };
        let out = fs
            .decode_raw(0, 16, 14, Alg::Interlaced { skip: 5 }, false)
            .unwrap();
        let mut expect: Vec<u8> = (5u8..16).collect();
        expect.extend(0u8..3);
        assert_eq!(out, expect);
    }
}
