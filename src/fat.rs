//! FAT12/16/32 reader: enough of the format to say where each file's
//! bytes live, which is all a hashoscope or a recipe ever needs.
//!
//! FAT matters here because every UEFI install medium carries an EFI
//! System Partition — on a hybrid ISO it is an El Torito boot image
//! appended outside the ISO9660 directory tree, so nothing else in the
//! walk can see it — and its contents are the same signed shim and
//! grub binaries the distro ships in packages.
//!
//! Files are returned as extent runs over the filesystem's own view:
//! a cluster chain coalesced into contiguous ranges, truncated to the
//! directory entry's size. Nothing is decompressed and nothing is
//! copied — the walker slices the view and hashes what it names.

use crate::peek_source::View;
use anyhow::{ensure, Result};
use std::collections::HashSet;

/// A FAT filesystem's geometry, read from the boot sector.
pub(crate) struct Fat {
    bytes_per_sector: u64,
    sectors_per_cluster: u64,
    reserved: u64,
    num_fats: u64,
    root_entries: u64,
    fat_sectors: u64,
    total_sectors: u64,
    root_cluster: u32,
    kind: Bits,
    /// Where cluster 2 begins, in bytes.
    data_start: u64,
    cluster_count: u32,
}

#[derive(Clone, Copy, PartialEq)]
enum Bits {
    Fat12,
    Fat16,
    Fat32,
}

/// One file the directory tree names, with the byte ranges holding it.
pub(crate) struct FatFile {
    pub(crate) path: String,
    pub(crate) runs: Vec<(u64, u64)>,
}

/// A FAT table bigger than this is not a filesystem we read: the whole
/// table is held in memory to follow chains, and the bound belongs in
/// the design rather than in a later OOM.
const FAT_TABLE_MAX: u64 = 64 << 20;
/// Directory nesting past this is a corrupt image, not a deep tree.
const MAX_DIR_DEPTH: usize = 64;

fn le16(b: &[u8], i: usize) -> u64 {
    u16::from_le_bytes([b[i], b[i + 1]]) as u64
}

fn le32(b: &[u8], i: usize) -> u64 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as u64
}

/// Whether a boot sector plausibly starts a FAT filesystem.
///
/// FAT has no magic worth the name — a 0x55AA signature at 510 is
/// shared with every MBR and plenty of firmware blobs — so this asks
/// for the whole BPB to make sense at once: a jump instruction, sane
/// geometry, and the type string mkfs writes. Reading a file that is
/// not a filesystem as one is how a walker invents members.
pub(crate) fn looks_like(head: &[u8]) -> bool {
    if head.len() < 512 || head[510] != 0x55 || head[511] != 0xAA {
        return false;
    }
    if !matches!(head[0], 0xEB | 0xE9) {
        return false;
    }
    let bps = le16(head, 11);
    let spc = head[13] as u64;
    if !matches!(bps, 512 | 1024 | 2048 | 4096) || spc == 0 || !spc.is_power_of_two() || spc > 128 {
        return false;
    }
    if le16(head, 14) == 0 || !matches!(head[16], 1 | 2) || head[21] < 0xF0 {
        return false;
    }
    head[54..59].starts_with(b"FAT") || head[82..87].starts_with(b"FAT")
}

impl Fat {
    pub(crate) fn open(view: &View) -> Result<Fat> {
        let mut boot = [0u8; 512];
        ensure!(
            view.read_full_at(&mut boot, 0)? == boot.len(),
            "truncated boot sector"
        );
        ensure!(looks_like(&boot), "not a FAT boot sector");
        let bytes_per_sector = le16(&boot, 11);
        let sectors_per_cluster = boot[13] as u64;
        let reserved = le16(&boot, 14);
        let num_fats = boot[16] as u64;
        let root_entries = le16(&boot, 17);
        let fat_sectors = match le16(&boot, 22) {
            0 => le32(&boot, 36),
            n => n,
        };
        let total_sectors = match le16(&boot, 19) {
            0 => le32(&boot, 32),
            n => n,
        };
        ensure!(fat_sectors > 0 && total_sectors > 0, "empty FAT geometry");

        // The classic layout arithmetic, straight out of the spec.
        let root_sectors = (root_entries * 32).div_ceil(bytes_per_sector);
        let first_data = reserved + num_fats * fat_sectors + root_sectors;
        ensure!(total_sectors > first_data, "no data area");
        let clusters = (total_sectors - first_data) / sectors_per_cluster;
        let kind = if clusters < 4085 {
            Bits::Fat12
        } else if clusters < 65525 {
            Bits::Fat16
        } else {
            Bits::Fat32
        };
        ensure!(
            fat_sectors * bytes_per_sector <= FAT_TABLE_MAX,
            "FAT table too large to follow ({} bytes)",
            fat_sectors * bytes_per_sector
        );
        Ok(Fat {
            bytes_per_sector,
            sectors_per_cluster,
            reserved,
            num_fats,
            root_entries,
            fat_sectors,
            total_sectors,
            root_cluster: le32(&boot, 44) as u32,
            kind,
            data_start: first_data * bytes_per_sector,
            cluster_count: clusters.min(u32::MAX as u64) as u32,
        })
    }

    fn cluster_bytes(&self) -> u64 {
        self.bytes_per_sector * self.sectors_per_cluster
    }

    fn cluster_at(&self, c: u32) -> u64 {
        self.data_start + (c as u64 - 2) * self.cluster_bytes()
    }

    fn read_table(&self, view: &View) -> Result<Vec<u8>> {
        let mut table = vec![0u8; (self.fat_sectors * self.bytes_per_sector) as usize];
        let at = self.reserved * self.bytes_per_sector;
        ensure!(
            view.read_full_at(&mut table, at)? == table.len(),
            "truncated FAT table"
        );
        Ok(table)
    }

    /// The next cluster in a chain, or None at its end (also for the
    /// reserved "bad cluster" values, which end a chain here too).
    fn next(&self, table: &[u8], c: u32) -> Option<u32> {
        let v = match self.kind {
            Bits::Fat12 => {
                let i = (c as usize) + (c as usize) / 2;
                let raw = u16::from_le_bytes([*table.get(i)?, *table.get(i + 1)?]) as u32;
                if c & 1 == 1 {
                    raw >> 4
                } else {
                    raw & 0x0FFF
                }
            }
            Bits::Fat16 => {
                let i = c as usize * 2;
                u16::from_le_bytes([*table.get(i)?, *table.get(i + 1)?]) as u32
            }
            Bits::Fat32 => {
                let i = c as usize * 4;
                u32::from_le_bytes([
                    *table.get(i)?,
                    *table.get(i + 1)?,
                    *table.get(i + 2)?,
                    *table.get(i + 3)?,
                ]) & 0x0FFF_FFFF
            }
        };
        let end = match self.kind {
            Bits::Fat12 => 0x0FF7,
            Bits::Fat16 => 0xFFF7,
            Bits::Fat32 => 0x0FFF_FFF7,
        };
        (v >= 2 && v < end).then_some(v)
    }

    /// A cluster chain as contiguous byte runs. Chains that loop or
    /// run past the data area are refused rather than followed.
    fn chain(&self, table: &[u8], start: u32) -> Result<Vec<(u64, u64)>> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        let (mut cur, mut steps) = (start, 0u64);
        let size = self.cluster_bytes();
        loop {
            ensure!(
                cur >= 2 && (cur - 2) < self.cluster_count.max(1),
                "cluster {cur} outside the data area"
            );
            let at = self.cluster_at(cur);
            match runs.last_mut() {
                Some(last) if last.0 + last.1 == at => last.1 += size,
                _ => runs.push((at, size)),
            }
            steps += 1;
            ensure!(steps <= self.cluster_count as u64, "cluster chain loops");
            match self.next(table, cur) {
                Some(n) => cur = n,
                None => break,
            }
        }
        Ok(runs)
    }

    /// Every file in the tree, with the ranges its bytes occupy, plus
    /// notes for anything skipped (a corrupt subtree is a note, not a
    /// failed walk — the rest of the filesystem is still evidence).
    pub(crate) fn files(&self, view: &View) -> Result<(Vec<FatFile>, Vec<String>)> {
        let table = self.read_table(view)?;
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();
        // FAT12/16 keep the root directory in a fixed region before the
        // data area; FAT32 gives it a cluster chain like any other.
        let root: Vec<(u64, u64)> = if self.kind == Bits::Fat32 {
            self.chain(&table, self.root_cluster)?
        } else {
            let at = (self.reserved + self.num_fats * self.fat_sectors) * self.bytes_per_sector;
            vec![(at, self.root_entries * 32)]
        };
        self.walk_dir(view, &table, &root, "", 0, &mut seen, &mut out, &mut notes)?;
        Ok((out, notes))
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_dir(
        &self,
        view: &View,
        table: &[u8],
        runs: &[(u64, u64)],
        prefix: &str,
        depth: usize,
        seen: &mut HashSet<u32>,
        out: &mut Vec<FatFile>,
        notes: &mut Vec<String>,
    ) -> Result<()> {
        if depth >= MAX_DIR_DEPTH {
            notes.push(format!("{prefix}: directory nesting past {MAX_DIR_DEPTH}"));
            return Ok(());
        }
        let mut dir = Vec::new();
        for (at, len) in runs {
            let mut buf = vec![0u8; *len as usize];
            let got = view.read_full_at(&mut buf, *at)?;
            buf.truncate(got);
            dir.extend_from_slice(&buf);
        }
        let mut lfn: Vec<(u8, Vec<u16>)> = Vec::new();
        let mut subdirs: Vec<(String, u32)> = Vec::new();
        for e in dir.chunks_exact(32) {
            match e[0] {
                0x00 => break, // no entry here or after it
                0xE5 => {
                    lfn.clear(); // a deleted entry voids its long name
                    continue;
                }
                _ => {}
            }
            let attr = e[11];
            if attr == 0x0F {
                let mut chars: Vec<u16> = Vec::with_capacity(13);
                for r in [(1usize, 5usize), (14, 6), (28, 2)] {
                    for i in 0..r.1 {
                        chars.push(u16::from_le_bytes([e[r.0 + i * 2], e[r.0 + i * 2 + 1]]));
                    }
                }
                lfn.push((e[0] & 0x3F, chars));
                continue;
            }
            let name = long_name(&mut lfn).unwrap_or_else(|| short_name(e));
            if attr & 0x08 != 0 || name.is_empty() || name == "." || name == ".." {
                continue; // volume label, or the self/parent links
            }
            let start = ((le16(e, 20) << 16) | le16(e, 26)) as u32;
            let size = le32(e, 28);
            if attr & 0x10 != 0 {
                if start >= 2 && seen.insert(start) {
                    subdirs.push((name, start));
                }
                continue;
            }
            if size == 0 || start < 2 {
                continue; // an empty file has no bytes to point at
            }
            match self.chain(table, start) {
                Ok(runs) => out.push(FatFile {
                    path: format!("{prefix}{name}"),
                    runs: truncate_runs(runs, size),
                }),
                Err(e) => notes.push(format!("{prefix}{name}: {e}")),
            }
        }
        for (name, start) in subdirs {
            let runs = match self.chain(table, start) {
                Ok(r) => r,
                Err(e) => {
                    notes.push(format!("{prefix}{name}/: {e}"));
                    continue;
                }
            };
            self.walk_dir(
                view,
                table,
                &runs,
                &format!("{prefix}{name}/"),
                depth + 1,
                seen,
                out,
                notes,
            )?;
        }
        Ok(())
    }

    /// The filesystem's own length, which an El Torito catalog states
    /// only approximately.
    pub(crate) fn size(&self) -> u64 {
        self.total_sectors * self.bytes_per_sector
    }
}

/// Cluster runs cut down to the file's real length: the last cluster
/// is padding past it, and padding belongs to no file.
fn truncate_runs(runs: Vec<(u64, u64)>, size: u64) -> Vec<(u64, u64)> {
    let mut left = size;
    let mut out = Vec::with_capacity(runs.len());
    for (at, len) in runs {
        if left == 0 {
            break;
        }
        let take = len.min(left);
        out.push((at, take));
        left -= take;
    }
    out
}

/// Assemble the long name whose fragments precede a directory entry.
/// Fragments are stored last-first, so they sort by their ordinal.
fn long_name(parts: &mut Vec<(u8, Vec<u16>)>) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    let mut parts = std::mem::take(parts);
    parts.sort_by_key(|(order, _)| *order);
    let mut units: Vec<u16> = Vec::new();
    for (_, chunk) in parts {
        for u in chunk {
            if u == 0x0000 || u == 0xFFFF {
                break;
            }
            units.push(u);
        }
    }
    let name = String::from_utf16_lossy(&units);
    (!name.is_empty()).then_some(name)
}

/// The 8.3 name, with the case flags DOS never had and everyone uses.
fn short_name(e: &[u8]) -> String {
    let raw = |b: &[u8]| String::from_utf8_lossy(b).trim_end().to_string();
    let mut base = raw(&e[..8]);
    let mut ext = raw(&e[8..11]);
    if e[0] == 0x05 {
        base.replace_range(..1, "\u{e5}"); // 0x05 escapes a leading 0xE5
    }
    if e[12] & 0x08 != 0 {
        base = base.to_lowercase();
    }
    if e[12] & 0x10 != 0 {
        ext = ext.to_lowercase();
    }
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

/// One El Torito boot image: bytes the ISO9660 directory tree does not
/// mention, because the firmware finds them through the boot catalog.
pub(crate) struct BootImage {
    pub(crate) name: &'static str,
    pub(crate) at: u64,
    pub(crate) len: u64,
}

/// Boot images named by an El Torito catalog at `catalog_lba`, plus a
/// note for any entry that had to be left unwalked — a boot image the
/// walk skips silently would read as residue with no explanation.
///
/// The catalog's length field counts 512-byte sectors in 16 bits, so
/// it tops out at 32 MiB and tools that exceed it write zero. When the
/// image turns out to be a filesystem, its own superblock is the
/// better witness of how long it is — and it is the length that
/// decides which bytes a recipe can account for.
pub(crate) fn boot_images(view: &View, catalog_lba: u64) -> Result<(Vec<BootImage>, Vec<String>)> {
    let mut cat = [0u8; 2048];
    ensure!(
        view.read_full_at(&mut cat, catalog_lba * 2048)? == cat.len(),
        "truncated boot catalog"
    );
    ensure!(cat[0] == 0x01, "no El Torito validation entry");
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let mut platform = 0u8;
    for e in cat.chunks_exact(32) {
        match e[0] {
            0x01 | 0x90 | 0x91 => platform = e[1],
            0x88 => {
                let lba = le32(e, 8);
                let stated = le16(e, 6) * 512;
                let at = lba * 2048;
                if at >= view.len() {
                    notes.push(format!(
                        "el-torito boot image at lba {lba}: past the end of the image"
                    ));
                    continue;
                }
                let sub = view.slice(&[(at, view.len() - at)]);
                let len = match Fat::open(&sub) {
                    Ok(fs) if fs.size() >= stated && at + fs.size() <= view.len() => fs.size(),
                    _ => stated,
                };
                if len == 0 || at + len > view.len() {
                    // A non-filesystem image longer than the catalog's
                    // 16-bit sector count (which wraps to zero) has no
                    // other witness of its length.
                    notes.push(format!(
                        "el-torito boot image at lba {lba}: catalog states {stated} bytes \
                         and the image names no length of its own — left unwalked"
                    ));
                    continue;
                }
                out.push(BootImage {
                    name: match platform {
                        0xEF => "efi.img",
                        _ => "boot.img",
                    },
                    at,
                    len,
                });
            }
            _ => {}
        }
    }
    Ok((out, notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BPB guard admits a real boot sector and turns away the
    /// things that merely end in 0x55AA.
    #[test]
    fn sniffing_wants_the_whole_bpb() {
        let mut boot = vec![0u8; 512];
        boot[0] = 0xEB;
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 4;
        boot[14..16].copy_from_slice(&1u16.to_le_bytes());
        boot[16] = 2;
        boot[21] = 0xF8;
        boot[54..62].copy_from_slice(b"FAT16   ");
        boot[510] = 0x55;
        boot[511] = 0xAA;
        assert!(looks_like(&boot));

        let mut mbr = vec![0u8; 512];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        assert!(!looks_like(&mbr), "an MBR signature is not a filesystem");

        let mut odd = boot.clone();
        odd[13] = 3; // clusters are a power of two of sectors
        assert!(!looks_like(&odd));
        let mut nofat = boot.clone();
        nofat[54..62].copy_from_slice(b"NTFS    ");
        assert!(!looks_like(&nofat));
    }

    /// Long names are stored last fragment first; the assembled name
    /// follows the ordinals, and stops at the padding.
    #[test]
    fn long_names_assemble_in_ordinal_order() {
        let mut parts = vec![
            (2u8, vec![b'i' as u16, b'n' as u16, 0xFFFF]),
            (1u8, "grubx64.".encode_utf16().collect::<Vec<u16>>()),
        ];
        assert_eq!(long_name(&mut parts).as_deref(), Some("grubx64.in"));
        assert!(parts.is_empty(), "fragments are consumed");
        assert_eq!(long_name(&mut Vec::new()), None);
    }

    /// A file's last cluster is padding past its length.
    #[test]
    fn runs_stop_at_the_file_length() {
        let runs = truncate_runs(vec![(4096, 4096), (16384, 4096)], 5000);
        assert_eq!(runs, vec![(4096, 4096), (16384, 904)]);
    }

    /// 8.3 names carry the case flags every modern tool writes.
    #[test]
    fn short_names_honour_case_flags() {
        let mut e = [0x20u8; 32];
        e[..8].copy_from_slice(b"GRUBX64 ");
        e[8..11].copy_from_slice(b"EFI");
        e[11] = 0x20;
        e[12] = 0x08 | 0x10;
        assert_eq!(short_name(&e), "grubx64.efi");
        e[12] = 0;
        assert_eq!(short_name(&e), "GRUBX64.EFI");
    }
}
