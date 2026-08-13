//! Positioned byte sources for peek. A `View` is a read-only window
//! onto a seekable source — the root file or a spool — described by a
//! list of byte extents. Views are cheap to clone and read via
//! positional I/O (no shared cursor), so a nested container stored
//! uncompressed inside a seekable parent (squashfs in an iso, a
//! stored zip entry, a tar member) is walked as ranges of the
//! original file with nothing copied anywhere.

use anyhow::{Context, Result};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

/// Threads read a source at absolute offsets (pread semantics), so a
/// single handle serves the walker and every pool worker at once.
pub(crate) enum PSource {
    File(std::fs::File),
    Mem(Arc<[u8]>),
}

impl PSource {
    fn read_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            PSource::File(f) => std::os::unix::fs::FileExt::read_at(f, buf, off),
            #[cfg(windows)]
            PSource::File(f) => std::os::windows::fs::FileExt::seek_read(f, buf, off),
            PSource::Mem(m) => {
                let start = (off.min(m.len() as u64)) as usize;
                let n = buf.len().min(m.len() - start);
                buf[..n].copy_from_slice(&m[start..start + n]);
                Ok(n)
            }
        }
    }
}

/// A logical byte range assembled from extents of a shared source.
/// Implements `Read + Seek + Send`, which is everything the container
/// walkers (tar, zip, squashfs, iso) need.
#[derive(Clone)]
pub(crate) struct View {
    src: Arc<PSource>,
    /// (logical start, source offset, len), logical starts ascending.
    extents: Arc<[(u64, u64, u64)]>,
    len: u64,
    pos: u64,
}

impl View {
    pub(crate) fn new(src: Arc<PSource>, extents: &[(u64, u64)]) -> View {
        let mut mapped = Vec::with_capacity(extents.len());
        let mut logical = 0u64;
        for &(off, len) in extents {
            if len > 0 {
                mapped.push((logical, off, len));
                logical += len;
            }
        }
        View {
            src,
            extents: mapped.into(),
            len: logical,
            pos: 0,
        }
    }

    pub(crate) fn of_file(path: &std::path::Path) -> Result<View> {
        let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let len = f.metadata()?.len();
        Ok(View::new(Arc::new(PSource::File(f)), &[(0, len)]))
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// (logical start, source offset, len) triples, logical ascending.
    pub(crate) fn extents(&self) -> &[(u64, u64, u64)] {
        &self.extents
    }

    /// Identity of the underlying source. Extents are only comparable
    /// between views that share a source — a spool starts a new one.
    pub(crate) fn src_id(&self) -> usize {
        Arc::as_ptr(&self.src) as *const u8 as usize
    }

    /// The same window with the cursor back at the start.
    pub(crate) fn rewound(&self) -> View {
        let mut v = self.clone();
        v.pos = 0;
        v
    }

    /// A sub-window given in THIS view's logical coordinates,
    /// translated down to source extents (so views nest: a file inside
    /// an iso inside a file is still ranges of the root).
    pub(crate) fn slice(&self, ranges: &[(u64, u64)]) -> View {
        let mut out: Vec<(u64, u64)> = Vec::new();
        for &(lo, ln) in ranges {
            let mut want_start = lo.min(self.len);
            let want_end = lo.saturating_add(ln).min(self.len);
            for &(elog, eoff, elen) in self.extents.iter() {
                if want_start >= want_end {
                    break;
                }
                let eend = elog + elen;
                if eend <= want_start || elog >= want_end {
                    continue;
                }
                let from = want_start.max(elog);
                let to = want_end.min(eend);
                out.push((eoff + (from - elog), to - from));
                want_start = to;
            }
        }
        View::new(self.src.clone(), &out)
    }

    /// Best-effort exact read at a logical offset; short only at EOF.
    pub(crate) fn read_full_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
        let mut done = 0;
        while done < buf.len() {
            let n = self.read_at_logical(&mut buf[done..], off + done as u64)?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }

    fn read_at_logical(&self, buf: &mut [u8], pos: u64) -> std::io::Result<usize> {
        if pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        // Find the extent containing pos (last extent with start <= pos).
        let i = self
            .extents
            .partition_point(|&(elog, _, _)| elog <= pos)
            .saturating_sub(1);
        let (elog, eoff, elen) = self.extents[i];
        let within = pos - elog;
        let avail = (elen - within).min(buf.len() as u64) as usize;
        let n = self.src.read_at(&mut buf[..avail], eoff + within)?;
        if n == 0 {
            // The source ended before the extent said it would: report
            // EOF rather than spinning.
            return Ok(0);
        }
        Ok(n)
    }
}

impl Read for View {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.read_at_logical(buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for View {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(o) => Some(o),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        match target {
            Some(t) => {
                self.pos = t;
                Ok(t)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            )),
        }
    }
}

/// Members that need random access but arrive as a stream spool to RAM
/// up to this, then overflow to a temp file on real disk.
pub(crate) const RAM_SPOOL_MAX: u64 = 256 << 20;

/// Drain a stream into a seekable source, handing every byte to `feed`
/// (the member's hash jobs) on the way through.
pub(crate) fn spool_stream(src: &mut dyn Read, mut feed: impl FnMut(&[u8])) -> Result<View> {
    let mut mem: Vec<u8> = Vec::new();
    let mut file: Option<std::fs::File> = None;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        feed(&buf[..n]);
        if let Some(f) = &mut file {
            f.write_all(&buf[..n])?;
        } else {
            mem.extend_from_slice(&buf[..n]);
            if mem.len() as u64 > RAM_SPOOL_MAX {
                // NOT tempfile::tempfile(): std's temp dir is tmpfs on
                // many distros, and a multi-GB spool in tmpfs is a
                // memory bomb. The cache dir is real disk.
                let dir = crate::filter::filters_dir()
                    .parent()
                    .map(|p| p.join("tmp"))
                    .context("no cache dir")?;
                std::fs::create_dir_all(&dir)?;
                let mut f = tempfile::tempfile_in(&dir).context("create spool temp file")?;
                f.write_all(&mem)?;
                mem = Vec::new();
                file = Some(f);
            }
        }
    }
    let (source, len) = match file {
        Some(f) => {
            let len = f.metadata()?.len();
            (PSource::File(f), len)
        }
        None => {
            let len = mem.len() as u64;
            (PSource::Mem(mem.into()), len)
        }
    };
    Ok(View::new(Arc::new(source), &[(0, len)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_view(bytes: &[u8], extents: &[(u64, u64)]) -> View {
        View::new(Arc::new(PSource::Mem(bytes.to_vec().into())), extents)
    }

    fn read_all(mut v: View) -> Vec<u8> {
        let mut out = Vec::new();
        Read::read_to_end(&mut v, &mut out).unwrap();
        out
    }

    /// Slicing translates logical ranges down to source extents, so
    /// nested views (a file inside an iso inside the root) stay
    /// ranges of the original source.
    #[test]
    fn view_slices_translate_through_extents() {
        let src: Vec<u8> = (0u8..=255).collect();
        // Logical space: [10..30) then [50..60) of the source.
        let v = mem_view(&src, &[(10, 20), (50, 10)]);
        assert_eq!(v.len(), 30);
        let mut expect: Vec<u8> = (10u8..30).collect();
        expect.extend(50u8..60);
        assert_eq!(read_all(v.rewound()), expect);

        // A slice spanning the extent seam maps to two source ranges.
        let s = v.slice(&[(15, 10)]);
        assert_eq!(s.len(), 10);
        let mut expect: Vec<u8> = (25u8..30).collect();
        expect.extend(50u8..55);
        assert_eq!(read_all(s.rewound()), expect);

        // Nested slice of a slice still reads the right source bytes.
        let n = s.slice(&[(4, 3)]);
        assert_eq!(read_all(n.rewound()), vec![29, 50, 51]);

        // Out-of-range requests clamp instead of erroring.
        let c = v.slice(&[(25, 100)]);
        assert_eq!(c.len(), 5);
        assert_eq!(read_all(c.rewound()), (55u8..60).collect::<Vec<u8>>());

        // Seek + partial reads through the seam.
        let mut r = v.rewound();
        r.seek(SeekFrom::Start(18)).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(r.read(&mut buf).unwrap(), 2); // to the seam
        assert_eq!(&buf[..2], &[28, 29]);
        assert_eq!(r.read(&mut buf).unwrap(), 4);
        assert_eq!(&buf, &[50, 51, 52, 53]);
    }

    /// read_full_at is stateless and thread-safe — the walker and the
    /// pool read the same view concurrently.
    #[test]
    fn view_positional_reads() {
        let src: Vec<u8> = (0u8..=255).collect();
        let v = mem_view(&src, &[(100, 8), (200, 8)]);
        let mut buf = [0u8; 16];
        assert_eq!(v.read_full_at(&mut buf, 0).unwrap(), 16);
        let mut expect: Vec<u8> = (100u8..108).collect();
        expect.extend(200u8..208);
        assert_eq!(&buf[..], &expect[..]);
        let mut two = [0u8; 2];
        assert_eq!(v.read_full_at(&mut two, 7).unwrap(), 2);
        assert_eq!(two, [107, 200]);
        assert_eq!(v.read_full_at(&mut two, 16).unwrap(), 0);
    }
}
