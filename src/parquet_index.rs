//! Point lookups in parquet files sorted by a key column, generic over
//! any [`ChunkReader`] — an mmap, an in-memory buffer, or HTTP range
//! reads against a published dataset. Row-group footer stats route a
//! key to one ~256K-row group; the sorted key column is scanned with
//! early exit; the requested columns are then page-skipped to the
//! matching rows. No server-side query layer — the sorted layout IS
//! the index.
//!
//! With a page index in the footer, per-page min/max route the scan
//! straight to the first admitting page (or prove absence with no data
//! read at all), and column reads seek by offset index instead of
//! walking page headers.

use anyhow::{Context, Result};
use parquet::column::reader::{get_typed_column_reader, ColumnReaderImpl};
use parquet::data_type::{ByteArrayType, DataType, Int32Type, Int64Type};
use parquet::file::metadata::{ParquetMetaData, RowGroupMetaData};
use parquet::file::page_index::column_index::ColumnIndexMetaData;
use parquet::file::page_index::offset_index::PageLocation;
use parquet::file::reader::ChunkReader;
use parquet::file::serialized_reader::SerializedPageReader;
use parquet::file::statistics::Statistics;
use serde_json::{json, Value};
use std::sync::Arc;

/// Column chunks at or below this arrive as one ranged request instead
/// of a header walk: below ~4 MB one bulk fetch beats a round-trip per
/// skipped page. Only consulted when the footer has no offset index.
const PREFETCH_MAX: u64 = 4 << 20;

pub fn column_index(meta: &ParquetMetaData, name: &str) -> Result<usize> {
    meta.file_metadata()
        .schema_descr()
        .columns()
        .iter()
        .position(|c| c.path().string() == name)
        .with_context(|| format!("column {name} not in parquet schema"))
}

/// Row groups whose footer min/max admit `key` (0 or 1 in practice;
/// 2 when a digest's rows straddle a boundary).
pub fn candidate_row_groups(meta: &ParquetMetaData, col: usize, key: &[u8]) -> Vec<usize> {
    meta.row_groups()
        .iter()
        .enumerate()
        .filter(|(_, rg)| match rg.column(col).statistics() {
            Some(Statistics::ByteArray(s)) => match (s.min_opt(), s.max_opt()) {
                (Some(min), Some(max)) => min.data() <= key && key <= max.data(),
                _ => false,
            },
            _ => false,
        })
        .map(|(i, _)| i)
        .collect()
}

/// Page locations for one column chunk, when the footer carries an
/// offset index. With locations the page reader seeks straight to a
/// page and skips others without any read; without, skipping means
/// walking page headers.
pub fn page_locations(meta: &ParquetMetaData, rgi: usize, col: usize) -> Option<Vec<PageLocation>> {
    Some(
        meta.offset_index()?
            .get(rgi)?
            .get(col)?
            .page_locations()
            .clone(),
    )
}

fn typed_reader<R: ChunkReader + 'static, T: DataType>(
    reader: &Arc<R>,
    rg: &RowGroupMetaData,
    col: usize,
    locations: Option<Vec<PageLocation>>,
) -> Result<ColumnReaderImpl<T>> {
    let pages = SerializedPageReader::new(
        Arc::clone(reader),
        rg.column(col),
        rg.num_rows() as usize,
        locations,
    )?;
    Ok(get_typed_column_reader::<T>(
        parquet::column::reader::get_column_reader(meta_column(rg, col), Box::new(pages)),
    ))
}

fn meta_column(rg: &RowGroupMetaData, col: usize) -> parquet::schema::types::ColumnDescPtr {
    rg.schema_descr().column(col)
}

/// Scan the sorted key column of one row group for `key`: returns the
/// first matching record index and how many match (counting continues
/// past `cap` so "and N more" stays honest, but stops at the group end
/// or first greater value).
///
/// With a page index, per-page min/max route the scan straight to the
/// first admitting page (or prove absence with no data read at all).
/// Without one, the whole key chunk is fetched up front in one ranged
/// request — it gets decoded anyway.
pub fn scan_key_column<R: ChunkReader + 'static>(
    reader: &Arc<R>,
    meta: &ParquetMetaData,
    rgi: usize,
    col: usize,
    key: &[u8],
) -> Result<Option<(usize, usize)>> {
    let rg = meta.row_group(rgi);
    let locations = page_locations(meta, rgi, col);
    let column_index = meta
        .column_index()
        .and_then(|c| c.get(rgi)?.get(col))
        .and_then(|ix| match ix {
            ColumnIndexMetaData::BYTE_ARRAY(ix) => Some(ix),
            _ => None,
        });
    let skip = match (&locations, column_index) {
        (Some(locs), Some(ix)) => {
            // Keys are globally sorted, so admitting pages are
            // contiguous; land on the first.
            let admits = (0..locs.len()).position(|i| {
                matches!((ix.min_value(i), ix.max_value(i)),
                    (Some(mn), Some(mx)) if mn <= key && key <= mx)
            });
            match admits {
                Some(page) => locs[page].first_row_index as usize,
                None => return Ok(None),
            }
        }
        _ => {
            let (start, len) = rg.column(col).byte_range();
            let _ = reader.get_bytes(start, len as usize)?; // warm the range cache
            0
        }
    };
    let mut r = typed_reader::<R, ByteArrayType>(reader, rg, col, locations)?;
    if skip > 0 {
        r.skip_records(skip)?;
    }
    let max_def = meta_column(rg, col).max_def_level();
    let (mut record, mut first, mut count) = (skip, None, 0usize);
    loop {
        let mut vals = Vec::new();
        let mut defs: Vec<i16> = Vec::new();
        // Modest batches: the reader only fetches pages it must, so a
        // small batch keeps the early exit from dragging in pages past
        // the match (in-page state carries across calls).
        let (records, _, _) = r.read_records(256, Some(&mut defs), None, &mut vals)?;
        if records == 0 {
            break;
        }
        // A required column (max_def 0) fills no def levels.
        defs.resize(records, max_def);
        let mut vi = 0;
        for &d in defs.iter().take(records) {
            let val = if d == max_def {
                let v = vals[vi].data();
                vi += 1;
                Some(v)
            } else {
                None
            };
            if let Some(v) = val {
                if v == key {
                    first.get_or_insert(record);
                    count += 1;
                } else if v > key {
                    return Ok(first.map(|f| (f, count)));
                }
            }
            record += 1;
        }
    }
    Ok(first.map(|f| (f, count)))
}

pub enum ColValues {
    Str(Vec<Option<String>>),
    I32(Vec<Option<i32>>),
    I64(Vec<Option<i64>>),
}

/// Read `take` records of one column starting at record `skip`,
/// page-skipping everything before it.
pub fn read_column<R: ChunkReader + 'static>(
    reader: &Arc<R>,
    meta: &ParquetMetaData,
    rgi: usize,
    col: usize,
    skip: usize,
    take: usize,
) -> Result<ColValues> {
    use parquet::basic::Type;
    let rg = meta.row_group(rgi);
    let locations = page_locations(meta, rgi, col);
    let max_def = meta_column(rg, col).max_def_level();
    macro_rules! read {
        ($t:ty, $conv:expr) => {{
            let mut r = typed_reader::<R, $t>(reader, rg, col, locations.clone())?;
            if skip > 0 {
                r.skip_records(skip)?;
            }
            let mut vals = Vec::new();
            let mut defs: Vec<i16> = Vec::new();
            let mut out = Vec::with_capacity(take);
            while out.len() < take {
                vals.clear();
                defs.clear();
                let (records, _, _) =
                    r.read_records(take - out.len(), Some(&mut defs), None, &mut vals)?;
                if records == 0 {
                    break;
                }
                defs.resize(records, max_def); // required cols fill no def levels
                let mut vi = 0;
                for &d in defs.iter().take(records) {
                    if d == max_def {
                        out.push(Some($conv(&vals[vi])));
                        vi += 1;
                    } else {
                        out.push(None);
                    }
                }
            }
            out
        }};
    }
    Ok(match meta_column(rg, col).physical_type() {
        Type::BYTE_ARRAY => {
            ColValues::Str(read!(ByteArrayType, |v: &parquet::data_type::ByteArray| {
                String::from_utf8_lossy(v.data()).into_owned()
            }))
        }
        Type::INT32 => ColValues::I32(read!(Int32Type, |v: &i32| *v)),
        Type::INT64 => ColValues::I64(read!(Int64Type, |v: &i64| *v)),
        t => anyhow::bail!("unsupported column type {t}"),
    })
}

/// One requested column of one row group: optional whole-chunk warm-up
/// (only pays off when there is no offset index to seek by), then the
/// page-skipped read.
fn read_one_column<R: ChunkReader + 'static>(
    reader: &Arc<R>,
    meta: &ParquetMetaData,
    rgi: usize,
    name: &str,
    first: usize,
    take: usize,
) -> Result<ColValues> {
    let cidx = column_index(meta, name)?;
    if meta.offset_index().is_none() {
        let rg = meta.row_group(rgi);
        let (start, len) = rg.column(cidx).byte_range();
        if len <= PREFETCH_MAX {
            let _ = reader.get_bytes(start, len as usize)?;
        }
    }
    read_column(reader, meta, rgi, cidx, first, take)
}

/// One thread per column: each is a chain of ranged reads, so the wall
/// clock is the slowest column, not the sum.
#[cfg(not(target_arch = "wasm32"))]
fn read_columns<'a, R: ChunkReader + 'static>(
    reader: &Arc<R>,
    meta: &ParquetMetaData,
    rgi: usize,
    cols: &[&'a str],
    first: usize,
    take: usize,
) -> Vec<(&'a str, Result<ColValues>)> {
    std::thread::scope(|s| {
        let handles: Vec<_> = cols
            .iter()
            .map(|name| s.spawn(move || read_one_column(reader, meta, rgi, name, first, take)))
            .collect();
        cols.iter()
            .zip(handles)
            .map(|(name, h)| (*name, h.join().expect("column reader panicked")))
            .collect()
    })
}

/// wasm32 has no threads; the driver prefetches ranges up front, so
/// serial decode loses no latency.
#[cfg(target_arch = "wasm32")]
fn read_columns<'a, R: ChunkReader + 'static>(
    reader: &Arc<R>,
    meta: &ParquetMetaData,
    rgi: usize,
    cols: &[&'a str],
    first: usize,
    take: usize,
) -> Vec<(&'a str, Result<ColValues>)> {
    cols.iter()
        .map(|name| (*name, read_one_column(reader, meta, rgi, name, first, take)))
        .collect()
}

/// Read whole rows by absolute row index — the file's row order used
/// as a foreign key from another table (a normalized dataset's ref
/// column). Each index resolves through the row-group row counts,
/// then page-skips to the record; the result keeps `indices` order.
pub fn rows_at<R: ChunkReader + 'static>(
    reader: &Arc<R>,
    meta: &ParquetMetaData,
    cols: &[&str],
    indices: &[u64],
) -> Result<Vec<Value>> {
    let mut out = Vec::with_capacity(indices.len());
    for &idx in indices {
        let (mut rgi, mut rg_start) = (0usize, 0u64);
        loop {
            anyhow::ensure!(
                rgi < meta.num_row_groups(),
                "row index {idx} past end of file"
            );
            let n = meta.row_group(rgi).num_rows() as u64;
            if idx < rg_start + n {
                break;
            }
            rg_start += n;
            rgi += 1;
        }
        let first = (idx - rg_start) as usize;
        let mut obj = serde_json::Map::new();
        for (name, vals) in read_columns(reader, meta, rgi, cols, first, 1) {
            let v = match vals? {
                ColValues::Str(v) => v
                    .first()
                    .and_then(|o| o.as_ref())
                    .map_or(Value::Null, |s| json!(s)),
                ColValues::I32(v) => v.first().and_then(|o| *o).map_or(Value::Null, |n| json!(n)),
                ColValues::I64(v) => v.first().and_then(|o| *o).map_or(Value::Null, |n| json!(n)),
            };
            obj.insert(name.to_string(), v);
        }
        out.push(Value::Object(obj));
    }
    Ok(out)
}

/// Point lookup in a parquet file sorted by `key_col`: rows (as JSON
/// objects of the requested columns) whose key equals `key`, plus the
/// total number of matching rows.
pub fn find_rows<R: ChunkReader + 'static>(
    reader: &Arc<R>,
    meta: &ParquetMetaData,
    key_col: &str,
    cols: &[&str],
    key: &str,
    cap: usize,
) -> Result<(Vec<Value>, usize)> {
    let kidx = column_index(meta, key_col)?;
    let mut rows = Vec::new();
    let mut total = 0usize;
    for rgi in candidate_row_groups(meta, kidx, key.as_bytes()) {
        let Some((first, count)) = scan_key_column(reader, meta, rgi, kidx, key.as_bytes())? else {
            continue;
        };
        total += count;
        let take = count.min(cap.saturating_sub(rows.len()));
        if take == 0 {
            continue;
        }
        let mut objs: Vec<serde_json::Map<String, Value>> = vec![serde_json::Map::new(); take];
        for (name, vals) in read_columns(reader, meta, rgi, cols, first, take) {
            let vals = vals?;
            for (i, obj) in objs.iter_mut().enumerate() {
                let v = match &vals {
                    ColValues::Str(v) => v[i].as_ref().map_or(Value::Null, |s| json!(s)),
                    ColValues::I32(v) => v[i].map_or(Value::Null, |n| json!(n)),
                    ColValues::I64(v) => v[i].map_or(Value::Null, |n| json!(n)),
                };
                obj.insert(name.to_string(), v);
            }
        }
        for mut obj in objs {
            obj.insert(key_col.to_string(), json!(key));
            rows.push(Value::Object(obj));
        }
    }
    Ok((rows, total))
}
