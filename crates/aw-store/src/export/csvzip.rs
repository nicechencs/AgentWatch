//! CSV zip. Each P1 table is one stored entry, then `README.txt`.
//!
//! A table is written in two passes over the same pages: the first pass only
//! accumulates CRC-32 and length, the second writes the bytes. Neither pass
//! keeps more than one page. Classic zip32 headers then carry the size, so a
//! reader does not need a data descriptor.
//!
//! Entry timestamps are zero. Method is store (0).

use std::io::Write;

use rusqlite::Connection;

use crate::export::records::{self, csv_header, CsvTable, ExportRecord, PageSource, README};
use crate::export::source::{self, SqlitePages};
use crate::export::{io_err, ExportError, ExportOptions, Redact};

const CRC_TABLE: [u32; 256] = crc_table();

const fn crc_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut crc = !crc;
    for byte in data {
        let index = ((crc ^ u32::from(*byte)) & 0xff) as usize;
        crc = CRC_TABLE[index] ^ (crc >> 8);
    }
    !crc
}

struct CrcSink {
    crc: u32,
    len: u64,
}

impl Write for CrcSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.crc = crc32_update(self.crc, buf);
        self.len += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Entry {
    name: &'static str,
    crc: u32,
    len: u32,
    offset: u32,
}

/// Write one session as a CSV zip into `out`.
pub fn write_csv_zip<W: Write>(
    conn: &Connection,
    options: &ExportOptions<'_>,
    out: &mut W,
) -> Result<u64, ExportError> {
    let loaded = source::load_session(conn, options)?;
    let mut entries = Vec::with_capacity(5);
    let mut records = 0_u64;
    for table in CsvTable::ALL {
        let (entry, rows) = write_table(conn, options, table, loaded.redact, out, &entries)?;
        records = records.saturating_add(rows);
        entries.push(entry);
    }
    let readme = write_readme(out, &entries)?;
    entries.push(readme);
    write_central_directory(out, &entries)?;
    out.flush().map_err(|err| io_err("write_zip", err))?;
    Ok(records)
}

fn write_table<W: Write>(
    conn: &Connection,
    options: &ExportOptions<'_>,
    table: CsvTable,
    redact: Redact,
    out: &mut W,
    written: &[Entry],
) -> Result<(Entry, u64), ExportError> {
    let mut measure = CrcSink { crc: 0, len: 0 };
    let rows = stream_table(conn, options, table, redact, &mut measure)?;
    let len = u32::try_from(measure.len).map_err(|_| ExportError::TooLarge {
        name: table.file_name(),
    })?;
    let offset = current_offset(written)?;
    write_local_header(out, table.file_name(), measure.crc, len)?;
    let rows_again = stream_table(conn, options, table, redact, out)?;
    if rows_again != rows {
        return Err(ExportError::MissingRow {
            table: table.file_name(),
            id: 0,
        });
    }
    Ok((
        Entry {
            name: table.file_name(),
            crc: measure.crc,
            len,
            offset,
        },
        rows,
    ))
}

fn stream_table<W: Write>(
    conn: &Connection,
    options: &ExportOptions<'_>,
    table: CsvTable,
    redact: Redact,
    out: &mut W,
) -> Result<u64, ExportError> {
    let started = source::load_session(conn, options)?.header.started_ns;
    let mut pages = SqlitePages::new(conn, options, started)?;
    pages.only(table.timeline_cat());
    out.write_all(csv_header(table).as_bytes())
        .map_err(|err| io_err("write_csv", err))?;
    let mut rows = 0_u64;
    while let Some(page) = pages.next_page()? {
        for record in &page.records {
            if table_of(record) != table {
                continue;
            }
            records::write_csv_row(out, table, record, redact)?;
            rows = rows.saturating_add(1);
        }
        drop(page);
    }
    Ok(rows)
}

fn table_of(record: &ExportRecord) -> CsvTable {
    match record {
        ExportRecord::Process(_) => CsvTable::Processes,
        ExportRecord::Net(_) => CsvTable::NetFlows,
        ExportRecord::Dns(_) => CsvTable::Dns,
        ExportRecord::Gap(_) => CsvTable::Gaps,
    }
}

fn write_readme<W: Write>(out: &mut W, written: &[Entry]) -> Result<Entry, ExportError> {
    let bytes = README.as_bytes();
    let len =
        u32::try_from(bytes.len()).map_err(|_| ExportError::TooLarge { name: "README.txt" })?;
    let crc = crc32_update(0, bytes);
    let offset = current_offset(written)?;
    write_local_header(out, "README.txt", crc, len)?;
    out.write_all(bytes)
        .map_err(|err| io_err("write_zip", err))?;
    Ok(Entry {
        name: "README.txt",
        crc,
        len,
        offset,
    })
}

fn current_offset(written: &[Entry]) -> Result<u32, ExportError> {
    let mut offset = 0_u64;
    for entry in written {
        let local = 30_u64 + entry.name.len() as u64 + u64::from(entry.len);
        offset += local;
    }
    u32::try_from(offset).map_err(|_| ExportError::TooLarge { name: "zip" })
}

fn write_local_header<W: Write>(
    out: &mut W,
    name: &str,
    crc: u32,
    len: u32,
) -> Result<(), ExportError> {
    let name_len = u16::try_from(name.len()).map_err(|_| ExportError::TooLarge { name: "zip" })?;
    out.write_all(&0x0403_4b50_u32.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&20_u16.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&0_u16.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&0_u16.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&0_u16.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&0_u16.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&crc.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&len.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&len.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&name_len.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&0_u16.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(name.as_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    Ok(())
}

fn write_central_directory<W: Write>(out: &mut W, entries: &[Entry]) -> Result<(), ExportError> {
    let cd_offset = current_offset(entries)?;
    let mut cd_len = 0_u32;
    for entry in entries {
        let name_len =
            u16::try_from(entry.name.len()).map_err(|_| ExportError::TooLarge { name: "zip" })?;
        let before = cd_len;
        out.write_all(&0x0201_4b50_u32.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&20_u16.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&20_u16.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&0_u16.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&0_u16.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&0_u16.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&0_u16.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&entry.crc.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&entry.len.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&entry.len.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&name_len.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&0_u16.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&0_u16.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&0_u16.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&0_u16.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&0_u32.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(&entry.offset.to_le_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        out.write_all(entry.name.as_bytes())
            .map_err(|err| io_err("write_zip", err))?;
        let piece = 46_u32 + u32::from(name_len);
        cd_len = before
            .checked_add(piece)
            .ok_or(ExportError::TooLarge { name: "zip" })?;
    }
    let count = u16::try_from(entries.len()).map_err(|_| ExportError::TooLarge { name: "zip" })?;
    out.write_all(&0x0605_4b50_u32.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&0_u16.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&0_u16.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&count.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&count.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&cd_len.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&cd_offset.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    out.write_all(&0_u16.to_le_bytes())
        .map_err(|err| io_err("write_zip", err))?;
    Ok(())
}
