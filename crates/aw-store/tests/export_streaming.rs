//! The JSONL writer must drop a page before it asks for the next one.
//!
//! This does not build a 1e6-row database. Three pages of two gaps each are
//! enough: if the writer kept a previous page alive, `next_page` sees `live > 0`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::Cell;
use std::rc::Rc;

use aw_store::{
    write_jsonl_pages, ExportRecord, GapRecord, GapsSummary, Page, PageSource, Redact,
    SessionHeader,
};

struct CountingSource {
    left: Vec<Vec<ExportRecord>>,
    live: Rc<Cell<usize>>,
}

impl PageSource for CountingSource {
    fn next_page(&mut self) -> Result<Option<Page>, aw_store::ExportError> {
        assert_eq!(
            self.live.get(),
            0,
            "a previous page was still alive when the next page was requested"
        );
        let Some(records) = self.left.pop() else {
            return Ok(None);
        };
        self.live.set(1);
        let live = Rc::clone(&self.live);
        Ok(Some(Page::from_records_with_drop(
            records,
            Box::new(move || live.set(0)),
        )))
    }
}

fn gap(id: i64) -> ExportRecord {
    ExportRecord::Gap(GapRecord {
        id,
        session_id: Some(1),
        collector: "etw".to_string(),
        kind: "lost".to_string(),
        affects: "[\"net\"]".to_string(),
        from_ns: id,
        to_ns: id + 1,
        count: None,
        detail: None,
    })
}

#[test]
fn writer_holds_at_most_one_page() {
    let live = Rc::new(Cell::new(0));
    let mut pages = Vec::new();
    for batch in (0..3).rev() {
        let start = batch * 2;
        pages.push(vec![gap(start + 1), gap(start + 2)]);
    }
    let mut source = CountingSource {
        left: pages,
        live: Rc::clone(&live),
    };
    let header = SessionHeader {
        id: 1,
        public_id: "pub".to_string(),
        name: None,
        mode: "launch".to_string(),
        agent: None,
        started_ns: 0,
        ended_ns: None,
        platform: "windows".to_string(),
        user_id: "user-a".to_string(),
        collectors_json: "[]".to_string(),
    };
    let gaps = GapsSummary {
        rows: 6,
        unknown_count: 6,
        lost: None,
        by_collector: Vec::new(),
    };
    let mut buf = Vec::new();
    let n = write_jsonl_pages(
        &header,
        &gaps,
        &mut source,
        Redact {
            paths: false,
            hosts: false,
        },
        &mut buf,
    )
    .unwrap();
    assert_eq!(n, 6);
    assert_eq!(live.get(), 0);
    assert_eq!(String::from_utf8(buf).unwrap().lines().count(), 7);
}
