//! FileObject → path cache, and Kernel-File events → `RawEvent`.
//!
//! windows.md §2.2. Read, Write, and Close carry a `FileObject` and no path.
//! The path arrives on Create (event 12) or NameCreate (event 10), so this
//! module keeps a map and joins them.
//!
//! The key is `(FileObject, Create time)`. A `FileObject` address is reused
//! after Close (windows.md §6), so the address alone would join a new file
//! onto the previous path. Close removes the row.
//!
//! The process that issued the Create owns the `FileObject`. A later Write
//! whose header PID is System (PID 4) is attributed to that process, and the
//! field evidence says so. windows.md §2.2 marks this 【待验证 SPIKE-02】.
//! The attribution is still recorded: the alternative is to drop the write.
//!
//! Device paths are rewritten with a caller-supplied volume map. This module
//! does not call `QueryDosDeviceW` and does not open a process handle
//! (`NtQueryObject` is forbidden by the task card). A path that does not match
//! any volume stays as the kernel wrote it, with `path_resolved = false`.
//!
//! Read and write byte counts come from [`crate::etw::file::IoTally`]. They are
//! emitted once, on Close, not once per event.

use std::collections::HashMap;

use aw_core::{
    EventKind, Evidence, FileAccessMode, FileClose, FileCreate, FileDelete, FileOpen, FileRead,
    FileRename, FileWrite, Gap, GapKind, NaReason, ProcRef, ProcUid, RawEvent, Source,
    SCHEMA_VERSION,
};

use crate::etw::file::{
    self, disposition_creates, disposition_truncates, unavailable, FileOp, FileProperties, IoTally,
    FILE_DIRECTORY_FILE, PID_SYSTEM,
};
use crate::etw::process::DecodeClock;

/// Default cap on the FileObject map. The task card says 200_000.
pub const DEFAULT_CACHE_CAP: usize = 200_000;

/// `\Device\Mup\` prefix. A path under it is a UNC path (windows.md §2.2).
const DEVICE_MUP: &str = "\\Device\\Mup\\";

/// One volume the caller resolved with `QueryDosDeviceW`.
///
/// `device` is the kernel form without a trailing slash, for example
/// `\Device\HarddiskVolume3`. `drive` is the DOS form without a trailing
/// slash, for example `C:`. This module does not query the mapping itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeMapping {
    /// Kernel device path, no trailing slash.
    pub device: String,
    /// DOS drive, no trailing slash (`C:`).
    pub drive: String,
}

/// Key of one open file. `create_mono_ns` is the Create event's monotonic time,
/// so a reused `FileObject` address does not collide with the previous file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileKey {
    /// `FileObject` pointer.
    pub file_object: u64,
    /// Monotonic nanoseconds of the Create that opened it.
    pub create_mono_ns: u64,
}

/// One cached file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedFile {
    /// Key, repeated so a lookup by address can still hand back the full key.
    pub key: FileKey,
    /// Process that issued the Create. Later I/O is attributed here.
    pub owner_pid: u32,
    /// `ProcUid` of that process, when the caller could compute one.
    pub owner_uid: Option<ProcUid>,
    /// Thread of the Create, when the event had one.
    pub tid: Option<u32>,
    /// Path after volume substitution. The kernel form when no volume matched.
    pub path: String,
    /// `true` when the path is a drive letter or a UNC path, not a device path.
    pub path_resolved: bool,
    /// `FileKey` property, when the Create carried one. Read/Write name it too.
    pub file_key: Option<u64>,
    /// Last time this row was touched, in the caller's monotonic clock.
    ///
    /// Eviction drops the smallest value. This is use-order, not a wall clock.
    pub last_used_ns: u64,
}

/// What an eviction produced, so the caller can write a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eviction {
    /// How many rows were removed.
    pub count: u64,
    /// Monotonic time of the oldest removed row's last use.
    pub from_mono_ns: u64,
    /// Monotonic time the eviction happened at.
    pub to_mono_ns: u64,
}

/// FileObject map.
///
/// Lookups by address return the row whose `create_mono_ns` is the latest, and
/// only when that row is still open. Close deletes the row. The cap is
/// [`DEFAULT_CACHE_CAP`] unless the caller sets another.
#[derive(Debug)]
pub struct FileObjectMap {
    by_object: HashMap<u64, Vec<CachedFile>>,
    len: usize,
    cap: usize,
    /// Rows dropped because the cap was hit, since the last [`Self::take_eviction`].
    pending_eviction: Option<Eviction>,
}

impl FileObjectMap {
    /// Empty map with the default cap.
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_CACHE_CAP)
    }

    /// Empty map that evicts past `cap` rows. `cap == 0` is raised to 1: a map
    /// that cannot hold the row just inserted would drop every create.
    pub fn with_cap(cap: usize) -> Self {
        Self {
            by_object: HashMap::new(),
            len: 0,
            cap: cap.max(1),
            pending_eviction: None,
        }
    }

    /// How many rows are stored.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` when nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The cap.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Insert `file`. Returns the eviction, when inserting past the cap dropped
    /// older rows.
    ///
    /// A row with the same `(FileObject, create_mono_ns)` replaces the previous
    /// one and does not grow the map.
    pub fn insert(&mut self, file: CachedFile) -> Option<Eviction> {
        let object = file.key.file_object;
        let created = file.key.create_mono_ns;
        let bucket = self.by_object.entry(object).or_default();
        if let Some(existing) = bucket
            .iter_mut()
            .find(|row| row.key.create_mono_ns == created)
        {
            *existing = file;
            return None;
        }
        bucket.push(file);
        self.len += 1;
        self.evict_if_needed()
    }

    /// The open row for `file_object` whose Create is the latest, and not later
    /// than `at_mono_ns`.
    ///
    /// A Create that happens after the event being joined is not this file.
    /// Touching the row refreshes its eviction order.
    pub fn touch(&mut self, file_object: u64, at_mono_ns: u64) -> Option<&CachedFile> {
        let bucket = self.by_object.get_mut(&file_object)?;
        let index = bucket
            .iter()
            .enumerate()
            .filter(|(_, row)| row.key.create_mono_ns <= at_mono_ns)
            .max_by_key(|(_, row)| row.key.create_mono_ns)
            .map(|(index, _)| index)?;
        let row = &mut bucket[index];
        row.last_used_ns = at_mono_ns;
        Some(row)
    }

    /// Remove the latest open row for `file_object` at `at_mono_ns`.
    pub fn remove(&mut self, file_object: u64, at_mono_ns: u64) -> Option<CachedFile> {
        let bucket = self.by_object.get_mut(&file_object)?;
        let index = bucket
            .iter()
            .enumerate()
            .filter(|(_, row)| row.key.create_mono_ns <= at_mono_ns)
            .max_by_key(|(_, row)| row.key.create_mono_ns)
            .map(|(index, _)| index)?;
        let row = bucket.remove(index);
        if bucket.is_empty() {
            self.by_object.remove(&file_object);
        }
        self.len -= 1;
        Some(row)
    }

    /// Take the eviction accumulated since the last call.
    pub fn take_eviction(&mut self) -> Option<Eviction> {
        self.pending_eviction.take()
    }

    fn evict_if_needed(&mut self) -> Option<Eviction> {
        if self.len <= self.cap {
            return None;
        }
        let overflow = self.len - self.cap;
        let mut victims: Vec<(u64, u64, u64)> = Vec::with_capacity(overflow);
        for bucket in self.by_object.values() {
            for row in bucket {
                let candidate = (
                    row.last_used_ns,
                    row.key.file_object,
                    row.key.create_mono_ns,
                );
                if victims.len() < overflow {
                    victims.push(candidate);
                    victims.sort_unstable();
                } else if victims.last().is_some_and(|last| candidate < *last) {
                    victims.pop();
                    let pos = victims.partition_point(|item| *item < candidate);
                    victims.insert(pos, candidate);
                }
            }
        }
        let mut from = u64::MAX;
        let mut to = 0u64;
        let mut removed = 0u64;
        for (used, object, created) in victims {
            if let Some(bucket) = self.by_object.get_mut(&object) {
                let before = bucket.len();
                bucket.retain(|row| row.key.create_mono_ns != created);
                let gone = before - bucket.len();
                if gone > 0 {
                    if bucket.is_empty() {
                        self.by_object.remove(&object);
                    }
                    self.len -= gone;
                    removed += gone as u64;
                    from = from.min(used);
                    to = to.max(used);
                }
            }
        }
        if removed == 0 {
            return None;
        }
        let eviction = Eviction {
            count: removed,
            from_mono_ns: from,
            to_mono_ns: to,
        };
        self.pending_eviction = Some(match self.pending_eviction {
            Some(prev) => Eviction {
                count: prev.count.saturating_add(eviction.count),
                from_mono_ns: prev.from_mono_ns.min(eviction.from_mono_ns),
                to_mono_ns: prev.to_mono_ns.max(eviction.to_mono_ns),
            },
            None => eviction,
        });
        Some(eviction)
    }
}

impl Default for FileObjectMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Volume map used to rewrite `\Device\...` paths.
///
/// The caller fills it (from `QueryDosDeviceW`, on a volume-change notice, or
/// on a timer). This type does not call Win32. An empty map leaves device
/// paths untouched and reports them unresolved.
#[derive(Debug, Clone, Default)]
pub struct VolumeMap {
    volumes: Vec<VolumeMapping>,
}

impl VolumeMap {
    /// Empty map. No device path resolves.
    pub fn new() -> Self {
        Self {
            volumes: Vec::new(),
        }
    }

    /// Replace the whole table. Entries are matched longest-device-first so
    /// `\Device\HarddiskVolume10` wins over `\Device\HarddiskVolume1`.
    pub fn replace(&mut self, volumes: Vec<VolumeMapping>) {
        let mut volumes = volumes;
        volumes.sort_by_key(|volume| std::cmp::Reverse(volume.device.len()));
        self.volumes = volumes;
    }

    /// Rewrite one kernel path.
    ///
    /// `\Device\Mup\server\share\a` becomes `\\server\share\a`.
    /// `\Device\HarddiskVolume3\dir\a` becomes `C:\dir\a` when the map says so.
    /// Anything else is returned unchanged, with `resolved = false`.
    pub fn rewrite(&self, kernel_path: &str) -> RewrittenPath {
        if let Some(rest) = strip_prefix_ci(kernel_path, DEVICE_MUP) {
            return RewrittenPath {
                path: format!("\\\\{rest}"),
                resolved: true,
                unc: true,
            };
        }
        for volume in &self.volumes {
            if let Some(rest) = strip_device(kernel_path, &volume.device) {
                let drive = volume.drive.trim_end_matches(['\\', '/']);
                return RewrittenPath {
                    path: format!("{drive}{rest}"),
                    resolved: true,
                    unc: false,
                };
            }
        }
        RewrittenPath {
            path: kernel_path.to_owned(),
            resolved: false,
            unc: false,
        }
    }
}

/// A path after [`VolumeMap::rewrite`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewrittenPath {
    /// The path to store.
    pub path: String,
    /// `false` when the kernel path matched no volume and no MUP prefix.
    pub resolved: bool,
    /// `true` when the path came from `\Device\Mup\`.
    pub unc: bool,
}

/// What [`decode_file`] did with one event.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodedFile {
    /// One or more events. A Close emits the aggregated read and write first,
    /// then the close. A Create whose disposition creates emits `FileCreate`
    /// and `FileOpen`.
    Emitted(Vec<RawEvent>),
    /// NameCreate or NameDelete. The cache changed and no event is produced.
    Cached,
    /// A read or a write that was added to the tally. Emitted later, on Close.
    Accumulated,
    /// The id is not in the §2.2 table.
    Ignored { event_id: u16 },
    /// The id is in the table, but the field the cache needs was absent
    /// (`FileObject` on Create, Read, Write, Close). The event is not emitted:
    /// a `FileOpen` with no handle and no path would be a guess. The caller
    /// records a gap from `reason`.
    Undecodable { event_id: u16, reason: &'static str },
}

/// The process a file event is about, when the caller already knows it.
///
/// Kernel-File does not carry the process `CreateTime` (windows.md §2.2), so
/// this module cannot hash a `ProcUid` itself. Hashing the event timestamp
/// would mint a different identity for every event of the same process. The
/// caller passes the identity the process decoder already computed, or `None`
/// when it has not seen that process. `None` leaves `proc` empty and marks it
/// `NA(collector_unavailable)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownProcess {
    /// `ProcUid` from the process cache.
    pub uid: ProcUid,
    /// `CreateTime` is not stored. The uid already commits to it.
    pub pid: u32,
}

/// State both decodes share: the map, the byte tally, and the volume table.
pub struct FileDecoder {
    map: FileObjectMap,
    tally: IoTally,
    volumes: VolumeMap,
}

impl FileDecoder {
    /// Empty cache, empty tally, empty volume map.
    pub fn new() -> Self {
        Self {
            map: FileObjectMap::new(),
            tally: IoTally::new(),
            volumes: VolumeMap::new(),
        }
    }
}

impl Default for FileDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FileDecoder {
    /// Replace the volume table. The caller built it from `QueryDosDeviceW`.
    pub fn set_volumes(&mut self, volumes: Vec<VolumeMapping>) {
        self.volumes.replace(volumes);
    }

    /// The map, for a caller that reads it.
    pub fn map(&self) -> &FileObjectMap {
        &self.map
    }

    /// The tally, for a caller that reads it.
    pub fn tally(&self) -> &IoTally {
        &self.tally
    }

    /// Decode one event.
    ///
    /// `seq` is the caller's counter. It is consumed once per emitted event;
    /// the returned events carry `seq`, `seq + 1`, … in order. A read or write
    /// that only accumulates does not consume it. `clock` is the already
    /// converted header time. This function does not read a clock.
    ///
    /// `process` is the identity of the header PID, from the process cache.
    /// `None` means that cache has not seen the process; `proc` is then `NA`.
    pub fn decode(
        &mut self,
        props: &FileProperties,
        seq: u64,
        clock: DecodeClock,
        process: Option<KnownProcess>,
    ) -> DecodedFile {
        let Some(op) = file::classify(props.event_id) else {
            return DecodedFile::Ignored {
                event_id: props.event_id,
            };
        };
        match op {
            FileOp::NameCreate => self.on_name_create(props, clock, process),
            FileOp::NameDelete => self.on_name_delete(props),
            FileOp::Create => self.on_create(props, seq, clock, process),
            FileOp::CreateNew => self.on_create_new(props, seq, clock, process),
            FileOp::Read => self.on_io(props, false),
            FileOp::Write => self.on_io(props, true),
            FileOp::Close => self.on_close(props, seq, clock, process),
            FileOp::Delete => self.on_delete(props, seq, clock, process),
            FileOp::Rename => self.on_rename(props, seq, clock, process),
        }
    }

    /// Gap for rows the cap evicted since the last call, if any.
    pub fn eviction_gap(&mut self, seq: u64, clock: DecodeClock) -> Option<RawEvent> {
        let eviction = self.map.take_eviction()?;
        Some(cache_evicted_gap(seq, clock, eviction))
    }

    fn on_name_create(
        &mut self,
        props: &FileProperties,
        clock: DecodeClock,
        process: Option<KnownProcess>,
    ) -> DecodedFile {
        // NameCreate carries FileKey and FileName, not FileObject (windows.md
        // §2.2). There is nothing to key a FileObject row on. The name is kept
        // only when a FileObject is also present, which the documented row does
        // not promise. Absent FileObject: the event is cache-only and a no-op.
        let Some(file_object) = props.file_object else {
            return DecodedFile::Cached;
        };
        let Some(pid) = props.pid else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "pid",
            };
        };
        let Some(name) = props.file_name.clone() else {
            return DecodedFile::Cached;
        };
        let rewritten = self.volumes.rewrite(&name);
        let file = CachedFile {
            key: FileKey {
                file_object,
                create_mono_ns: clock.ts_mono_ns,
            },
            owner_pid: pid,
            owner_uid: process
                .filter(|known| known.pid == pid)
                .map(|known| known.uid),
            tid: props.tid,
            path: rewritten.path,
            path_resolved: rewritten.resolved,
            file_key: props.file_key,
            last_used_ns: clock.ts_mono_ns,
        };
        self.map.insert(file);
        DecodedFile::Cached
    }

    fn on_name_delete(&mut self, props: &FileProperties) -> DecodedFile {
        // NameDelete names FileKey, not FileObject. Without a FileObject there
        // is no row to drop. A caller that has both drops the row.
        if let Some(file_object) = props.file_object {
            let _ = self.map.remove(file_object, u64::MAX);
        }
        DecodedFile::Cached
    }

    fn on_create(
        &mut self,
        props: &FileProperties,
        seq: u64,
        clock: DecodeClock,
        process: Option<KnownProcess>,
    ) -> DecodedFile {
        let Some(file_object) = props.file_object else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "file_object",
            };
        };
        let Some(pid) = props.pid else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "pid",
            };
        };
        let rewritten = match &props.file_name {
            Some(name) => self.volumes.rewrite(name),
            None => RewrittenPath {
                path: String::new(),
                resolved: false,
                unc: false,
            },
        };
        let path_missing = props.file_name.is_none();
        let uid = process
            .filter(|known| known.pid == pid)
            .map(|known| known.uid);
        let cached = CachedFile {
            key: FileKey {
                file_object,
                create_mono_ns: clock.ts_mono_ns,
            },
            owner_pid: pid,
            owner_uid: uid,
            tid: props.tid.or(props.issuing_thread_id),
            path: rewritten.path.clone(),
            path_resolved: rewritten.resolved,
            file_key: props.file_key,
            last_used_ns: clock.ts_mono_ns,
        };
        self.map.insert(cached);

        let creates = props.create_disposition.is_some_and(disposition_creates);
        let truncated = props.create_disposition.map(disposition_truncates);
        // `FileCreate.is_dir` is a plain `bool`. Emitting `false` when
        // `CreateOptions` is absent would say "this is a file". The event is
        // emitted only when the bit is present; otherwise the `FileOpen`
        // carries `created = true` and `is_dir` stays unobserved.
        let is_dir = props
            .create_options
            .map(|options| options & FILE_DIRECTORY_FILE != 0);

        let mut out = Vec::new();
        let mut next = seq;
        if creates && !path_missing {
            if let Some(is_dir) = is_dir {
                let mut created = build_event(
                    next,
                    clock,
                    proc_ref(uid, pid, props.tid.or(props.issuing_thread_id)),
                    EventKind::FileCreate(FileCreate::new(rewritten.path.clone(), is_dir)),
                );
                mark_common(&mut created, props, &rewritten, path_missing);
                out.push(created);
                next = next.saturating_add(1);
            }
        }

        let access = access_from_options(props.create_options);
        let mut opened = build_event(
            next,
            clock,
            proc_ref(uid, pid, props.tid.or(props.issuing_thread_id)),
            EventKind::FileOpen(FileOpen::new(
                Some(file_object),
                if path_missing {
                    String::new()
                } else {
                    rewritten.path.clone()
                },
                access,
                Some(creates),
                truncated,
                props.status,
                None,
                rewritten.resolved && !path_missing,
            )),
        );
        mark_common(&mut opened, props, &rewritten, path_missing);
        if path_missing {
            opened.mark_na("path", unavailable());
        }
        if props.create_disposition.is_none() {
            opened.mark_na("created", unavailable());
            opened.mark_na("truncated", unavailable());
        }
        if props.status.is_none() {
            opened.mark_na("result", unavailable());
        }
        if props.create_options.is_none() {
            opened.mark_na("access", unavailable());
        }
        // `via` is not a Kernel-File column. `None` without a marker would read
        // as "ordinary open" rather than "not observed".
        opened.mark_na("via", unavailable());
        if props.share_access.is_some() {
            // Named in §2.2, and `FileOpen` has no slot for it.
            opened.mark_na("share_access", unavailable());
        }
        out.push(opened);
        DecodedFile::Emitted(out)
    }

    fn on_create_new(
        &mut self,
        props: &FileProperties,
        seq: u64,
        clock: DecodeClock,
        process: Option<KnownProcess>,
    ) -> DecodedFile {
        let Some(pid) = props.pid else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "pid",
            };
        };
        let Some(name) = props.file_name.as_deref() else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "file_name",
            };
        };
        let rewritten = self.volumes.rewrite(name);
        // CreateNewFile names FileObject and FileName (windows.md §2.2). When
        // the FileObject is present, remember the path so a later Close joins.
        // The event itself is a FileCreate either way.
        if let Some(file_object) = props.file_object {
            let uid = process
                .filter(|known| known.pid == pid)
                .map(|known| known.uid);
            self.map.insert(CachedFile {
                key: FileKey {
                    file_object,
                    create_mono_ns: clock.ts_mono_ns,
                },
                owner_pid: pid,
                owner_uid: uid,
                tid: props.tid,
                path: rewritten.path.clone(),
                path_resolved: rewritten.resolved,
                file_key: props.file_key,
                last_used_ns: clock.ts_mono_ns,
            });
        }
        let uid = process
            .filter(|known| known.pid == pid)
            .map(|known| known.uid);
        let mut event = build_event(
            seq,
            clock,
            proc_ref(uid, pid, props.tid),
            EventKind::FileCreate(FileCreate::new(rewritten.path.clone(), false)),
        );
        mark_common(&mut event, props, &rewritten, false);
        // CreateNewFile does not carry CreateOptions (windows.md §2.2), so
        // directory-ness is not observable. `is_dir` is a plain `bool` and the
        // constructor takes one; `false` would read as "this is a file". The
        // marker says the bit was not observed.
        event.mark_na("is_dir", unavailable());
        DecodedFile::Emitted(vec![event])
    }

    fn on_io(&mut self, props: &FileProperties, write: bool) -> DecodedFile {
        let Some(pid) = props.pid else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "pid",
            };
        };
        self.tally.add(
            pid,
            props.file_object,
            write,
            props.io_size,
            props.byte_offset,
        );
        if props.file_object.is_none() {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "file_object",
            };
        }
        DecodedFile::Accumulated
    }

    fn on_close(
        &mut self,
        props: &FileProperties,
        seq: u64,
        clock: DecodeClock,
        process: Option<KnownProcess>,
    ) -> DecodedFile {
        let Some(file_object) = props.file_object else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "file_object",
            };
        };
        let cached = self.map.remove(file_object, clock.ts_mono_ns);
        let header_pid = props.pid;
        let (owner_pid, owner_uid, tid, path, resolved) = match &cached {
            Some(row) => (
                row.owner_pid,
                row.owner_uid.or_else(|| {
                    process
                        .filter(|known| Some(known.pid) == header_pid && known.pid == row.owner_pid)
                        .map(|known| known.uid)
                }),
                row.tid.or(props.tid),
                Some(row.path.clone()),
                row.path_resolved,
            ),
            None => (
                header_pid.unwrap_or(0),
                process
                    .filter(|known| Some(known.pid) == header_pid)
                    .map(|known| known.uid),
                props.tid,
                None,
                false,
            ),
        };
        // Cache-manager delayed I/O is attributed to System (windows.md §2.2,
        // 【待验证 SPIKE-02】). The tally row was stored under PID 4. The event
        // is attributed to the Create process, and `proc` is marked
        // `NA(attribution_break)` so the reassignment is not silent.
        let delayed = header_pid == Some(PID_SYSTEM) && cached.is_some() && owner_pid != PID_SYSTEM;
        let totals = if delayed {
            self.tally.take(PID_SYSTEM, file_object)
        } else {
            let header = header_pid.unwrap_or(owner_pid);
            self.tally
                .take(header, file_object)
                .or_else(|| self.tally.take(owner_pid, file_object))
        };

        let mut out = Vec::new();
        let mut next = seq;
        if let Some(totals) = totals {
            if totals.reads > 0 {
                let mut read = build_event(
                    next,
                    clock,
                    proc_ref(owner_uid, owner_pid, tid),
                    EventKind::FileRead(FileRead::new(
                        Some(file_object),
                        path.clone(),
                        totals.bytes_read,
                        totals.read_offset,
                        None,
                    )),
                );
                mark_io(&mut read, &cached, resolved, path.is_none());
                if totals.bytes_read.is_none() {
                    read.mark_na("bytes", unavailable());
                }
                if totals.read_offset.is_none() {
                    read.mark_na("offset", unavailable());
                }
                read.mark_na("via", unavailable());
                if delayed {
                    read.mark_na("proc", NaReason::AttributionBreak);
                }
                out.push(read);
                next = next.saturating_add(1);
            }
            if totals.writes > 0 {
                let mut write = build_event(
                    next,
                    clock,
                    proc_ref(owner_uid, owner_pid, tid),
                    EventKind::FileWrite(FileWrite::new(
                        Some(file_object),
                        path.clone(),
                        totals.bytes_written,
                        totals.write_offset,
                    )),
                );
                mark_io(&mut write, &cached, resolved, path.is_none());
                if totals.bytes_written.is_none() {
                    write.mark_na("bytes", unavailable());
                }
                if totals.write_offset.is_none() {
                    write.mark_na("offset", unavailable());
                }
                if delayed {
                    write.mark_na("proc", NaReason::AttributionBreak);
                }
                out.push(write);
                next = next.saturating_add(1);
            }
        }

        let modified = totals.as_ref().map(|totals| totals.writes > 0);
        let mut closed = build_event(
            next,
            clock,
            proc_ref(owner_uid, owner_pid, tid),
            EventKind::FileClose(FileClose::new(Some(file_object), path.clone(), modified)),
        );
        mark_io(&mut closed, &cached, resolved, path.is_none());
        if modified.is_none() {
            // No write was accumulated, and Close itself does not say. `None`
            // would read as "not modified" if left unmarked. It is "not observed".
            closed.mark_na("modified", unavailable());
        }
        if cached.is_none() {
            closed.mark_na("proc", unavailable());
            if header_pid.is_none() {
                closed.mark_na("pid", unavailable());
            }
        } else if delayed {
            closed.mark_na("proc", NaReason::AttributionBreak);
        }
        out.push(closed);
        DecodedFile::Emitted(out)
    }

    fn on_delete(
        &mut self,
        props: &FileProperties,
        seq: u64,
        clock: DecodeClock,
        process: Option<KnownProcess>,
    ) -> DecodedFile {
        let Some(pid) = props.pid else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "pid",
            };
        };
        let joined = props
            .file_object
            .and_then(|object| self.map.touch(object, clock.ts_mono_ns).cloned());
        let (path, resolved, path_missing) = path_of(props, &joined, &self.volumes);
        if path_missing && joined.is_none() {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "path",
            };
        }
        let uid = joined.as_ref().and_then(|row| row.owner_uid).or_else(|| {
            process
                .filter(|known| known.pid == pid)
                .map(|known| known.uid)
        });
        let owner = joined.as_ref().map(|row| row.owner_pid).unwrap_or(pid);
        let mut event = build_event(
            seq,
            clock,
            proc_ref(uid, owner, props.tid),
            EventKind::FileDelete(FileDelete::new(path, None)),
        );
        if let Some(row) = &joined {
            if !row.path_resolved {
                event.mark_na("path", unavailable());
            }
        } else if !resolved {
            event.mark_na("path", unavailable());
        }
        // DeletePath does not say whether the object is a directory.
        event.mark_na("is_dir", unavailable());
        if joined.is_some() && owner != pid {
            event.mark_na("proc", NaReason::AttributionBreak);
        }
        DecodedFile::Emitted(vec![event])
    }

    fn on_rename(
        &mut self,
        props: &FileProperties,
        seq: u64,
        clock: DecodeClock,
        process: Option<KnownProcess>,
    ) -> DecodedFile {
        let Some(pid) = props.pid else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "pid",
            };
        };
        // §2.2 names one path on RenamePath and calls it the new path. The old
        // path is the cached Create path. When the cache has no row, the old
        // path is unknown and the event is not emitted with an empty `from`.
        let joined = props
            .file_object
            .and_then(|object| self.map.touch(object, clock.ts_mono_ns).cloned());
        let Some(name) = props.file_name.as_deref() else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "file_path",
            };
        };
        let new_path = self.volumes.rewrite(name);
        let old_path = joined.as_ref().map(|row| row.path.clone());
        let Some(from) = old_path else {
            return DecodedFile::Undecodable {
                event_id: props.event_id,
                reason: "old_path",
            };
        };
        let uid = joined.as_ref().and_then(|row| row.owner_uid).or_else(|| {
            process
                .filter(|known| known.pid == pid)
                .map(|known| known.uid)
        });
        let owner = joined.as_ref().map(|row| row.owner_pid).unwrap_or(pid);
        let mut event = build_event(
            seq,
            clock,
            proc_ref(uid, owner, props.tid),
            EventKind::FileRename(FileRename::new(from, new_path.path.clone())),
        );
        if !new_path.resolved {
            event.mark_na("to", unavailable());
        }
        if joined.as_ref().is_some_and(|row| !row.path_resolved) {
            event.mark_na("from", unavailable());
        }
        if owner != pid {
            event.mark_na("proc", NaReason::AttributionBreak);
        }
        // Keep the cache pointing at the new path so a later Close reports it.
        if let Some(object) = props.file_object {
            if let Some(row) = self.map.touch(object, clock.ts_mono_ns) {
                let mut updated = row.clone();
                updated.path = new_path.path;
                updated.path_resolved = new_path.resolved;
                updated.last_used_ns = clock.ts_mono_ns;
                self.map.insert(updated);
            }
        }
        DecodedFile::Emitted(vec![event])
    }
}

fn path_of(
    props: &FileProperties,
    joined: &Option<CachedFile>,
    volumes: &VolumeMap,
) -> (String, bool, bool) {
    if let Some(name) = props.file_name.as_deref() {
        let rewritten = volumes.rewrite(name);
        return (rewritten.path, rewritten.resolved, false);
    }
    match joined {
        Some(row) => (row.path.clone(), row.path_resolved, false),
        None => (String::new(), false, true),
    }
}

fn proc_ref(uid: Option<ProcUid>, pid: u32, tid: Option<u32>) -> Option<ProcRef> {
    uid.map(|uid| ProcRef { uid, pid, tid })
}

fn access_from_options(options: Option<u32>) -> FileAccessMode {
    // Kernel-File Create does not carry a desired-access mask in the §2.2
    // column (it names CreateOptions, CreateAttributes, ShareAccess). The
    // access mode is therefore not derived from a bit this table does not
    // list. `Unknown` plus an NA marker (added by the caller when
    // CreateOptions itself is absent) keeps the field from reading as a
    // measured `read`.
    let _ = options;
    FileAccessMode::Unknown
}

fn build_event(seq: u64, clock: DecodeClock, proc: Option<ProcRef>, kind: EventKind) -> RawEvent {
    let wall_known = clock.ts_wall_ns.is_some();
    let proc_known = proc.is_some();
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns: clock.ts_mono_ns,
        ts_wall_ns: clock.ts_wall_ns.unwrap_or(0),
        session_id: None,
        proc,
        source: file::source(),
        evidence: Evidence::E1,
        field_evidence: std::collections::BTreeMap::new(),
        kind,
    };
    if !wall_known {
        event.mark_na("ts_wall_ns", unavailable());
    }
    if !proc_known {
        event.mark_na("proc", unavailable());
    }
    let _ = event.check();
    event
}

fn mark_common(
    event: &mut RawEvent,
    props: &FileProperties,
    rewritten: &RewrittenPath,
    path_missing: bool,
) {
    if props.pid.is_none() {
        event.mark_na("pid", unavailable());
    }
    if path_missing || !rewritten.resolved {
        event.mark_na("path", unavailable());
    }
    let _ = props.irp;
    let _ = props.file_attributes;
    let _ = props.io_flags;
    let _ = props.extra_info;
}

fn mark_io(event: &mut RawEvent, cached: &Option<CachedFile>, resolved: bool, path_missing: bool) {
    if path_missing || !resolved {
        event.mark_na("path", unavailable());
    }
    if cached.is_none() {
        event.mark_na("file_object_owner", unavailable());
    }
}

fn cache_evicted_gap(seq: u64, clock: DecodeClock, eviction: Eviction) -> RawEvent {
    let gap = Gap::new(
        Source::new(file::SOURCE_KERNEL_FILE),
        GapKind::CacheEvicted,
        vec!["file".to_owned()],
        eviction.from_mono_ns,
        eviction.to_mono_ns,
        Some(eviction.count),
        Some("file_object cache evicted".to_owned()),
    );
    build_event(seq, clock, None, EventKind::Gap(gap))
}

/// `true` when `path` starts with `prefix`, comparing ASCII case-insensitively.
///
/// Device paths are not case-sensitive. The match is on the prefix only; the
/// remainder is returned unchanged.
fn strip_prefix_ci<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let path_bytes = path.as_bytes();
    let prefix_bytes = prefix.as_bytes();
    if path_bytes.len() < prefix_bytes.len() {
        return None;
    }
    let (head, rest) = path.split_at(prefix.len());
    if head.eq_ignore_ascii_case(prefix) {
        Some(rest)
    } else {
        None
    }
}

/// Strip `device` from the front of `path`, requiring a `\` boundary so
/// `HarddiskVolume1` does not match `HarddiskVolume10`.
fn strip_device<'a>(path: &'a str, device: &str) -> Option<&'a str> {
    let rest = strip_prefix_ci(path, device)?;
    if rest.is_empty() {
        return Some("");
    }
    if rest.starts_with('\\') || rest.starts_with('/') {
        Some(rest)
    } else {
        None
    }
}
