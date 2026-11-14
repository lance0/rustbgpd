//! Bounded snapshot encoding and disk sorting of EVPN records.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use rustbgpd_wire::EvpnRouteKey;

use crate::codec::{StreamEncodeError, StreamingEncoder, evpn_record_sort_key};
use crate::types::{MrtPeerEntry, MrtSnapshotChunk, MrtWriterConfig};
use crate::writer::{StreamingDump, check_cancelled};

/// A single record must fit in this scratch buffer; file size is not capped.
pub(crate) const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
/// Each merge retains at most this many bounded records and reader buffers.
const MERGE_FAN_IN: usize = 8;

type EvpnSortKey = (u16, EvpnRouteKey);

pub(crate) struct StreamingSnapshot {
    output: StreamingDump,
    encoder: StreamingEncoder,
    runs: EvpnRuns,
    cancelled: Arc<AtomicBool>,
}

impl StreamingSnapshot {
    pub(crate) fn new(
        config: &MrtWriterConfig,
        collector: Ipv4Addr,
        timestamp: u32,
        peers: &[MrtPeerEntry],
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, StreamEncodeError> {
        check_cancelled(&cancelled)?;
        let mut encoder = StreamingEncoder::new(collector, peers, timestamp, MAX_RECORD_BYTES)?;
        let mut output = StreamingDump::new(config)?;
        encoder.write_peer_index(&mut CancelWriter::new(&mut output, &cancelled))?;
        Ok(Self {
            output,
            encoder,
            runs: EvpnRuns::default(),
            cancelled,
        })
    }

    #[cfg(test)]
    pub(crate) fn fix_originated_time(&mut self, originated: u32) {
        self.encoder.fix_originated_time(originated);
    }

    pub(crate) fn push(&mut self, chunk: &MrtSnapshotChunk) -> Result<(), StreamEncodeError> {
        check_cancelled(&self.cancelled)?;
        self.encoder.write_unicast(
            &chunk.routes,
            &mut CancelWriter::new(&mut self.output, &self.cancelled),
        )?;
        if chunk.evpn_routes.is_empty() {
            return Ok(());
        }

        // Slots supply bounded actor work, while disk runs preserve the existing
        // peer-index/key byte order without retaining the full EVPN table.
        let mut ordered = chunk
            .evpn_routes
            .iter()
            .map(|route| Ok(((self.encoder.peer_index(route.peer)?, route.key()), route)))
            .collect::<Result<Vec<_>, crate::codec::EncodeError>>()?;
        ordered.sort_by_key(|(key, _)| *key);
        let mut file = BufWriter::new(self.output.create_run()?);
        let mut last = None;
        for (key, route) in ordered {
            check_cancelled(&self.cancelled)?;
            if last == Some(key) {
                continue;
            }
            let (_, record) = self.encoder.encode_evpn(route)?;
            file.write_all(record)?;
            last = Some(key);
        }
        let file = file.into_inner().map_err(io::IntoInnerError::into_error)?;
        self.runs.push(file, &mut self.output, &self.cancelled)?;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<(std::path::PathBuf, u64), StreamEncodeError> {
        let mut sequence = self.encoder.next_sequence();
        self.runs
            .finish(&mut self.output, &mut sequence, &self.cancelled)?;
        Ok(self.output.finish(&self.cancelled)?)
    }
}

struct CancelWriter<'a, W> {
    writer: &'a mut W,
    cancelled: &'a AtomicBool,
}

impl<'a, W> CancelWriter<'a, W> {
    fn new(writer: &'a mut W, cancelled: &'a AtomicBool) -> Self {
        Self { writer, cancelled }
    }
}

impl<W: Write> Write for CancelWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        check_cancelled(self.cancelled)?;
        self.writer.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        check_cancelled(self.cancelled)?;
        self.writer.flush()
    }
}

struct SortRun {
    file: File,
    /// Runs cover disjoint observation intervals; older observations win ties.
    first: u64,
}

#[derive(Default)]
struct EvpnRuns {
    /// At most seven runs at each level, as in a base-eight counter. Open
    /// descriptors grow logarithmically, and each merge has a fixed fan-in.
    levels: Vec<Vec<SortRun>>,
    next: u64,
}

impl EvpnRuns {
    fn push(
        &mut self,
        file: File,
        output: &mut StreamingDump,
        cancelled: &AtomicBool,
    ) -> io::Result<()> {
        let mut run = SortRun {
            file,
            first: self.next,
        };
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("MRT sort run counter exhausted"))?;
        let mut level = 0;
        loop {
            if self.levels.len() == level {
                self.levels.push(Vec::new());
            }
            let runs = &mut self.levels[level];
            runs.push(run);
            if runs.len() < MERGE_FAN_IN {
                return Ok(());
            }
            let first = runs[0].first;
            let mut merged = BufWriter::new(output.create_run()?);
            merge_runs(std::mem::take(runs), &mut merged, None, cancelled)?;
            run = SortRun {
                file: merged
                    .into_inner()
                    .map_err(io::IntoInnerError::into_error)?,
                first,
            };
            level += 1;
        }
    }

    fn finish(
        self,
        output: &mut StreamingDump,
        sequence: &mut u32,
        cancelled: &AtomicBool,
    ) -> io::Result<()> {
        let mut runs: Vec<_> = self.levels.into_iter().flatten().collect();
        runs.sort_by_key(|run| run.first);
        // Compact the final uneven levels before the final bounded merge.
        while runs.len() > MERGE_FAN_IN {
            let mut remaining = runs.split_off(MERGE_FAN_IN);
            let first = runs[0].first;
            let mut merged = BufWriter::new(output.create_run()?);
            merge_runs(runs, &mut merged, None, cancelled)?;
            remaining.insert(
                0,
                SortRun {
                    file: merged
                        .into_inner()
                        .map_err(io::IntoInnerError::into_error)?,
                    first,
                },
            );
            runs = remaining;
        }
        merge_runs(runs, output, Some(sequence), cancelled)
    }
}

struct RunReader {
    reader: BufReader<File>,
    record: Vec<u8>,
}

impl RunReader {
    fn new(mut file: File) -> io::Result<Self> {
        file.seek(SeekFrom::Start(0))?;
        Ok(Self {
            reader: BufReader::new(file),
            record: Vec::new(),
        })
    }

    fn next(&mut self) -> io::Result<Option<EvpnSortKey>> {
        let mut header = [0; 12];
        if self.reader.read(&mut header[..1])? == 0 {
            return Ok(None);
        }
        self.reader.read_exact(&mut header[1..])?;
        let payload = u32::from_be_bytes(header[8..12].try_into().expect("fixed MRT length field"));
        let length = usize::try_from(payload)
            .ok()
            .and_then(|n| n.checked_add(12))
            .filter(|&n| n <= MAX_RECORD_BYTES)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MRT sort record exceeds byte cap",
                )
            })?;
        if self.record.capacity() < length {
            self.record
                .try_reserve_exact(length - self.record.len())
                .map_err(|error| {
                    io::Error::other(format!("MRT sort record allocation failed: {error}"))
                })?;
        }
        self.record.resize(length, 0);
        self.record[..12].copy_from_slice(&header);
        self.reader.read_exact(&mut self.record[12..])?;
        evpn_record_sort_key(&self.record).map(Some)
    }
}

fn merge_runs(
    mut runs: Vec<SortRun>,
    writer: &mut impl Write,
    mut sequence: Option<&mut u32>,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    debug_assert!(runs.len() <= MERGE_FAN_IN);
    runs.sort_by_key(|run| run.first);
    let mut readers = runs
        .into_iter()
        .map(|run| RunReader::new(run.file))
        .collect::<io::Result<Vec<_>>>()?;
    let mut heap = BinaryHeap::new();
    for (index, reader) in readers.iter_mut().enumerate() {
        check_cancelled(cancelled)?;
        if let Some(key) = reader.next()? {
            heap.push(Reverse((key, index)));
        }
    }
    let mut last = None;
    while let Some(Reverse((key, index))) = heap.pop() {
        check_cancelled(cancelled)?;
        let reader = &mut readers[index];
        if last != Some(key) {
            if let Some(sequence) = sequence.as_deref_mut() {
                reader.record[12..16].copy_from_slice(&sequence.to_be_bytes());
                *sequence = sequence.wrapping_add(1);
            }
            writer.write_all(&reader.record)?;
            last = Some(key);
        }
        if let Some(next) = reader.next()? {
            if next < key {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MRT sort run is out of order",
                ));
            }
            heap.push(Reverse((next, index)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::IpAddr;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    use rustbgpd_rib::route::{EvpnRibRoute, RouteOrigin};
    use rustbgpd_rib::{AttrSet, PeerId};
    use rustbgpd_wire::{
        EthernetTagId, EvpnImet, EvpnRoute, Origin, PathAttribute, RouteDistinguisher,
    };

    use super::*;
    use crate::codec::encode_snapshot_with_allocation_diagnostics;
    use crate::reader::SnapshotReader;
    use crate::writer::private_tempdir;

    const TIMESTAMP: u32 = 1_700_000_000;

    fn config(dir: &Path, compress: bool) -> MrtWriterConfig {
        MrtWriterConfig {
            output_dir: dir.to_path_buf(),
            dump_interval: 3600,
            compress,
            file_prefix: "rib".to_owned(),
            max_files: None,
            ancestor_check: None,
        }
    }

    fn peers() -> [MrtPeerEntry; 2] {
        [1, 2].map(|last| {
            let addr = Ipv4Addr::new(192, 0, 2, last);
            MrtPeerEntry {
                peer: PeerId::from_addr(IpAddr::V4(addr)),
                peer_addr: IpAddr::V4(addr),
                interface: None,
                peer_bgp_id: addr,
                peer_asn: 65_000 + u32::from(last),
            }
        })
    }

    fn route(peer: &MrtPeerEntry, key: u8, marker: u32) -> EvpnRibRoute {
        EvpnRibRoute {
            route: EvpnRoute::Imet(EvpnImet {
                rd: RouteDistinguisher([0; 8]),
                ethernet_tag: EthernetTagId(0),
                originator_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, key)),
            }),
            next_hop: peer.peer_addr,
            link_local_next_hop: None,
            peer: peer.peer,
            attributes: AttrSet::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::Med(marker),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: peer.peer_bgp_id,
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    fn fixture(peer_index: u16, key: u8, marker: u32) -> (EvpnSortKey, Vec<u8>) {
        let peers = peers();
        let route = route(&peers[usize::from(peer_index)], key, marker);
        let key = (peer_index, route.key());
        let (snapshot, _) = encode_snapshot_with_allocation_diagnostics(
            Ipv4Addr::LOCALHOST,
            &peers,
            &[],
            &[route],
            TIMESTAMP,
            TIMESTAMP - 30,
        )
        .unwrap();
        let peer_table_length =
            usize::try_from(u32::from_be_bytes(snapshot[8..12].try_into().unwrap())).unwrap();
        (key, snapshot[12 + peer_table_length..].to_vec())
    }

    fn run_file(bytes: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    fn read_dump(path: &Path, compress: bool) -> Vec<u8> {
        let bytes = std::fs::read(path).unwrap();
        if compress {
            let mut plain = Vec::new();
            flate2::read::GzDecoder::new(bytes.as_slice())
                .read_to_end(&mut plain)
                .unwrap();
            plain
        } else {
            bytes
        }
    }

    #[test]
    fn multilevel_disk_merge_preserves_first_records_and_exact_bytes_with_gzip() {
        for compress in [false, true] {
            let dir = private_tempdir();
            let mut output = StreamingDump::new(&config(dir.path(), compress)).unwrap();
            let cancelled = AtomicBool::new(false);
            let mut runs = EvpnRuns::default();
            let mut expected = BTreeMap::new();
            // 127 leaves force merges beyond 64 runs and an uneven final merge.
            for ordinal in 0..127_u8 {
                let mut records = vec![
                    fixture(u16::from(ordinal % 2), 126 - ordinal, u32::from(ordinal)),
                    fixture(0, 250, u32::from(ordinal)),
                    fixture(1, 250, u32::from(ordinal)),
                    fixture(0, 250, 1000 + u32::from(ordinal)),
                ];
                records.sort_by_key(|(key, _)| *key);
                let mut file = output.create_run().unwrap();
                for (key, record) in records {
                    file.write_all(&record).unwrap();
                    expected.entry(key).or_insert(record);
                }
                runs.push(file, &mut output, &cancelled).unwrap();
            }
            let mut sequence = 17_u32;
            let mut expected_bytes = Vec::new();
            for (offset, mut record) in expected.into_values().enumerate() {
                let expected_sequence = 17 + u32::try_from(offset).unwrap();
                record[12..16].copy_from_slice(&expected_sequence.to_be_bytes());
                expected_bytes.extend_from_slice(&record);
            }
            runs.finish(&mut output, &mut sequence, &cancelled).unwrap();
            let (path, bytes_written) = output.finish(&cancelled).unwrap();
            assert_eq!(sequence, 17 + 129);
            assert_eq!(read_dump(&path, compress), expected_bytes);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), bytes_written);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn run_reader_rejects_partial_malformed_and_oversized_records() {
        let (_, record) = fixture(0, 1, 7);
        let mut empty = RunReader::new(run_file(&[])).unwrap();
        assert!(empty.next().unwrap().is_none());
        for length in 1..record.len() {
            let mut reader = RunReader::new(run_file(&record[..length])).unwrap();
            assert_eq!(
                reader.next().unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof,
                "truncation at {length}"
            );
        }
        for offset in [4, 6, 16, 18] {
            let mut malformed = record.clone();
            malformed[offset] ^= 1;
            let mut reader = RunReader::new(run_file(&malformed)).unwrap();
            assert_eq!(
                reader.next().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut oversized = record[..12].to_vec();
        oversized[8..12]
            .copy_from_slice(&u32::try_from(MAX_RECORD_BYTES - 11).unwrap().to_be_bytes());
        let mut reader = RunReader::new(run_file(&oversized)).unwrap();
        assert_eq!(
            reader.next().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(reader.record, [] as [u8; 0]);
        assert_eq!(
            reader.record.capacity(),
            0,
            "reject before payload allocation"
        );

        let mut trailing_partial = record.clone();
        trailing_partial.extend_from_slice(&record[..7]);
        let mut reader = RunReader::new(run_file(&trailing_partial)).unwrap();
        assert!(reader.next().unwrap().is_some());
        assert_eq!(
            reader.next().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn merge_rejects_descending_run_before_publishing() {
        let dir = private_tempdir();
        let mut output = StreamingDump::new(&config(dir.path(), false)).unwrap();
        let bytes = [fixture(0, 2, 7).1, fixture(0, 1, 8).1].concat();
        let error = merge_runs(
            vec![SortRun {
                file: run_file(&bytes),
                first: 0,
            }],
            &mut output,
            Some(&mut 0),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        drop(output);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn streaming_chunks_keep_first_duplicate_and_publish_readable_snapshot() {
        for compress in [false, true] {
            let dir = private_tempdir();
            let peers = peers();
            let mut snapshot = StreamingSnapshot::new(
                &config(dir.path(), compress),
                Ipv4Addr::LOCALHOST,
                TIMESTAMP,
                &peers,
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
            for routes in [
                vec![
                    route(&peers[1], 9, 90),
                    route(&peers[0], 2, 20),
                    route(&peers[0], 2, 21),
                ],
                vec![route(&peers[0], 2, 22), route(&peers[0], 1, 10)],
            ] {
                snapshot
                    .push(&MrtSnapshotChunk {
                        evpn_routes: routes,
                        ..MrtSnapshotChunk::default()
                    })
                    .unwrap();
            }
            let (path, _) = snapshot.finish().unwrap();
            let bytes = read_dump(&path, compress);
            let rows = SnapshotReader::new(&bytes)
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>();
            assert_eq!(rows.len(), 3);
            for (row, (peer_index, marker)) in rows.iter().zip([(0, 10), (0, 20), (1, 90)]) {
                assert_eq!(row.peer_index, peer_index);
                assert!(row.attributes.contains(&PathAttribute::Med(marker)));
            }
        }
    }

    #[test]
    fn dropped_and_cancelled_snapshots_remove_stages_and_anonymous_runs() {
        for compress in [false, true] {
            for cancel in [false, true] {
                let dir = private_tempdir();
                let sentinel = dir.path().join("keep.mrt");
                std::fs::write(&sentinel, b"existing dump").unwrap();
                let peers = peers();
                let cancelled = Arc::new(AtomicBool::new(false));
                let mut snapshot = StreamingSnapshot::new(
                    &config(dir.path(), compress),
                    Ipv4Addr::LOCALHOST,
                    TIMESTAMP,
                    &peers,
                    Arc::clone(&cancelled),
                )
                .unwrap();
                snapshot
                    .push(&MrtSnapshotChunk {
                        evpn_routes: vec![route(&peers[0], 1, 7)],
                        ..MrtSnapshotChunk::default()
                    })
                    .unwrap();
                let runs = snapshot.runs.levels.iter().flatten().collect::<Vec<_>>();
                assert_eq!(runs.len(), 1);
                let metadata = runs[0].file.metadata().unwrap();
                assert_eq!(metadata.nlink(), 0, "run must already be unlinked");
                assert_eq!(metadata.mode() & 0o777, 0o600);
                assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
                if cancel {
                    cancelled.store(true, Ordering::Release);
                    assert!(matches!(snapshot.finish(), Err(StreamEncodeError::Io(_))));
                } else {
                    drop(snapshot);
                }
                assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
                assert_eq!(std::fs::read(&sentinel).unwrap(), b"existing dump");
            }
        }
    }

    #[test]
    fn cancelled_writer_does_not_retry_or_write() {
        let cancelled = AtomicBool::new(true);
        let mut bytes = Vec::new();
        let mut writer = CancelWriter::new(&mut bytes, &cancelled);
        // Fail before write_all if Interrupted is reintroduced: it would retry forever.
        assert_ne!(
            writer.write(b"route").unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(writer.write_all(b"route").is_err());
        assert_ne!(
            writer.flush().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(bytes, [] as [u8; 0]);
    }
}
