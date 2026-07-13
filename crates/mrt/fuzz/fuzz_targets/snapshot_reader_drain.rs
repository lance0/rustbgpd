#![no_main]

use libfuzzer_sys::fuzz_target;
use rustbgpd_mrt::SnapshotReader;

// A valid empty PEER_INDEX_TABLE lets every arbitrary suffix reach the
// iterator as well as fuzzing construction directly from the original input.
const EMPTY_PEER_INDEX_TABLE: &[u8] = &[
    0, 0, 0, 0, // timestamp
    0, 13, // TABLE_DUMP_V2
    0, 1, // PEER_INDEX_TABLE
    0, 0, 0, 8, // payload length
    0, 0, 0, 0, // collector BGP ID
    0, 0, // empty view name
    0, 0, // zero peers
];

fn drain(bytes: &[u8]) {
    if let Ok(mut reader) = SnapshotReader::new(bytes) {
        while reader.next().is_some() {}
    }
}

fuzz_target!(|data: &[u8]| {
    drain(data);

    let mut after_peer_table = Vec::with_capacity(EMPTY_PEER_INDEX_TABLE.len() + data.len());
    after_peer_table.extend_from_slice(EMPTY_PEER_INDEX_TABLE);
    after_peer_table.extend_from_slice(data);
    drain(&after_peer_table);
});
