use std::collections::HashMap;

fn next_batch(
    map: &HashMap<u64, u64>,
    after: Option<u64>,
    limit: usize,
    visits: &mut usize,
) -> Vec<u64> {
    let mut candidates = Vec::new();
    for key in map.keys().copied() {
        *visits += 1;
        if after.is_none_or(|after| key > after) {
            candidates.push(key);
        }
    }
    candidates.sort_unstable();
    candidates.truncate(limit);
    candidates
}

fn main() {
    const ROWS: usize = 4096;
    const BATCH: usize = 64;
    let map: HashMap<u64, u64> = (0..ROWS as u64).map(|key| (key, key)).collect();
    let mut visits = 0;
    let mut after = None;
    let mut yielded = 0;
    loop {
        let batch = next_batch(&map, after, BATCH, &mut visits);
        let Some(last) = batch.last().copied() else {
            break;
        };
        yielded += batch.len();
        after = Some(last);
    }
    assert_eq!(yielded, ROWS);
    assert_eq!(visits, ROWS * (ROWS.div_ceil(BATCH) + 1));
    println!(
        "rows={ROWS} batch={BATCH} visits={visits} amplification={:.1}x",
        visits as f64 / ROWS as f64
    );
}
