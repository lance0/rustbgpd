use std::collections::HashMap;
use std::collections::hash_map::Iter;

struct ActorOwnedCursor<'a> {
    canonical: HashMap<u64, u64>,
    cursor: Iter<'a, u64, u64>,
}

impl ActorOwnedCursor<'_> {
    fn new(canonical: HashMap<u64, u64>) -> Self {
        let cursor = canonical.iter();
        Self { canonical, cursor }
    }
}

fn main() {}
