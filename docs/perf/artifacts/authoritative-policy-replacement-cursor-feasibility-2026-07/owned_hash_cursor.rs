use std::collections::HashMap;
use std::collections::hash_map::IntoIter;

struct ActorOwnedCursor {
    canonical: HashMap<u64, u64>,
    cursor: IntoIter<u64, u64>,
}

impl ActorOwnedCursor {
    fn new(mut canonical: HashMap<u64, u64>) -> Self {
        let cursor = std::mem::take(&mut canonical).into_iter();
        Self { canonical, cursor }
    }
}

fn main() {
    let owner = ActorOwnedCursor::new(HashMap::from([(7, 70), (9, 90)]));
    assert!(owner.canonical.get(&7).is_none());
    assert_eq!(owner.cursor.len(), 2);
}
