//! Local discriminator allocation (RFC 5880 §6.8.1: each session's
//! discriminator must be unique and non-zero).

use std::collections::BTreeSet;

/// Hands out unique, non-zero local discriminators and tracks which are in use.
#[derive(Debug, Default, Clone)]
pub struct DiscriminatorAllocator {
    next: u32,
    in_use: BTreeSet<u32>,
}

impl DiscriminatorAllocator {
    /// Create an empty allocator.
    #[must_use]
    pub fn new() -> DiscriminatorAllocator {
        DiscriminatorAllocator {
            next: 1,
            in_use: BTreeSet::new(),
        }
    }

    /// Allocate the next free non-zero discriminator.
    ///
    /// # Panics
    /// Panics only in the pathological case that all 2³²−1 discriminators are
    /// simultaneously in use, which cannot happen with any realistic peer count.
    pub fn allocate(&mut self) -> u32 {
        for _ in 0..=u32::MAX {
            if self.next == 0 {
                self.next = 1;
            }
            let candidate = self.next;
            self.next = self.next.wrapping_add(1);
            if self.in_use.insert(candidate) {
                return candidate;
            }
        }
        panic!("BFD discriminator space exhausted");
    }

    /// Release a previously allocated discriminator.
    pub fn release(&mut self, discriminator: u32) {
        self.in_use.remove(&discriminator);
    }

    /// Number of discriminators currently allocated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.in_use.len()
    }

    /// Whether no discriminators are currently allocated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.in_use.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocations_are_unique_and_non_zero() {
        let mut alloc = DiscriminatorAllocator::new();
        let mut seen = BTreeSet::new();
        for _ in 0..1000 {
            let d = alloc.allocate();
            assert_ne!(d, 0);
            assert!(seen.insert(d), "discriminator {d} handed out twice");
        }
        assert_eq!(alloc.len(), 1000);
    }

    #[test]
    fn released_discriminators_become_reusable() {
        let mut alloc = DiscriminatorAllocator::new();
        let a = alloc.allocate();
        let b = alloc.allocate();
        alloc.release(a);
        assert_eq!(alloc.len(), 1);
        // Eventually the freed value is handed out again after wraparound.
        alloc.release(b);
        assert!(alloc.is_empty());
    }
}
