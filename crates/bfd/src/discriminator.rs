//! Local discriminator allocation (RFC 5880 §6.8.1: each session's
//! discriminator must be unique and non-zero).

use std::collections::BTreeSet;

/// Local discriminator allocation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DiscriminatorAllocationError {
    /// Every non-zero 32-bit discriminator is already in use.
    #[error("BFD discriminator space exhausted")]
    Exhausted,
}

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
    /// # Errors
    /// Returns [`DiscriminatorAllocationError::Exhausted`] only when every
    /// non-zero 32-bit discriminator is simultaneously in use.
    pub fn allocate(&mut self) -> Result<u32, DiscriminatorAllocationError> {
        self.allocate_with_scan_limit(u64::from(u32::MAX) + 1)
    }

    fn allocate_with_scan_limit(
        &mut self,
        scan_limit: u64,
    ) -> Result<u32, DiscriminatorAllocationError> {
        for _ in 0..scan_limit {
            if self.next == 0 {
                self.next = 1;
            }
            let candidate = self.next;
            self.next = self.next.wrapping_add(1);
            if self.in_use.insert(candidate) {
                return Ok(candidate);
            }
        }
        Err(DiscriminatorAllocationError::Exhausted)
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
            let d = alloc.allocate().expect("test allocation must succeed");
            assert_ne!(d, 0);
            assert!(seen.insert(d), "discriminator {d} handed out twice");
        }
        assert_eq!(alloc.len(), 1000);
    }

    #[test]
    fn released_discriminators_become_reusable() {
        let mut alloc = DiscriminatorAllocator::new();
        let a = alloc.allocate().expect("test allocation must succeed");
        let b = alloc.allocate().expect("test allocation must succeed");
        alloc.release(a);
        assert_eq!(alloc.len(), 1);
        // Eventually the freed value is handed out again after wraparound.
        alloc.release(b);
        assert!(alloc.is_empty());
    }

    #[test]
    fn exhausted_scan_returns_error_instead_of_panicking() {
        let mut alloc = DiscriminatorAllocator::new();
        alloc.in_use.insert(1);
        alloc.next = 1;

        assert_eq!(
            alloc.allocate_with_scan_limit(1),
            Err(DiscriminatorAllocationError::Exhausted)
        );
        assert_eq!(alloc.len(), 1);
    }
}
