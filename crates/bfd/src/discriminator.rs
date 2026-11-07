//! Local discriminator allocation (RFC 5880 §6.8.1: each session's
//! discriminator must be unique and non-zero, and SHOULD be random).
//!
//! The allocator is pure: the caller supplies the random source, so the
//! runtime can draw from the OS CSPRNG and tests can draw deterministically.

use std::collections::BTreeSet;

/// Draws allowed per allocation. With realistic session counts a draw
/// collides with probability about `sessions / 2^32`, so running out of
/// draws means the source is not random rather than the space being full.
const MAX_DRAWS: usize = 64;

/// Local discriminator allocation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DiscriminatorAllocationError {
    /// No unused non-zero value came out of the random source.
    #[error("BFD discriminator allocation drew no unused non-zero value")]
    Exhausted,
}

/// Hands out unique, non-zero local discriminators and tracks which are in use.
#[derive(Debug, Default, Clone)]
pub struct DiscriminatorAllocator {
    in_use: BTreeSet<u32>,
}

impl DiscriminatorAllocator {
    /// Create an empty allocator.
    #[must_use]
    pub fn new() -> DiscriminatorAllocator {
        DiscriminatorAllocator::default()
    }

    /// Allocate a discriminator drawn from `draw`, redrawing zero and values
    /// already in use. Random values keep a peer from guessing another
    /// session's discriminator from its own; they do not hide it from a
    /// sender that can observe the session (RFC 5880 §9).
    ///
    /// # Errors
    /// Returns [`DiscriminatorAllocationError::Exhausted`] when `draw` yields
    /// no unused non-zero value in a bounded number of attempts.
    pub fn allocate(
        &mut self,
        mut draw: impl FnMut() -> u32,
    ) -> Result<u32, DiscriminatorAllocationError> {
        for _ in 0..MAX_DRAWS {
            let candidate = draw();
            if candidate != 0 && self.in_use.insert(candidate) {
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

    /// Deterministic xorshift source standing in for the CSPRNG.
    fn xorshift(mut state: u32) -> impl FnMut() -> u32 {
        move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        }
    }

    #[test]
    fn allocations_are_unique_and_non_zero() {
        let mut alloc = DiscriminatorAllocator::new();
        let mut draw = xorshift(0x9e37_79b9);
        let mut seen = BTreeSet::new();
        for _ in 0..100_000 {
            let d = alloc.allocate(&mut draw).expect("allocation succeeds");
            assert_ne!(d, 0);
            assert!(seen.insert(d), "discriminator {d} handed out twice");
        }
        assert_eq!(alloc.len(), 100_000);
    }

    #[test]
    fn zero_and_in_use_draws_are_redrawn() {
        let mut alloc = DiscriminatorAllocator::new();
        let mut draws = [0, 9, 9, 3].into_iter();
        let mut draw = || draws.next().expect("enough draws");
        assert_eq!(alloc.allocate(&mut draw), Ok(9), "zero is never handed out");
        assert_eq!(
            alloc.allocate(&mut draw),
            Ok(3),
            "a value in use is redrawn"
        );
        assert_eq!(alloc.len(), 2);
    }

    #[test]
    fn released_discriminators_become_reusable() {
        let mut alloc = DiscriminatorAllocator::new();
        assert_eq!(alloc.allocate(|| 7), Ok(7));
        assert_eq!(
            alloc.allocate(|| 7),
            Err(DiscriminatorAllocationError::Exhausted)
        );
        alloc.release(7);
        assert!(alloc.is_empty());
        assert_eq!(alloc.allocate(|| 7), Ok(7));
    }

    #[test]
    fn a_source_without_unused_values_fails_instead_of_looping() {
        let mut alloc = DiscriminatorAllocator::new();
        assert_eq!(
            alloc.allocate(|| 0),
            Err(DiscriminatorAllocationError::Exhausted)
        );
        assert!(alloc.is_empty());
    }
}
