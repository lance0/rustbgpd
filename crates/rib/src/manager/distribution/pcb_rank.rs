//! The common binary heap compares live candidate identities. A fenced
//! release uses a contiguous vector. The cold builder also budgets work
//! within each sift and allocates overflow in independently retired pages.

use super::PeerId;
use smallvec::SmallVec;
use std::collections::BTreeMap;
use std::ops::{Index, IndexMut};

pub(in crate::manager) type Path = (PeerId, u32);
const INLINE: usize = 4;
const PAGE: usize = super::release_pcb::CANDIDATES_PER_POLL;

pub(super) trait RankedPaths: Default + IndexMut<usize, Output = Path> {
    const FIRST_GROUP: bool;
    fn len(&self) -> usize;
    fn push_tail(&mut self, path: Path);
    fn pop_tail(&mut self) -> Option<Path>;

    /// Dirty paths may already be absent. Dropping tail slots involves no
    /// comparisons or source lookups.
    fn retire(&mut self, budget: &mut usize) -> bool {
        let count = (*budget).min(self.len());
        for _ in 0..count {
            self.pop_tail();
        }
        *budget -= count;
        #[cfg(test)]
        if count != 0 {
            super::super::slice_timing::record_work("first_pcb_rank_retired", count);
        }
        self.len() == 0
    }

    /// Include one candidate visit and the maximum comparisons for its sift.
    fn push_budget(&self) -> usize {
        1 + (self.len() + 1).ilog2() as usize
    }

    fn pop_budget(&self) -> usize {
        1 + 2 * self.len().max(1).ilog2() as usize
    }

    fn push_ranked(&mut self, path: Path, mut precedes: impl FnMut(Path, Path) -> bool) {
        let mut index = self.len();
        self.push_tail(path);
        while index > 0 {
            let parent = (index - 1) / 2;
            let upper = self[parent];
            if !precedes(path, upper) {
                break;
            }
            self[index] = upper;
            #[cfg(test)]
            if Self::FIRST_GROUP {
                super::super::slice_timing::record_work("first_pcb_rank_moves", 1);
            }
            index = parent;
        }
        self[index] = path;
    }

    fn pop_ranked(&mut self, mut precedes: impl FnMut(Path, Path) -> bool) -> Option<Path> {
        if self.len() == 0 {
            return None;
        }
        let first = self[0];
        let last = self.pop_tail().expect("nonempty ranked paths");
        if self.len() != 0 {
            let mut index = 0;
            while 2 * index + 1 < self.len() {
                let mut child = 2 * index + 1;
                if child + 1 < self.len() && precedes(self[child + 1], self[child]) {
                    child += 1;
                }
                let lower = self[child];
                if !precedes(lower, last) {
                    break;
                }
                self[index] = lower;
                #[cfg(test)]
                if Self::FIRST_GROUP {
                    super::super::slice_timing::record_work("first_pcb_rank_moves", 1);
                }
                index = child;
            }
            self[index] = last;
            #[cfg(test)]
            if Self::FIRST_GROUP {
                super::super::slice_timing::record_work("first_pcb_rank_moves", 1);
            }
        }
        Some(first)
    }
}

impl RankedPaths for Vec<Path> {
    const FIRST_GROUP: bool = false;
    fn len(&self) -> usize {
        self.len()
    }
    fn push_tail(&mut self, path: Path) {
        self.push(path);
    }
    fn pop_tail(&mut self) -> Option<Path> {
        self.pop()
    }
}

#[derive(Default)]
pub(in crate::manager) struct PagedPaths {
    first: SmallVec<[Path; INLINE]>,
    pages: BTreeMap<usize, Vec<Path>>,
    len: usize,
}

impl Index<usize> for PagedPaths {
    type Output = Path;

    fn index(&self, i: usize) -> &Path {
        if i < INLINE {
            &self.first[i]
        } else {
            let n = i - INLINE;
            &self.pages[&(n / PAGE)][n % PAGE]
        }
    }
}

impl IndexMut<usize> for PagedPaths {
    fn index_mut(&mut self, i: usize) -> &mut Path {
        if i < INLINE {
            &mut self.first[i]
        } else {
            let n = i - INLINE;
            &mut self
                .pages
                .get_mut(&(n / PAGE))
                .expect("allocated heap page")[n % PAGE]
        }
    }
}

impl RankedPaths for PagedPaths {
    const FIRST_GROUP: bool = true;
    fn len(&self) -> usize {
        self.len
    }

    fn push_tail(&mut self, path: Path) {
        if self.len < INLINE {
            self.first.push(path);
        } else {
            self.pages
                .entry((self.len - INLINE) / PAGE)
                .or_insert_with(|| Vec::with_capacity(PAGE))
                .push(path);
        }
        self.len += 1;
    }

    fn pop_tail(&mut self) -> Option<Path> {
        self.len = self.len.checked_sub(1)?;
        if self.len < INLINE {
            self.first.pop()
        } else {
            let mut entry = self.pages.last_entry().expect("last heap page");
            let last = entry.get_mut().pop();
            if entry.get().is_empty() {
                entry.remove();
            }
            last
        }
    }
}
