//! Explicit `event_id` allocator (ADR-0072).
//!
//! The allocator lives at `metadata.last_event_id` in the events DB.
//! Every batch insert is one SQL transaction: read the allocator,
//! assign IDs in memory to every event in the batch, bulk insert with
//! explicit `event_id` column, update the allocator, commit. All-or-
//! nothing.
//!
//! On disk, `events.event_id` is a SQLite `INTEGER PRIMARY KEY` (ROWID-
//! aliased). What we change is **how the value is assigned** — we
//! never let SQLite auto-assign via `INSERT … VALUES (NULL, …)`. Every
//! row carries an explicit `event_id` taken from this allocator. That
//! protects against ROWID reuse after vacuum, and against the
//! "`MAX(event_id)` of an empty table is NULL" ambiguity that bites
//! when retention has cleared everything.
//!
//! The quarantine fallback and diagnostic sidecar helpers live in
//! [`crate::quarantine`]; `read_allocator` here is the in-DB-metadata
//! step only. The recovery-ladder orchestration is in [`crate::storage`].

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::EventHistoryError;
use crate::migrations::META_LAST_EVENT_ID;

/// Read the persisted `last_event_id` from the metadata table.
///
/// Returns `None` when the metadata row is absent (interpreted by the
/// caller as "no allocator anchor in this DB" — distinct from "anchor
/// = 0," which would be `Some(0)` on a fresh DB after `bootstrap`).
pub(crate) fn read_allocator(conn: &Connection) -> Result<Option<u64>, EventHistoryError> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![META_LAST_EVENT_ID],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(|s| {
        s.parse::<u64>().map_err(|e| {
            EventHistoryError::AllocatorCorrupt(format!(
                "metadata.{META_LAST_EVENT_ID} not a u64: {e}"
            ))
        })
    })
    .transpose()
}

/// Update the persisted `last_event_id`. Caller is expected to be
/// inside an active transaction.
pub(crate) fn write_allocator(conn: &Connection, new_value: u64) -> Result<(), EventHistoryError> {
    let updated = conn.execute(
        "UPDATE metadata SET value = ?1 WHERE key = ?2",
        params![new_value.to_string(), META_LAST_EVENT_ID],
    )?;
    if updated == 0 {
        // Row absent — insert. Shouldn't happen post-bootstrap but is
        // defensive against the "metadata table exists but allocator
        // key missing" corruption case.
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES (?1, ?2)",
            params![META_LAST_EVENT_ID, new_value.to_string()],
        )?;
    }
    Ok(())
}

/// In-memory allocator handed across calls within a single
/// [`crate::storage::Store::append_batch_blocking`] transaction.
///
/// Construction reads the persisted value; [`Self::next`] mints the
/// next `event_id`; [`Self::finalize`] persists the new high-water
/// mark inside the same SQL transaction the caller will commit.
///
/// Designed so the caller cannot forget to persist — `finalize` takes
/// `self` and `&Connection`, and `Drop` would only fire if `finalize`
/// is never called (which is itself a bug the test suite catches).
#[derive(Debug)]
pub(crate) struct Allocator {
    /// The last-assigned event_id at the time we read the metadata.
    /// Increments locally per [`Self::next`]; persisted on
    /// [`Self::finalize`].
    next_to_assign: u64,
    /// Snapshot of the persisted value when constructed. Diagnostic
    /// only; used by tests.
    initial: u64,
    finalized: bool,
}

impl Allocator {
    /// Load the allocator from the metadata table. Caller must be
    /// inside an active transaction (or accept that read is from the
    /// connection's current view).
    pub(crate) fn load(conn: &Connection) -> Result<Self, EventHistoryError> {
        let initial = read_allocator(conn)?
            .ok_or_else(|| EventHistoryError::AllocatorCorrupt("missing".to_string()))?;
        Ok(Self {
            next_to_assign: initial,
            initial,
            finalized: false,
        })
    }

    /// Returns the next `event_id` and increments the local counter.
    /// `event_id` is a `u64` and we will never wrap in practice (at
    /// 10k events/s, u64::MAX is ~58 million years away), but check
    /// defensively.
    pub(crate) fn next(&mut self) -> Result<u64, EventHistoryError> {
        let assigned = self.next_to_assign.checked_add(1).ok_or_else(|| {
            EventHistoryError::AllocatorCorrupt("u64 event_id space exhausted".to_string())
        })?;
        self.next_to_assign = assigned;
        Ok(assigned)
    }

    /// Persist the new high-water mark to the metadata table. Caller
    /// must commit the surrounding transaction afterward.
    pub(crate) fn finalize(mut self, conn: &Connection) -> Result<u64, EventHistoryError> {
        write_allocator(conn, self.next_to_assign)?;
        self.finalized = true;
        Ok(self.next_to_assign)
    }

    /// The persisted value at load time. Diagnostic only.
    #[cfg(test)]
    pub(crate) fn initial(&self) -> u64 {
        self.initial
    }
}

impl Drop for Allocator {
    fn drop(&mut self) {
        // An un-finalized allocator means the caller assigned IDs but
        // never persisted them. Subsequent loads would re-assign the
        // same IDs — silent corruption.
        //
        // Debug-build assert is the right tool here: tests catch it,
        // release builds don't panic (the surrounding transaction
        // either committed-with-finalize or rolled back, so the IDs
        // aren't actually leaked to disk).
        if !self.finalized && self.next_to_assign != self.initial {
            debug_assert!(
                false,
                "Allocator dropped without finalize() after assigning ids ({} -> {})",
                self.initial, self.next_to_assign
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SynchronousMode, migrations::bootstrap};
    use rusqlite::Connection;

    fn open_bootstrapped() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        bootstrap(&mut conn, SynchronousMode::Full).unwrap();
        conn
    }

    #[test]
    fn fresh_allocator_starts_at_zero() {
        let conn = open_bootstrapped();
        let alloc = Allocator::load(&conn).unwrap();
        assert_eq!(alloc.initial(), 0);
    }

    #[test]
    fn next_returns_monotonic_ids() {
        let conn = open_bootstrapped();
        let mut alloc = Allocator::load(&conn).unwrap();
        assert_eq!(alloc.next().unwrap(), 1);
        assert_eq!(alloc.next().unwrap(), 2);
        assert_eq!(alloc.next().unwrap(), 3);
        alloc.finalize(&conn).unwrap();
        // Reload — next allocator picks up at 4.
        let mut alloc = Allocator::load(&conn).unwrap();
        assert_eq!(alloc.initial(), 3);
        assert_eq!(alloc.next().unwrap(), 4);
        // Finalize again; otherwise the Drop sanity-check fires
        // (the assigned IDs leak otherwise) — itself proof the
        // guard works.
        alloc.finalize(&conn).unwrap();
    }

    #[test]
    fn finalize_persists_high_water_mark() {
        let conn = open_bootstrapped();
        {
            let mut alloc = Allocator::load(&conn).unwrap();
            for _ in 0..5 {
                alloc.next().unwrap();
            }
            alloc.finalize(&conn).unwrap();
        }
        assert_eq!(read_allocator(&conn).unwrap(), Some(5));
    }

    #[test]
    fn write_allocator_inserts_when_missing() {
        let conn = open_bootstrapped();
        // Remove the row, simulate a corruption case where bootstrap
        // ran but the allocator key got deleted.
        conn.execute(
            "DELETE FROM metadata WHERE key = ?1",
            params![META_LAST_EVENT_ID],
        )
        .unwrap();
        write_allocator(&conn, 42).unwrap();
        assert_eq!(read_allocator(&conn).unwrap(), Some(42));
    }
}
