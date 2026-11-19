//! Build a cold registration's unicast table privately, one actor turn at a time.

use tokio::sync::mpsc;

use super::update_groups::GroupRibOut;
use super::{OutboundRouteUpdate, PeerId, RibManager};
use crate::loc_rib::{REGISTRATION_PAGE_SIZE, RegistrationScanStatus};

struct Waiter {
    session_id: u64,
    sender: mpsc::Sender<OutboundRouteUpdate>,
}

pub(super) struct FirstGroupBuild {
    gid: usize,
    pub(super) peer: PeerId,
    // None while discarding a canceled table. Keep the same allocation until
    // retirement finishes so repeated reconnects cannot retain more tables.
    waiter: Option<Waiter>,
    table: GroupRibOut,
}

impl RibManager {
    pub(super) fn first_group_candidate(
        &mut self,
        peer: PeerId,
    ) -> Option<(usize, u64, mpsc::Sender<OutboundRouteUpdate>)> {
        #[cfg(test)]
        let threshold = self.first_group_build_min_routes;
        #[cfg(not(test))]
        let threshold = super::INITIAL_DUMP_DEFER_MIN_ROUTES;
        if self.loc_rib.len() < threshold {
            return None;
        }
        let candidate = self.prospective_first_group(peer, None)?;
        (!self.group_ribs.contains_key(&candidate.0) || self.prestaging_destination(candidate.0))
            .then_some(candidate)
    }

    pub(super) fn start_first_group(
        &mut self,
        peer: PeerId,
        gid: usize,
        session_id: u64,
        sender: mpsc::Sender<OutboundRouteUpdate>,
    ) {
        debug_assert!(self.first_group_build.is_none());
        self.loc_rib.start_registration_scan();
        self.first_group_build = Some(Box::new(FirstGroupBuild {
            gid,
            peer,
            waiter: Some(Waiter { session_id, sender }),
            table: self.first_group_table(peer, gid),
        }));
    }

    pub(super) fn first_group_targets(&self, gid: usize) -> bool {
        self.first_group_build
            .as_ref()
            .is_some_and(|job| job.gid == gid)
    }

    /// A policy owner may claim this destination after the last private page retires.
    pub(super) fn retire_first_group_for_policy(&mut self, gid: usize) -> bool {
        let Some(job) = self.first_group_build.as_mut().filter(|job| job.gid == gid) else {
            return true;
        };
        if job.waiter.take().is_some() {
            self.loc_rib.stop_registration_scan();
        }
        self.advance_first_group_build();
        false
    }

    /// Look at one waiter per busy turn. A second cold group, or a retry after
    /// overflow, can start under steady ingress without reordering warm joins.
    pub(super) fn advance_busy_first_group(&mut self, search: &mut usize) {
        if self.first_group_build.is_none() {
            let queue = &self.pending_initial_registrations;
            if *search >= queue.len() {
                *search = 0;
            }
            let Some(&peer) = queue.get(*search) else {
                return;
            };
            *search += 1;
            let Some((gid, session, sender)) = self.first_group_candidate(peer) else {
                return;
            };
            if self.prestaging_destination(gid) {
                return;
            }
            self.start_first_group(peer, gid, session, sender);
        }
        self.advance_first_group_build();
    }

    // Keep the existing queue as the authority on pending registrations, even
    // while this job is building. GR and collision handling consult that queue.
    pub(super) fn advance_first_group_build(&mut self) {
        let mut job = self.first_group_build.take().expect("active first group");
        if let Some(waiter) = &job.waiter {
            let current = self.prospective_first_group(job.peer, Some(job.gid));
            let same_generation = current.is_some_and(|(gid, session_id, sender)| {
                gid == job.gid
                    && waiter.session_id == session_id
                    && waiter.sender.same_channel(&sender)
            });
            if same_generation
                && !self.group_ribs.contains_key(&job.gid)
                && self.loc_rib.registration_scan_status() != RegistrationScanStatus::Overflow
            {
                let page = self.loc_rib.take_registration_page();
                debug_assert!(page.bucket_visits + page.repairs <= REGISTRATION_PAGE_SIZE);
                if !page.keys.is_empty() {
                    let prefixes = page.keys.into_iter().collect();
                    job.table = self.stage_first_group_page(job.gid, job.table, &prefixes);
                }
                if self.loc_rib.registration_scan_status() != RegistrationScanStatus::Ready
                    || !self.pending_route_batches.is_empty()
                {
                    self.first_group_build = Some(job);
                    return;
                }
                self.loc_rib.stop_registration_scan();
                let peer = job.peer;
                let Some(table) = self.publish_first_group(job.gid, job.table) else {
                    // Publish, install the member and hand it the complete
                    // initial replay in this turn. No other command observes
                    // a memberless destination claimed by this registration.
                    self.pending_initial_registrations
                        .retain(|queued| *queued != peer);
                    self.complete_deferred_registration(peer);
                    return;
                };
                job.table = table;
            } else {
                self.loc_rib.stop_registration_scan();
            }
            job.waiter = None;
        }
        if !job.table.retire_first_group_page(REGISTRATION_PAGE_SIZE) {
            self.first_group_build = Some(job);
        }
    }

    #[cfg(test)]
    pub(super) fn first_group_contains(&self, prefix: rustbgpd_wire::Prefix) -> bool {
        self.first_group_build
            .as_ref()
            .is_some_and(|job| job.waiter.is_some() && job.table.table.get(&prefix, 0).is_some())
    }
}
