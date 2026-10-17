//! Scan-cycle bookkeeping for [`crate`] discovery.
//!
//! BlueZ replays every cached device object plus every device property
//! change as `DeviceAdded` events, so one scan cycle may report the same
//! device dozens of times. Evaluating a sighting costs two D-Bus property
//! reads (`UUIDs`, `RSSI`); running those serially inside the bounded scan
//! window starves real-time advertisement events. [`SeenQueue`] bounds and
//! deduplicates pending sightings so each unique address waits in line at
//! most once, in first-seen order. The at-most-once guarantee for
//! *evaluations* belongs to the active scheduler, which tracks addresses
//! already in flight — not to this queue, which only tracks what is still
//! pending.

use std::collections::{HashSet, VecDeque};

use bluer::Address;

/// Maximum number of devices waiting for property evaluation.
///
/// A scan burst over a crowded bus can report far more unique devices than
/// can be evaluated inside one scan window; beyond this cap the newest
/// unique sighting is dropped rather than evicting an address that arrived
/// earlier.
const MAX_PENDING: usize = 256;

/// Bounded FIFO queue of device addresses awaiting property evaluation.
///
/// `push` deduplicates: an address already pending is not enqueued again,
/// and once [`MAX_PENDING`] unique addresses are waiting the newest unique
/// sighting is ignored while pending entries keep their place.
/// `pop_ready` hands out the oldest pending address that satisfies its
/// predicate without discarding or reordering addresses that are not
/// ready yet, and `remove` erases a pending sighting outright.
///
/// Deduplication covers only the pending set: a popped address may be
/// pushed again, so a sighting that arrives while its evaluation is in
/// flight re-queues the device for a fresh look (its `UUIDs`/`RSSI` may
/// have changed). Preventing two evaluations of the same address from
/// running concurrently is the scheduler's job, not this queue's.
#[derive(Default)]
pub(crate) struct SeenQueue {
    queue: VecDeque<Address>,
    enqueued: HashSet<Address>,
}

impl SeenQueue {
    /// Queue `addr` for evaluation unless it is already pending or the
    /// queue is at capacity.
    pub(crate) fn push(&mut self, addr: Address) {
        if self.enqueued.contains(&addr) || self.queue.len() >= MAX_PENDING {
            return;
        }
        self.enqueued.insert(addr);
        self.queue.push_back(addr);
    }

    /// Take the oldest pending address for which `ready` returns `true`.
    ///
    /// Pending addresses that fail the predicate stay queued in their
    /// original order, so a blocked head cannot starve later candidates.
    /// A returned address may be pushed again afterward.
    pub(crate) fn pop_ready(&mut self, ready: impl FnMut(&Address) -> bool) -> Option<Address> {
        let index = self.queue.iter().position(ready)?;
        let addr = self.queue.remove(index)?;
        self.enqueued.remove(&addr);
        Some(addr)
    }

    /// Erase a pending sighting so a stale address is never evaluated.
    ///
    /// No-op when `addr` is not queued; an address removed this way may be
    /// pushed again by a later sighting.
    pub(crate) fn remove(&mut self, addr: Address) {
        if !self.enqueued.remove(&addr) {
            return;
        }
        if let Some(index) = self.queue.iter().position(|queued| *queued == addr) {
            self.queue.remove(index);
        }
    }
}

#[cfg(test)]
impl SeenQueue {
    /// Number of queued, not-yet-started evaluations.
    fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether no evaluations are pending.
    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address([n, n, n, n, n, n])
    }

    fn pop_any(q: &mut SeenQueue) -> Option<Address> {
        q.pop_ready(|_| true)
    }

    #[test]
    fn deduplicates_pending_addresses() {
        let mut q = SeenQueue::default();
        q.push(addr(1));
        q.push(addr(1));
        q.push(addr(2));
        q.push(addr(1));
        assert_eq!(q.len(), 2);
        assert_eq!(pop_any(&mut q), Some(addr(1)));
        assert_eq!(pop_any(&mut q), Some(addr(2)));
        assert_eq!(pop_any(&mut q), None);
        assert!(q.is_empty());
    }

    #[test]
    fn address_can_requeue_after_pop() {
        let mut q = SeenQueue::default();
        q.push(addr(7));
        assert_eq!(pop_any(&mut q), Some(addr(7)));
        // A property-change sighting arriving mid-evaluation must not be
        // silently dropped once the earlier evaluation started.
        q.push(addr(7));
        assert_eq!(pop_any(&mut q), Some(addr(7)));
        assert_eq!(pop_any(&mut q), None);
    }

    #[test]
    fn pop_ready_is_fifo_across_many_devices() {
        let mut q = SeenQueue::default();
        for n in 0..16u8 {
            q.push(addr(n));
        }
        for n in 0..16u8 {
            assert_eq!(pop_any(&mut q), Some(addr(n)));
        }
    }

    #[test]
    fn capacity_rejects_newest_unique_without_displacing_pending() {
        let mut q = SeenQueue::default();
        for n in 0..MAX_PENDING {
            q.push(addr(n as u8));
        }
        assert_eq!(q.len(), MAX_PENDING);
        // Repeat sightings of pending addresses are still deduplicated.
        q.push(addr(0));
        assert_eq!(q.len(), MAX_PENDING);
        // A brand-new sighting past capacity is ignored, not swapped in.
        let late = Address([0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF]);
        q.push(late);
        assert_eq!(q.len(), MAX_PENDING);
        for n in 0..MAX_PENDING {
            assert_eq!(pop_any(&mut q), Some(addr(n as u8)));
        }
        assert!(q.is_empty());
        // Once space frees up the same sighting is accepted again.
        q.push(late);
        assert_eq!(pop_any(&mut q), Some(late));
    }

    #[test]
    fn remove_erases_pending_sighting() {
        let mut q = SeenQueue::default();
        q.push(addr(1));
        q.push(addr(2));
        q.push(addr(3));
        q.remove(addr(2));
        // The removed device is never handed to an evaluator.
        assert_eq!(pop_any(&mut q), Some(addr(1)));
        assert_eq!(pop_any(&mut q), Some(addr(3)));
        assert_eq!(pop_any(&mut q), None);
        // Removing an address that was never queued is a no-op.
        q.remove(addr(9));
        // A later genuine sighting may queue the device again.
        q.push(addr(2));
        assert_eq!(pop_any(&mut q), Some(addr(2)));
        assert!(q.is_empty());
    }

    #[test]
    fn ineligible_head_does_not_starve_later_candidates() {
        let mut q = SeenQueue::default();
        q.push(addr(1)); // evaluation already in flight elsewhere
        q.push(addr(2));
        q.push(addr(3));
        let blocked = addr(1);
        // Ready candidates behind the blocked head are still served.
        assert_eq!(q.pop_ready(|a| *a != blocked), Some(addr(2)));
        assert_eq!(q.pop_ready(|a| *a != blocked), Some(addr(3)));
        // The blocked head was neither dropped nor reordered.
        assert_eq!(q.len(), 1);
        assert_eq!(q.pop_ready(|a| *a == blocked), Some(addr(1)));
        assert!(q.is_empty());
    }
}
