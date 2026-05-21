use crossbeam_queue::ArrayQueue;
use std::cell::UnsafeCell;
use std::sync::Arc;

pub const DEFAULT_FRAME_CAP: usize = 1600;
pub const DEFAULT_HEADROOM: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    Control,
    Realtime,
    Interactive,
    Bulk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketDesc {
    pub slot: u32,
    pub data_offset: usize,
    pub payload_offset: usize,
    pub len: usize,
    pub class: TrafficClass,
}

struct PacketCell<const FRAME_CAP: usize>(UnsafeCell<[u8; FRAME_CAP]>);

// Safety: packet slots are only mutated via descriptor ownership from the freelist.
unsafe impl<const FRAME_CAP: usize> Sync for PacketCell<FRAME_CAP> {}

pub struct PacketSlab<const FRAME_CAP: usize = DEFAULT_FRAME_CAP> {
    slots: Vec<PacketCell<FRAME_CAP>>,
    free: ArrayQueue<u32>,
    headroom: usize,
}

impl<const FRAME_CAP: usize> PacketSlab<FRAME_CAP> {
    pub fn new(capacity: usize, headroom: usize) -> Arc<Self> {
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(PacketCell(UnsafeCell::new([0u8; FRAME_CAP])));
        }

        let free = ArrayQueue::new(capacity);
        for index in 0..capacity {
            let _ = free.push(index as u32);
        }

        Arc::new(Self {
            slots,
            free,
            headroom,
        })
    }

    pub fn default_pool(capacity: usize) -> Arc<Self> {
        Self::new(capacity, DEFAULT_HEADROOM)
    }

    pub fn acquire(&self) -> Option<PacketDesc> {
        self.free.pop().map(|slot| PacketDesc {
            slot,
            data_offset: 0,
            payload_offset: self.headroom,
            len: 0,
            class: TrafficClass::Bulk,
        })
    }

    pub fn release(&self, desc: PacketDesc) {
        let _ = self.free.push(desc.slot);
    }

    pub fn available(&self) -> usize {
        self.free.len()
    }

    pub fn with_slot_mut<R>(
        &self,
        desc: PacketDesc,
        func: impl FnOnce(&mut [u8; FRAME_CAP]) -> R,
    ) -> R {
        let slot = &self.slots[desc.slot as usize];
        // Safety: slot mutation is guarded by the ownership of `PacketDesc`.
        let buf = unsafe { &mut *slot.0.get() };
        func(buf)
    }

    pub fn get_slot_slice(&self, desc: &PacketDesc) -> &[u8] {
        let slot = &self.slots[desc.slot as usize];
        // Safety: slot access is guarded by ownership of `PacketDesc`.
        unsafe { &*slot.0.get() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_release_slots() {
        let slab = PacketSlab::<512>::new(2, 64);
        let a = slab.acquire().expect("first slot");
        let b = slab.acquire().expect("second slot");
        assert!(slab.acquire().is_none());

        slab.release(a);
        let c = slab.acquire().expect("reused slot");
        assert_eq!(c.slot, a.slot);

        slab.with_slot_mut(c, |buf| {
            buf[64] = 7;
            assert_eq!(buf[64], 7);
        });

        slab.release(c);
        slab.release(b);
        assert_eq!(slab.available(), 2);
    }
}
