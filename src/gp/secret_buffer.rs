//! Fixed allocation for bounded control-plane plaintext.
//!
//! Allocate and initialize before receiving secrets. Logical length never
//! changes the allocation, and Drop wipes the entire initialized allocation.
use std::{io, ops::Deref};
use zeroize::Zeroize;

pub(super) struct SecretBuffer {
    bytes: Box<[u8]>,
    len: usize,
    #[cfg(test)]
    audit: Option<audit::Audit>,
    #[cfg(test)]
    allocation_address: usize,
}

impl SecretBuffer {
    pub(super) fn new(capacity: usize) -> io::Result<Self> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "control buffer allocation failed",
            )
        })?;
        bytes.resize(capacity, 0);
        // Any allocator adjustment here happens while every byte is still zero.
        let bytes = bytes.into_boxed_slice();
        Ok(Self {
            #[cfg(test)]
            allocation_address: bytes.as_ptr() as usize,
            bytes,
            len: 0,
            #[cfg(test)]
            audit: audit::Audit::capture(),
        })
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn capacity(&self) -> usize {
        self.bytes.len()
    }

    /// Includes initialized storage beyond the logical length. A partial read
    /// may write there before returning an error; Drop still wipes those bytes.
    pub(super) fn initialized_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub(super) fn set_len(&mut self, len: usize) -> io::Result<()> {
        if len > self.capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control buffer length exceeds capacity",
            ));
        }
        self.len = len;
        Ok(())
    }

    pub(super) fn push(&mut self, byte: u8) -> io::Result<()> {
        if self.len == self.capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control buffer length exceeds capacity",
            ));
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        Ok(())
    }
}

impl Deref for SecretBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes[..self.len]
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        #[cfg(test)]
        let before = self
            .audit
            .as_ref()
            .map(|audit| audit.inspect_before(&self.bytes));
        self.bytes.zeroize();
        #[cfg(test)]
        if let (Some(audit), Some((pre_nonzero, needle_present))) = (&self.audit, before) {
            audit.record_drop(audit::DropRecord {
                pre_nonzero,
                needle_present,
                post_all_zero: self.bytes.iter().all(|byte| *byte == 0),
                address_stable: self.allocation_address == self.bytes.as_ptr() as usize,
                capacity: self.bytes.len(),
                logical_len: self.len,
            });
        }
    }
}

/// Observe the production Drop path before allocation release. Only synthetic
/// tests install an audit; records contain counts/booleans, never buffer bytes.
#[cfg(test)]
pub(crate) mod audit {
    use std::{
        future::Future,
        sync::{Arc, Mutex},
    };

    tokio::task_local! {
        static ACTIVE: Audit;
    }

    #[derive(Clone)]
    pub(crate) struct Audit(Arc<Mutex<State>>);

    struct State {
        needle: Vec<u8>,
        created: usize,
        records: Vec<DropRecord>,
    }

    #[derive(Clone, Debug)]
    pub(crate) struct DropRecord {
        pub(crate) pre_nonzero: usize,
        pub(crate) needle_present: bool,
        pub(crate) post_all_zero: bool,
        pub(crate) address_stable: bool,
        pub(crate) capacity: usize,
        pub(crate) logical_len: usize,
    }

    #[derive(Clone, Debug)]
    pub(crate) struct Snapshot {
        pub(crate) created: usize,
        pub(crate) records: Vec<DropRecord>,
    }

    impl Audit {
        pub(crate) fn new(needle: &[u8]) -> Self {
            assert!(!needle.is_empty(), "audit needs a synthetic marker");
            Self(Arc::new(Mutex::new(State {
                needle: needle.to_vec(),
                created: 0,
                records: Vec::new(),
            })))
        }

        pub(crate) async fn scope<F: Future>(&self, operation: F) -> F::Output {
            ACTIVE.scope(self.clone(), operation).await
        }

        pub(crate) fn snapshot(&self) -> Snapshot {
            let state = self.0.lock().unwrap_or_else(|error| error.into_inner());
            Snapshot {
                created: state.created,
                records: state.records.clone(),
            }
        }

        pub(super) fn capture() -> Option<Self> {
            ACTIVE
                .try_with(|audit| {
                    audit
                        .0
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .created += 1;
                    audit.clone()
                })
                .ok()
        }

        pub(super) fn inspect_before(&self, bytes: &[u8]) -> (usize, bool) {
            let state = self.0.lock().unwrap_or_else(|error| error.into_inner());
            (
                bytes.iter().filter(|byte| **byte != 0).count(),
                bytes
                    .windows(state.needle.len())
                    .any(|window| window == state.needle),
            )
        }

        pub(super) fn record_drop(&self, record: DropRecord) {
            self.0
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .records
                .push(record);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{audit::Audit, SecretBuffer};

    #[tokio::test]
    async fn fixed_allocation_wipes_written_bytes_beyond_logical_length() {
        let audit = Audit::new(b"synthetic-marker");
        let mut bytes = audit.scope(async { SecretBuffer::new(64).unwrap() }).await;
        // The audit scope has already ended: Drop must use the captured audit.
        let address = bytes.as_ptr();
        bytes.initialized_mut()[16..32].copy_from_slice(b"synthetic-marker");
        bytes.push(b'A').unwrap();
        bytes.push(b'B').unwrap();
        assert_eq!(&*bytes, b"AB");
        bytes.set_len(32).unwrap();
        assert_eq!(bytes.as_ptr(), address);
        assert_eq!(bytes.capacity(), 64);
        bytes.set_len(1).unwrap();
        drop(bytes);
        let snapshot = audit.snapshot();
        assert_eq!(snapshot.created, 1);
        assert_eq!(snapshot.records.len(), 1);
        let record = &snapshot.records[0];
        assert!(record.needle_present);
        assert_eq!(record.pre_nonzero, 18);
        assert_eq!(record.logical_len, 1);
        assert_eq!(record.capacity, 64);
        assert!(record.post_all_zero && record.address_stable);
    }

    #[tokio::test]
    async fn rejected_growth_preserves_data_and_allocation() {
        let audit = Audit::new(b"AB");
        audit
            .scope(async {
                let mut bytes = SecretBuffer::new(2).unwrap();
                let address = bytes.as_ptr();
                bytes.push(b'A').unwrap();
                bytes.push(b'B').unwrap();
                assert!(bytes.push(b'C').is_err());
                assert!(bytes.set_len(3).is_err());
                assert_eq!(&*bytes, b"AB");
                assert_eq!(bytes.len(), 2);
                assert_eq!(bytes.capacity(), 2);
                assert_eq!(bytes.as_ptr(), address);
            })
            .await;
        let snapshot = audit.snapshot();
        assert_eq!(snapshot.created, 1);
        assert_eq!(snapshot.records.len(), 1);
        assert!(snapshot.records[0].needle_present);
        assert!(snapshot.records[0].post_all_zero && snapshot.records[0].address_stable);
    }

    #[test]
    fn zero_capacity_and_impossible_allocation_fail_without_receiving_bytes() {
        let mut empty = SecretBuffer::new(0).unwrap();
        assert_eq!(empty.len(), 0);
        assert!(empty.push(1).is_err());
        assert!(empty.set_len(1).is_err());
        empty.set_len(0).unwrap();
        assert!(SecretBuffer::new(usize::MAX).is_err());
    }
}
