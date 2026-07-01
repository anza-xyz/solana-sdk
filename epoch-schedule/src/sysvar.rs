pub use solana_sdk_ids::sysvar::epoch_schedule::{check_id, id, ID};
use {
    crate::EpochSchedule,
    solana_get_sysvar::{get_sysvar_unchecked, GetSysvar},
    solana_program_error::ProgramError,
    solana_sysvar_id::impl_sysvar_id,
};

impl_sysvar_id!(EpochSchedule);

/// Pod (Plain Old Data) representation of [`EpochSchedule`] with no padding.
///
/// This type can be safely loaded via `sol_get_sysvar` without undefined behavior.
/// Provides performant zero-copy accessors as an alternative to the `EpochSchedule` type.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PodEpochSchedule {
    slots_per_epoch: [u8; 8],
    leader_schedule_slot_offset: [u8; 8],
    warmup: u8,
    first_normal_epoch: [u8; 8],
    first_normal_slot: [u8; 8],
}

const POD_EPOCH_SCHEDULE_SIZE: usize = 33;
const _: () = assert!(core::mem::size_of::<PodEpochSchedule>() == POD_EPOCH_SCHEDULE_SIZE);

impl PodEpochSchedule {
    /// Fetch the sysvar data using the `sol_get_sysvar` syscall.
    /// This provides an alternative to `EpochSchedule` which provides zero-copy accessors.
    pub fn fetch() -> Result<Self, ProgramError> {
        let mut pod = core::mem::MaybeUninit::<Self>::uninit();
        // Safety: `get_sysvar_unchecked` will initialize `pod` with the sysvar data,
        // and error if unsuccessful.
        unsafe {
            get_sysvar_unchecked(
                pod.as_mut_ptr() as *mut u8,
                (&id()) as *const _ as *const u8,
                0,
                POD_EPOCH_SCHEDULE_SIZE as u64,
            )?;
            Ok(pod.assume_init())
        }
    }

    pub fn slots_per_epoch(&self) -> u64 {
        u64::from_le_bytes(self.slots_per_epoch)
    }

    pub fn leader_schedule_slot_offset(&self) -> u64 {
        u64::from_le_bytes(self.leader_schedule_slot_offset)
    }

    pub fn warmup(&self) -> bool {
        // SAFETY: upstream invariant: the sysvar data is created exclusively
        // by the Solana runtime and serializes bool as 0x00 or 0x01.
        self.warmup > 0
    }

    pub fn first_normal_epoch(&self) -> u64 {
        u64::from_le_bytes(self.first_normal_epoch)
    }

    pub fn first_normal_slot(&self) -> u64 {
        u64::from_le_bytes(self.first_normal_slot)
    }
}

impl From<PodEpochSchedule> for EpochSchedule {
    fn from(pod: PodEpochSchedule) -> Self {
        Self {
            slots_per_epoch: pod.slots_per_epoch(),
            leader_schedule_slot_offset: pod.leader_schedule_slot_offset(),
            warmup: pod.warmup(),
            first_normal_epoch: pod.first_normal_epoch(),
            first_normal_slot: pod.first_normal_slot(),
        }
    }
}

impl GetSysvar for EpochSchedule {
    fn get() -> Result<Self, ProgramError> {
        Ok(PodEpochSchedule::fetch()?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pod_epoch_schedule_conversion() {
        let pod = PodEpochSchedule {
            slots_per_epoch: 432000u64.to_le_bytes(),
            leader_schedule_slot_offset: 432000u64.to_le_bytes(),
            warmup: 1,
            first_normal_epoch: 14u64.to_le_bytes(),
            first_normal_slot: 524256u64.to_le_bytes(),
        };

        let epoch_schedule = EpochSchedule::from(pod);

        assert_eq!(epoch_schedule.slots_per_epoch, 432000);
        assert_eq!(epoch_schedule.leader_schedule_slot_offset, 432000);
        assert!(epoch_schedule.warmup);
        assert_eq!(epoch_schedule.first_normal_epoch, 14);
        assert_eq!(epoch_schedule.first_normal_slot, 524256);
    }
}
