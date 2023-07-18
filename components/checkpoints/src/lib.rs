use bindings::exports::warg::registry::compute_checkpoint::{AppendLeafErrno, ComputeCheckpoint};
use bindings::warg::registry::types::{Checkpoint, Leaf};

use std::str::FromStr;
use std::unreachable;
use sync_unsafe_cell::SyncUnsafeCell;
use warg_crypto::hash::{AnyHash, Sha256};
use warg_protocol::registry::{LogId, LogLeaf, MapLeaf, RecordId};
use warg_transparency::log::{LogBuilder, StackLog};
use warg_transparency::map::Map;

type VerifiableLog = StackLog<Sha256, LogLeaf>;
type VerifiableMap = Map<Sha256, LogId, MapLeaf>;

static mut MAP: SyncUnsafeCell<Option<VerifiableMap>> = SyncUnsafeCell::new(None);
static mut LOG: SyncUnsafeCell<Option<VerifiableLog>> = SyncUnsafeCell::new(None);

fn get_map() -> &'static mut VerifiableMap {
    match unsafe { MAP.get_mut() } {
        Some(map) => map,
        None => {
            unsafe { *MAP.get() = Some(VerifiableMap::default()) };
            unsafe {
                match MAP.get_mut() {
                    Some(map) => map,
                    None => unreachable!(),
                }
            }
        }
    }
}
fn get_log() -> &'static mut VerifiableLog {
    match unsafe { LOG.get_mut() } {
        Some(log) => log,
        None => {
            unsafe { *LOG.get() = Some(VerifiableLog::default()) };
            unsafe {
                match LOG.get_mut() {
                    Some(log) => log,
                    None => unreachable!(),
                }
            }
        }
    }
}

struct Component;

impl ComputeCheckpoint for Component {
    fn append_leaf(leaf: Leaf) -> Result<(), AppendLeafErrno> {
        let log_id = match AnyHash::from_str(&leaf.log_id) {
            Ok(log_id) => LogId::from(log_id),
            Err(_) => return Err(AppendLeafErrno::InvalidLogId),
        };
        let record_id = match AnyHash::from_str(&leaf.record_id) {
            Ok(record_id) => RecordId::from(record_id),
            Err(_) => return Err(AppendLeafErrno::InvalidRecordId),
        };

        let map = get_map();
        map.insert(
            log_id.clone(),
            MapLeaf {
                record_id: record_id.clone(),
            },
        );
        let log = get_log();
        log.push(&LogLeaf { log_id, record_id });

        Ok(())
    }

    fn compute_checkpoint() -> Result<Checkpoint, ()> {
        let map = get_map();
        let log = get_log();

        let log_checkpoint = log.checkpoint();
        let log_root: AnyHash = log_checkpoint.root().into();
        let log_length = log_checkpoint.length() as u32;
        let map_root: AnyHash = map.root().clone().into();

        Ok(Checkpoint {
            log_length,
            log_root: log_root.to_string(),
            map_root: map_root.to_string(),
        })
    }
}

bindings::export!(Component);
