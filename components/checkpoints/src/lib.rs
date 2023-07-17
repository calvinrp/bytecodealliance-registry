#[macro_use]
extern crate lazy_static;

use bindings::warg::registry::types::{Checkpoint, Leaf};
use bindings::exports::warg::registry::compute_checkpoint::ComputeCheckpoint;

use std::sync::Mutex;
use warg_crypto::hash::{AnyHash, HashAlgorithm, Sha256};
use warg_protocol::registry::{LogId, LogLeaf, MapLeaf, RecordId};
use warg_transparency::log::{LogBuilder, StackLog};
use warg_transparency::map::Map;

pub type VerifiableLog = StackLog<Sha256, LogLeaf>;
pub type VerifiableMap = Map<Sha256, LogId, MapLeaf>;

struct VerifiableState {
    log: VerifiableLog,
    map: VerifiableMap,
}

lazy_static! {
    static ref VERIFIABLE_STATE: Mutex<VerifiableState> = Mutex::new({
        VerifiableState {
            log: VerifiableLog::default(),
            map: VerifiableMap::default(),
        }
    });
}

struct Component;

impl ComputeCheckpoint for Component {
    fn append_leaf(leaf: Leaf) {
        let mut state = VERIFIABLE_STATE.lock().unwrap();
        let log_id = LogId::from(AnyHash::new(HashAlgorithm::Sha256, leaf.log_id));
        let record_id = RecordId::from(AnyHash::new(HashAlgorithm::Sha256, leaf.record_id));
        state.log.push(&LogLeaf {
            log_id: log_id.clone(),
            record_id: record_id.clone(),
        });
        state.map.insert(log_id, MapLeaf { record_id });
    }

    fn compute_checkpoint() -> Checkpoint {
        let state = VERIFIABLE_STATE.lock().unwrap();

        let checkpoint = state.log.checkpoint();
        let log_root: AnyHash = checkpoint.root().into();
        let log_length = checkpoint.length() as u32;
        let map_root: AnyHash = state.map.root().clone().into();

        Checkpoint {
            log_length,
            log_root: log_root.bytes().to_vec(),
            map_root: map_root.bytes().to_vec(),
        }
    }
}

bindings::export!(Component);
