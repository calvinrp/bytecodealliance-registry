#[macro_use]
extern crate lazy_static;

use bindings::exports::ba::registry::create_checkpoint::CreateCheckpoint;
use bindings::ba::registry::types::{Checkpoint, Leaf, HashErrno};

use warg_protocol::registry::{LogId, RecordId, LogLeaf, MapLeaf};
use warg_transparency::map::Map;
use warg_transparency::log::{LogBuilder, StackLog};
use warg_crypto::hash::{Sha256, AnyHash, AnyHashError};
use std::str::FromStr;
use std::sync::Mutex;

pub type VerifiableLog = StackLog<Sha256, LogLeaf>;
pub type VerifiableMap = Map<Sha256, LogId, MapLeaf>;

struct VerifiableState {
    log: VerifiableLog,
    map: VerifiableMap,
}

lazy_static! {
    static ref VERIFIABLE_STATE: Mutex<VerifiableState> = Mutex::new({
        VerifiableState{
            log: VerifiableLog::default(),
            map: VerifiableMap::default(),
        }
    });
}

struct Component;

impl CreateCheckpoint for Component {
    fn append_leafs(leafs: Vec<Leaf>) -> Result<(), HashErrno> {
        let mut state = VERIFIABLE_STATE.lock().unwrap();
        for leaf in leafs {
            let log_id = LogId::from(parse_hash(&leaf.log_id)?);
            let record_id = RecordId::from(parse_hash(&leaf.record_id)?);
            state.log.push(&LogLeaf{ log_id: log_id.clone(), record_id: record_id.clone() });
            state.map.insert(log_id, MapLeaf{ record_id });
        }

        Ok(())
    }

    fn create_checkpoint() -> Result<Checkpoint, ()> {
        let state = VERIFIABLE_STATE.lock().unwrap();

        let checkpoint = state.log.checkpoint();
        let log_root: AnyHash = checkpoint.root().into();
        let log_length = checkpoint.length() as u32;
        let map_root: AnyHash = state.map.root().clone().into();

        Ok(Checkpoint{
            log_length,
            log_root: log_root.to_string(),
            map_root: map_root.to_string(),
        })
    }
}

fn parse_hash(hash_str: &str) -> Result<AnyHash, HashErrno> {
    match AnyHash::from_str(&hash_str) {
        Ok(hash) => Ok(hash),
        Err(err) => Err(match err {
            AnyHashError::InvalidHashAlgorithm(_) => HashErrno::UnsupportedHashAlgorithm,
            _ => HashErrno::InvalidHash,
        }),
    }
}

bindings::export!(Component);

//use bindings::exports::ba::registry::checkpoint_hash::{CheckpointHash, CheckpointHashErrno};
//use warg_crypto::Encode;
//use warg_protocol::registry::{LogId, RecordId, LogLeaf, MapCheckpoint, MapLeaf};
//impl CheckpointHash for Component {
//    fn checkpoint_hash(checkpoint: Checkpoint) -> Result<String, CheckpointHashErrno> {
//        let log_root = match AnyHash::from_str(&checkpoint.log_root) {
//            Ok(log_root) => log_root,
//            Err(err) => return Err(match err {
//                AnyHashError::InvalidHashAlgorithm(_) => CheckpointHashErrno::LogRootUnsupportedHashAlgorithm,
//                _ => CheckpointHashErrno::LogRootInvalid,
//            }),
//        };
//
//        let map_root = match AnyHash::from_str(&checkpoint.map_root) {
//            Ok(map_root) => map_root,
//            Err(err) => return Err(match err {
//                AnyHashError::InvalidHashAlgorithm(_) => CheckpointHashErrno::MapRootUnsupportedHashAlgorithm,
//                _ => CheckpointHashErrno::MapRootInvalid,
//            }),
//        };
//
//        let map_checkpoint = MapCheckpoint{
//            log_length: checkpoint.log_length,
//            log_root,
//            map_root,
//        };
//
//        Ok(Encode::encode(&map_checkpoint).to_string())
//    }
//}

