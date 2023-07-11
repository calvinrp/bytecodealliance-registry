#![feature(sync_unsafe_cell)]

#[macro_use]
extern crate lazy_static;

use std::cell::SyncUnsafeCell;
use std::sync::Mutex;
use warg_crypto::hash::{AnyHash, HashAlgorithm, Sha256};
use warg_protocol::registry::{LogId, LogLeaf, MapLeaf, RecordId};
use warg_transparency::log::{LogBuilder, StackLog};
use warg_transparency::map::Map;

pub type VerifiableLog = StackLog<Sha256, LogLeaf>;
pub type VerifiableMap = Map<Sha256, LogId, MapLeaf>;

#[repr(C)]
pub struct Checkpoint {
    pub log_length: u32,
    pub log_root: [u8; 64],
    pub map_root: [u8; 64],
}

#[repr(C)]
pub struct Leaf {
    pub log_id: [u8; 64],
    pub record_id: [u8; 64],
}

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

static mut CHECKPOINT: SyncUnsafeCell<Checkpoint> = SyncUnsafeCell::new(
    Checkpoint{ log_length: 0, log_root: [0; 64], map_root: [0; 64] }
);
static mut LEAF: SyncUnsafeCell<Leaf> = SyncUnsafeCell::new(Leaf{ log_id: [0; 64], record_id: [0; 64] });

//#[export_name = "wizer.initialize"]
//pub extern "C" fn init() {
//}

#[no_mangle]
pub extern "C" fn leaf_ptr() -> &'static mut Leaf {
    unsafe { LEAF.get_mut() }
}

#[no_mangle]
pub extern "C" fn append_leaf() {
    let mut state = VERIFIABLE_STATE.lock().unwrap();
    let leaf = unsafe { LEAF.get_mut() };
    let log_id = LogId::from(AnyHash::new(HashAlgorithm::Sha256, hex::decode(leaf.log_id).unwrap()));
    let record_id = RecordId::from(AnyHash::new(HashAlgorithm::Sha256, hex::decode(leaf.record_id).unwrap()));
    state.log.push(&LogLeaf {
        log_id: log_id.clone(),
        record_id: record_id.clone(),
    });
    state.map.insert(log_id, MapLeaf { record_id });
}

#[no_mangle]
pub extern "C" fn create_checkpoint() -> &'static mut Checkpoint {
    let state = VERIFIABLE_STATE.lock().unwrap();

    let checkpoint = state.log.checkpoint();
    let log_root: AnyHash = checkpoint.root().into();
    let log_length = checkpoint.length() as u32;
    let map_root: AnyHash = state.map.root().clone().into();

    let cp = unsafe { CHECKPOINT.get_mut() };
    cp.log_root.copy_from_slice(hex::encode(log_root.bytes()).as_bytes());
    cp.map_root.copy_from_slice(hex::encode(map_root.bytes()).as_bytes());
    cp.log_length = log_length;

    cp
}
