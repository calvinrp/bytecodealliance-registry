#![feature(sync_unsafe_cell)]
//#[macro_use]
//extern crate lazy_static;

use bindings::exports::warg::log_proofs::log_state::{AppendLeafErrno, LogState};
use bindings::exports::warg::log_proofs::log_consistency::{ProofConsistencyErrno, LogConsistency};
use bindings::exports::warg::log_proofs::log_inclusion::{ProofInclusionError, LogInclusion};

use bindings::warg::log_proofs::types::{Leaf, ProofBundle, Index};

use std::str::FromStr;
//use std::sync::Mutex;
use std::cell::SyncUnsafeCell;
use warg_crypto::hash::{AnyHash, Sha256};
use warg_protocol::registry::{LogLeaf, RecordId, LogId};
use warg_transparency::log::{VecLog, LogBuilder, LogProofBundle, LogData, Node};

//lazy_static! {
//    static ref VEC_LOG: Mutex<VecLog<Sha256, LogLeaf>> =
//        Mutex::new(VecLog::default());
//}

static mut VEC_LOG: SyncUnsafeCell<Option<VecLog<Sha256, LogLeaf>>> = SyncUnsafeCell::new(
    None
);

struct Component;

impl LogState for Component {
    fn append_leaf(leaf: Leaf) -> Result<Index, AppendLeafErrno> {
        let log_id = match AnyHash::from_str(&leaf.log_id) {
            Ok(log_id) => LogId::from(log_id),
            Err(_) => return Err(AppendLeafErrno::InvalidLogId),
        };
        let record_id = match AnyHash::from_str(&leaf.record_id) {
            Ok(record_id) => RecordId::from(record_id),
            Err(_) => return Err(AppendLeafErrno::InvalidRecordId),
        };
        let leaf = LogLeaf{ log_id, record_id };
        //let mut vec_log = VEC_LOG.lock().unwrap();
        let vec_log = match unsafe { VEC_LOG.get_mut() } {
            Some(vec_log) => vec_log,
            None => {
                unsafe { *VEC_LOG.get() = Some(VecLog::default()) };
                unsafe {
                    match VEC_LOG.get_mut() {
                        Some(vec_log) => vec_log,
                        None => return Err(AppendLeafErrno::UnexpectedFailure)
                    }
                }
            }
        };
        let node = vec_log.push(&leaf);
        Ok(node.0 as u32)
    }
}

impl LogConsistency for Component {
    fn prove_log_consistency(starting_log_length: u32, ending_log_length: u32) -> Result<ProofBundle, ProofConsistencyErrno> {
        //let mut vec_log = VEC_LOG.lock().unwrap();
        let vec_log = match unsafe { VEC_LOG.get_mut() } {
            Some(vec_log) => vec_log,
            None => return Err(ProofConsistencyErrno::LogEmpty),
        };
        let proof = vec_log.prove_consistency(starting_log_length as usize, ending_log_length as usize);
        match LogProofBundle::bundle(vec![proof], vec![], vec_log) {
            Ok(bundle) => Ok(bundle.encode()),
            Err(_) => Err(ProofConsistencyErrno::ProofBundleFailed),
        }
    }
}

impl LogInclusion for Component {
    fn prove_log_inclusion(log_length: u32, leaf_indices: Vec<u32>) -> Result<ProofBundle, ProofInclusionError> {
        let vec_log = match unsafe { VEC_LOG.get_mut() } {
            Some(vec_log) => vec_log,
            None => return Err(ProofInclusionError::LogEmpty),
        };
        let mut proofs = Vec::with_capacity(leaf_indices.len());
        for leaf_index in leaf_indices {
            proofs.push(vec_log.prove_inclusion(Node(leaf_index as usize), log_length as usize));
        }
        match LogProofBundle::bundle(vec![], proofs, vec_log) {
            Ok(bundle) => Ok(bundle.encode()),
            Err(_) => Err(ProofInclusionError::ProofBundleFailed),
        }
    }
}

bindings::export!(Component);
