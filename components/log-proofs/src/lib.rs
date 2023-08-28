cargo_component_bindings::generate!();

use bindings::exports::warg::log_proofs::generate_log_proofs::{
    AppendLeafErrno, GenerateLogProofs, ProofConsistencyErrno, ProofInclusionError,
};

use bindings::warg::log_proofs::types::{Index, Leaf, ProofBundle};

use std::str::FromStr;
use std::unreachable;
use sync_unsafe_cell::SyncUnsafeCell;
use warg_crypto::hash::{AnyHash, Sha256};
use warg_protocol::registry::{LogId, LogLeaf, RecordId};
use warg_transparency::log::{LogBuilder, LogData, LogProofBundle, Node, VecLog};

type Log = VecLog<Sha256, LogLeaf>;

static mut VEC_LOG: SyncUnsafeCell<Option<Log>> = SyncUnsafeCell::new(None);

fn get_log() -> &'static mut Log {
    match unsafe { VEC_LOG.get_mut() } {
        Some(log) => log,
        None => {
            unsafe { *VEC_LOG.get() = Some(Log::default()) };
            unsafe {
                match VEC_LOG.get_mut() {
                    Some(log) => log,
                    None => unreachable!(),
                }
            }
        }
    }
}

struct Component;

impl GenerateLogProofs for Component {
    fn append_leaf(leaf: Leaf) -> Result<Index, AppendLeafErrno> {
        let log_id = match AnyHash::from_str(&leaf.log_id) {
            Ok(log_id) => LogId::from(log_id),
            Err(_) => return Err(AppendLeafErrno::InvalidLogId),
        };
        let record_id = match AnyHash::from_str(&leaf.record_id) {
            Ok(record_id) => RecordId::from(record_id),
            Err(_) => return Err(AppendLeafErrno::InvalidRecordId),
        };
        let leaf = LogLeaf { log_id, record_id };
        let log = get_log();
        let node = log.push(&leaf);
        Ok(node.0 as u32)
    }

    fn prove_log_consistency(
        starting_log_length: u32,
        ending_log_length: u32,
    ) -> Result<ProofBundle, ProofConsistencyErrno> {
        let vec_log = match unsafe { VEC_LOG.get_mut() } {
            Some(vec_log) => vec_log,
            None => return Err(ProofConsistencyErrno::LogEmpty),
        };
        let proof =
            vec_log.prove_consistency(starting_log_length as usize, ending_log_length as usize);
        match LogProofBundle::bundle(vec![proof], vec![], vec_log) {
            Ok(bundle) => Ok(bundle.encode()),
            Err(_) => Err(ProofConsistencyErrno::ProofBundleFailed),
        }
    }

    fn prove_log_inclusion(
        log_length: u32,
        leaf_indices: Vec<u32>,
    ) -> Result<ProofBundle, ProofInclusionError> {
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
