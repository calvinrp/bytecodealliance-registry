cargo_component_bindings::generate!();

use bindings::exports::warg::map_proofs::generate_map_proofs::{
    AppendLeafErrno, GenerateMapProofs, ProofInclusionError,
};

use bindings::warg::map_proofs::types::{Hash, Leaf, ProofBundle};

use std::str::FromStr;
use std::unreachable;
use sync_unsafe_cell::SyncUnsafeCell;
use warg_crypto::hash::{AnyHash, Sha256};
use warg_protocol::registry::{LogId, MapLeaf, RecordId};
use warg_transparency::map::{Map, MapProofBundle};

type VerifiableMap = Map<Sha256, LogId, MapLeaf>;

static mut MAP: SyncUnsafeCell<Option<VerifiableMap>> = SyncUnsafeCell::new(None);

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

struct Component;

impl GenerateMapProofs for Component {
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
        unsafe { *MAP.get() = Some(map.insert(log_id, MapLeaf { record_id })) };
        Ok(())
    }

    fn prove_map_inclusion(
        map_checkpoint: Hash,
        leafs: Vec<Leaf>,
    ) -> Result<ProofBundle, ProofInclusionError> {
        let map_checkpoint = AnyHash::from_str(&map_checkpoint)
            .map_err(|_| ProofInclusionError::InvalidMapCheckpoint)?
            .try_into()
            .map_err(|_| ProofInclusionError::InvalidMapCheckpoint)?;
        let map = match unsafe { MAP.get_mut() } {
            Some(map) => map,
            None => return Err(ProofInclusionError::MapEmpty),
        };

        let mut proofs = Vec::with_capacity(leafs.len());
        for leaf in leafs {
            let log_id = match AnyHash::from_str(&leaf.log_id) {
                Ok(log_id) => LogId::from(log_id),
                Err(_) => return Err(ProofInclusionError::InvalidLogId(leaf.log_id)),
            };
            let record_id = match AnyHash::from_str(&leaf.record_id) {
                Ok(record_id) => RecordId::from(record_id),
                Err(_) => return Err(ProofInclusionError::InvalidRecordId(leaf.record_id)),
            };

            let proof = map
                .prove(log_id.clone())
                .ok_or_else(|| ProofInclusionError::LogIdNotFound(leaf.log_id))?;
            let found_root = proof.evaluate(&log_id, &MapLeaf { record_id });
            if found_root != map_checkpoint {
                return Err(ProofInclusionError::MapCheckpointDoesNotMatch);
            }
            proofs.push(proof);
        }

        Ok(MapProofBundle::bundle(proofs).encode())
    }
}
