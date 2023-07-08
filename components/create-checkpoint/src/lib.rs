use bindings::exports::ba::registry::{CheckpointHash, CreateCheckpoint};

struct Component;

struct Checkpoint {
    log_length: u32,
    log_root: String,
    map_root: String,
}

struct Leaf {
    log_id: String,
    record_id: String,
}

impl CheckpointHash for Component {
    fn checkpoint_hash(checkpoint: Checkpoint) -> String {
        "sha256:deadbeef!".to_string()
    }
}

impl CreateCheckpoint for Component {
    fn append_leaf(leafs: Vec<Leaf>) -> bool {
        true
    }

    fn create_checkpoint() -> Result<Checkpoint, _> {
        Ok(Checkpoint{
            log_length: 1,
            log_root: "sha256:deadbeef".to_string(),
            map_root: "sha256:deadbeef".to_string(),
        })
    }
}

bindings::export!(Component);
