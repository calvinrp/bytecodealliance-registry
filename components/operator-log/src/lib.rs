#[macro_use]
extern crate lazy_static;

use bindings::exports::warg::operator_log::operator_records::{
    EncodedOperatorRecord, Envelope, OperatorDecodeErrno, OperatorEncodeErrno, OperatorEntry,
    OperatorGrantFlat, OperatorInit, OperatorPermission, OperatorRecord, OperatorRecords,
    OperatorRevokeFlat, OperatorValidationError, RecordId, UnauthorizedPermissionError,
    UnexpectedHashAlgorithm,
};
use bindings::warg::operator_log::types::Timestamp;

use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use warg_crypto::hash::{AnyHash, HashAlgorithm, Sha256};
use warg_crypto::signing::{PublicKey, Signature};
use warg_crypto::{Decode, Encode};
use warg_protocol::operator;
use warg_protocol::operator::ValidationError::{
    FirstEntryIsNotInit, IncorrectHashAlgorithm, InitialEntryAfterBeginning,
    InitialRecordDoesNotInit, KeyIDNotRecognized, NoPreviousHashAfterInit,
    PermissionNotFoundToRevoke, PreviousHashOnFirstRecord, ProtocolVersionNotAllowed,
    RecordHashDoesNotMatch, SignatureError, TimestampLowerThanPrevious, UnauthorizedAction,
};
use warg_protocol::registry::RecordId as WargRecordId;

lazy_static! {
    static ref OPERATOR_LOG_STATE: Mutex<operator::LogState> =
        Mutex::new(operator::LogState::new());
}

struct Component;

impl OperatorRecords for Component {
    fn append_operator_record(envelope: Envelope) -> Result<RecordId, OperatorValidationError> {
        let signature = match Signature::from_str(&envelope.signature) {
            Ok(signature) => signature,
            Err(_) => return Err(OperatorValidationError::SignatureParseFailure),
        };
        let contents = match operator::OperatorRecord::decode(&envelope.content_bytes) {
            Ok(rec) => rec,
            Err(_) => return Err(OperatorValidationError::FailedToDecodeOperatorRecord),
        };
        let proto_envelope = warg_protocol::ProtoEnvelope::<operator::OperatorRecord> {
            contents,
            content_bytes: envelope.content_bytes,
            key_id: envelope.key_id.into(),
            signature,
        };

        let mut state = OPERATOR_LOG_STATE.lock().unwrap();
        match state.validate(&proto_envelope) {
            Ok(_) => match state.head() {
                Some(head) => Ok(head.digest.to_string()),
                None => Err(OperatorValidationError::UnexpectedValidationError),
            },
            Err(FirstEntryIsNotInit) => Err(OperatorValidationError::FirstEntryIsNotInit),
            Err(InitialRecordDoesNotInit) => Err(OperatorValidationError::InitialRecordDoesNotInit),
            Err(KeyIDNotRecognized { key_id }) => Err(OperatorValidationError::KeyIdNotRecognized(
                key_id.to_string(),
            )),
            Err(InitialEntryAfterBeginning) => {
                Err(OperatorValidationError::InitialEntryAfterBeginning)
            }
            Err(UnauthorizedAction {
                key_id,
                needed_permission,
            }) => {
                let permission = match needed_permission {
                    operator::Permission::Commit => OperatorPermission::Commit,
                    _ => return Err(OperatorValidationError::UnknownOperatorPermission),
                };
                Err(OperatorValidationError::UnauthorizedAction(
                    UnauthorizedPermissionError {
                        key_id: key_id.to_string(),
                        permission,
                    },
                ))
            }
            Err(PermissionNotFoundToRevoke { key_id, permission }) => {
                let permission = match permission {
                    operator::Permission::Commit => OperatorPermission::Commit,
                    _ => return Err(OperatorValidationError::UnknownOperatorPermission),
                };
                Err(OperatorValidationError::PermissionNotFoundToRevoke(
                    UnauthorizedPermissionError {
                        key_id: key_id.to_string(),
                        permission,
                    },
                ))
            }
            Err(SignatureError(_)) => Err(OperatorValidationError::SignatureInvalid),
            Err(IncorrectHashAlgorithm { found, expected }) => Err(
                OperatorValidationError::IncorrectHashAlgorithm(UnexpectedHashAlgorithm {
                    found: found.to_string(),
                    expected: expected.to_string(),
                }),
            ),

            Err(RecordHashDoesNotMatch) => Err(OperatorValidationError::RecordHashDoesNotMatch),
            Err(PreviousHashOnFirstRecord) => {
                Err(OperatorValidationError::PreviousHashOnFirstRecord)
            }
            Err(NoPreviousHashAfterInit) => Err(OperatorValidationError::NoPreviousHashAfterInit),
            Err(ProtocolVersionNotAllowed { version }) => {
                Err(OperatorValidationError::ProtocolVersionNotAllowed(version))
            }
            Err(TimestampLowerThanPrevious) => {
                Err(OperatorValidationError::TimestampLowerThanPrevious)
            }
        }
    }

    fn encode_operator_record(
        rec: OperatorRecord,
    ) -> Result<EncodedOperatorRecord, OperatorEncodeErrno> {
        let prev = match rec.prev {
            Some(id) => match AnyHash::from_str(&id) {
                Ok(id) => Some(id),
                Err(_) => return Err(OperatorEncodeErrno::PrevRecordIdInvalidFormat),
            },
            None => None,
        };

        let mut entries: Vec<operator::OperatorEntry> = Vec::with_capacity(rec.entries.len());

        for entry in rec.entries {
            entries.push(match entry {
                OperatorEntry::OperatorInit(OperatorInit {
                    hash_algorithm,
                    key,
                }) => {
                    let hash_algorithm = match HashAlgorithm::from_str(&hash_algorithm) {
                        Ok(algo) => algo,
                        Err(_) => return Err(OperatorEncodeErrno::UnsupportedHashAlgorithm),
                    };
                    let key = match PublicKey::from_str(&key) {
                        Ok(key) => key,
                        Err(_) => return Err(OperatorEncodeErrno::PublicKeyParseFailure),
                    };
                    operator::OperatorEntry::Init {
                        hash_algorithm,
                        key,
                    }
                }
                OperatorEntry::OperatorGrantFlat(OperatorGrantFlat { key, permission }) => {
                    let key = match PublicKey::from_str(&key) {
                        Ok(key) => key,
                        Err(_) => return Err(OperatorEncodeErrno::PublicKeyParseFailure),
                    };
                    operator::OperatorEntry::GrantFlat {
                        key,
                        permission: match permission {
                            OperatorPermission::Commit => operator::Permission::Commit,
                            //_ => return Err(OperatorEncodeErrno::UnknownOperatorPermission),
                        },
                    }
                }
                OperatorEntry::OperatorRevokeFlat(OperatorRevokeFlat { key, permission }) => {
                    operator::OperatorEntry::RevokeFlat {
                        key_id: key.into(),
                        permission: match permission {
                            OperatorPermission::Commit => operator::Permission::Commit,
                            //_ => return Err(OperatorEncodeErrno::UnknownOperatorPermission),
                        },
                    }
                } //_ => return Err(OperatorEncodeErrno::UnknownOperatorEntry),
            });
        }

        let prev: Option<WargRecordId> = match prev {
            Some(prev) => Some(prev.into()),
            None => None,
        };

        let operator_record = operator::OperatorRecord {
            prev,
            version: rec.version,
            timestamp: SystemTime::UNIX_EPOCH
                + Duration::new(rec.timestamp.seconds as u64, rec.timestamp.nanos as u32),
            entries,
        };

        let content_bytes = Encode::encode(&operator_record);
        let record_id = WargRecordId::operator_record::<Sha256>(&content_bytes).to_string();

        Ok(EncodedOperatorRecord {
            content_bytes,
            record_id,
        })
    }
    fn decode_operator_record(bytes: Vec<u8>) -> Result<OperatorRecord, OperatorDecodeErrno> {
        let rec = match operator::OperatorRecord::decode(&bytes) {
            Ok(rec) => rec,
            Err(_) => return Err(OperatorDecodeErrno::FailedToDecode),
        };

        let duration_since_epoch = match rec.timestamp.duration_since(UNIX_EPOCH) {
            Ok(duration_since_epoch) => duration_since_epoch,
            Err(_) => return Err(OperatorDecodeErrno::FailedToDecode),
        };

        let mut entries: Vec<OperatorEntry> = Vec::with_capacity(rec.entries.len());

        for entry in rec.entries {
            entries.push(match entry {
                operator::OperatorEntry::Init {
                    hash_algorithm,
                    key,
                } => OperatorEntry::OperatorInit(OperatorInit {
                    hash_algorithm: hash_algorithm.to_string(),
                    key: key.to_string(),
                }),
                operator::OperatorEntry::GrantFlat { key, permission } => {
                    OperatorEntry::OperatorGrantFlat(OperatorGrantFlat {
                        key: key.to_string(),
                        permission: match permission {
                            operator::Permission::Commit => OperatorPermission::Commit,
                            _ => return Err(OperatorDecodeErrno::UnknownOperatorPermission),
                        },
                    })
                }
                operator::OperatorEntry::RevokeFlat { key_id, permission } => {
                    OperatorEntry::OperatorRevokeFlat(OperatorRevokeFlat {
                        key: key_id.to_string(),
                        permission: match permission {
                            operator::Permission::Commit => OperatorPermission::Commit,
                            _ => return Err(OperatorDecodeErrno::UnknownOperatorPermission),
                        },
                    })
                }
                _ => return Err(OperatorDecodeErrno::UnknownOperatorEntry),
            });
        }

        Ok(OperatorRecord {
            prev: rec.prev.map(|hash| hash.to_string()),
            version: rec.version,
            timestamp: Timestamp {
                seconds: duration_since_epoch.as_secs() as i64,
                nanos: duration_since_epoch.subsec_nanos() as i32,
            },
            entries,
        })
    }
}

bindings::export!(Component);
