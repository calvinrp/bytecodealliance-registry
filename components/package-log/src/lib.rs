use bindings::exports::warg::package_log::package_records::{
    EncodedPackageRecord, Envelope, PackageDecodeErrno, PackageEncodeErrno, PackageEntry,
    PackageGrantFlat, PackageInit, PackagePermission, PackageRecord, PackageRecords,
    PackageRelease, PackageRevokeFlat, PackageValidationError, PackageYank, RecordId,
    UnauthorizedPermissionError, UnexpectedHashAlgorithm,
};
use bindings::warg::package_log::types::Timestamp;

use semver::Version;
use std::str::FromStr;
use std::unreachable;
use sync_unsafe_cell::SyncUnsafeCell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use warg_crypto::hash::{AnyHash, HashAlgorithm, Sha256};
use warg_crypto::signing::{PublicKey, Signature};
use warg_crypto::{Decode, Encode};
use warg_protocol::package;
use warg_protocol::package::ValidationError::{
    FirstEntryIsNotInit, IncorrectHashAlgorithm, InitialEntryAfterBeginning,
    InitialRecordDoesNotInit, KeyIDNotRecognized, NoPreviousHashAfterInit,
    PermissionNotFoundToRevoke, PreviousHashOnFirstRecord, ProtocolVersionNotAllowed,
    RecordHashDoesNotMatch, ReleaseOfReleased, SignatureError, TimestampLowerThanPrevious,
    UnauthorizedAction, YankOfUnreleased, YankOfYanked,
};
use warg_protocol::registry::RecordId as WargRecordId;

static mut STATE: SyncUnsafeCell<Option<package::LogState>> = SyncUnsafeCell::new(None);

fn get_state() -> &'static mut package::LogState {
    match unsafe { STATE.get_mut() } {
        Some(state) => state,
        None => {
            unsafe { *STATE.get() = Some(package::LogState::default()) };
            unsafe {
                match STATE.get_mut() {
                    Some(state) => state,
                    None => unreachable!(),
                }
            }
        }
    }
}

struct Component;

impl PackageRecords for Component {
    fn append_package_record(envelope: Envelope) -> Result<RecordId, PackageValidationError> {
        let signature = match Signature::from_str(&envelope.signature) {
            Ok(signature) => signature,
            Err(_) => return Err(PackageValidationError::SignatureParseFailure),
        };
        let contents = match package::PackageRecord::decode(&envelope.content_bytes) {
            Ok(rec) => rec,
            Err(_) => return Err(PackageValidationError::FailedToDecodeOperatorRecord),
        };
        let proto_envelope = warg_protocol::ProtoEnvelope::<package::PackageRecord> {
            contents,
            content_bytes: envelope.content_bytes,
            key_id: envelope.key_id.into(),
            signature,
        };

        let state = get_state();
        match state.validate(&proto_envelope) {
            Ok(_) => match state.head() {
                Some(head) => Ok(head.digest.to_string()),
                None => Err(PackageValidationError::UnexpectedValidationError),
            },
            Err(FirstEntryIsNotInit) => Err(PackageValidationError::FirstEntryIsNotInit),
            Err(InitialRecordDoesNotInit) => Err(PackageValidationError::InitialRecordDoesNotInit),
            Err(KeyIDNotRecognized { key_id }) => Err(PackageValidationError::KeyIdNotRecognized(
                key_id.to_string(),
            )),
            Err(InitialEntryAfterBeginning) => {
                Err(PackageValidationError::InitialEntryAfterBeginning)
            }
            Err(UnauthorizedAction {
                key_id,
                needed_permission,
            }) => {
                let permission = match needed_permission {
                    package::Permission::Release => PackagePermission::Release,
                    package::Permission::Yank => PackagePermission::Yank,
                    _ => return Err(PackageValidationError::UnknownPackagePermission),
                };
                Err(PackageValidationError::UnauthorizedAction(
                    UnauthorizedPermissionError {
                        key_id: key_id.to_string(),
                        permission,
                    },
                ))
            }
            Err(PermissionNotFoundToRevoke { key_id, permission }) => {
                let permission = match permission {
                    package::Permission::Release => PackagePermission::Release,
                    package::Permission::Yank => PackagePermission::Yank,
                    _ => return Err(PackageValidationError::UnknownPackagePermission),
                };
                Err(PackageValidationError::PermissionNotFoundToRevoke(
                    UnauthorizedPermissionError {
                        key_id: key_id.to_string(),
                        permission,
                    },
                ))
            }
            Err(ReleaseOfReleased { version }) => Err(PackageValidationError::ReleaseOfReleased(
                version.to_string(),
            )),
            Err(YankOfUnreleased { version }) => Err(PackageValidationError::YankOfUnreleased(
                version.to_string(),
            )),
            Err(YankOfYanked { version }) => {
                Err(PackageValidationError::YankOfYanked(version.to_string()))
            }
            Err(SignatureError(_)) => Err(PackageValidationError::SignatureInvalid),
            Err(IncorrectHashAlgorithm { found, expected }) => Err(
                PackageValidationError::IncorrectHashAlgorithm(UnexpectedHashAlgorithm {
                    found: found.to_string(),
                    expected: expected.to_string(),
                }),
            ),

            Err(RecordHashDoesNotMatch) => Err(PackageValidationError::RecordHashDoesNotMatch),
            Err(PreviousHashOnFirstRecord) => {
                Err(PackageValidationError::PreviousHashOnFirstRecord)
            }
            Err(NoPreviousHashAfterInit) => Err(PackageValidationError::NoPreviousHashAfterInit),
            Err(ProtocolVersionNotAllowed { version }) => {
                Err(PackageValidationError::ProtocolVersionNotAllowed(version))
            }
            Err(TimestampLowerThanPrevious) => {
                Err(PackageValidationError::TimestampLowerThanPrevious)
            }
        }
    }

    fn encode_package_record(
        rec: PackageRecord,
    ) -> Result<EncodedPackageRecord, PackageEncodeErrno> {
        let prev = match rec.prev {
            Some(id) => match AnyHash::from_str(&id) {
                Ok(id) => Some(id),
                Err(_) => return Err(PackageEncodeErrno::PrevRecordIdInvalidFormat),
            },
            None => None,
        };

        let mut entries: Vec<package::PackageEntry> = Vec::with_capacity(rec.entries.len());

        for entry in rec.entries {
            entries.push(match entry {
                PackageEntry::PackageInit(PackageInit {
                    hash_algorithm,
                    key,
                }) => {
                    let hash_algorithm = match HashAlgorithm::from_str(&hash_algorithm) {
                        Ok(algo) => algo,
                        Err(_) => return Err(PackageEncodeErrno::UnsupportedHashAlgorithm),
                    };
                    let key = match PublicKey::from_str(&key) {
                        Ok(key) => key,
                        Err(_) => return Err(PackageEncodeErrno::PublicKeyParseFailure),
                    };
                    package::PackageEntry::Init {
                        hash_algorithm,
                        key,
                    }
                }
                PackageEntry::PackageGrantFlat(PackageGrantFlat { key, permission }) => {
                    let key = match PublicKey::from_str(&key) {
                        Ok(key) => key,
                        Err(_) => return Err(PackageEncodeErrno::PublicKeyParseFailure),
                    };
                    package::PackageEntry::GrantFlat {
                        key,
                        permission: match permission {
                            PackagePermission::Release => package::Permission::Release,
                            PackagePermission::Yank => package::Permission::Yank,
                            //_ => return Err(PackageEncodeErrno::UnknownPackagePermission),
                        },
                    }
                }
                PackageEntry::PackageRevokeFlat(PackageRevokeFlat { key, permission }) => {
                    package::PackageEntry::RevokeFlat {
                        key_id: key.into(),
                        permission: match permission {
                            PackagePermission::Release => package::Permission::Release,
                            PackagePermission::Yank => package::Permission::Yank,
                            //_ => return Err(PackageEncodeErrno::UnknownPackagePermission),
                        },
                    }
                }
                PackageEntry::PackageRelease(PackageRelease {
                    version,
                    content_digest,
                }) => {
                    let version = match Version::parse(&version) {
                        Ok(version) => version,
                        Err(_) => return Err(PackageEncodeErrno::PackageVersionParseError),
                    };
                    let content = match AnyHash::from_str(&content_digest) {
                        Ok(hash) => hash,
                        Err(_) => return Err(PackageEncodeErrno::ContentDigestParseError),
                    };
                    package::PackageEntry::Release { version, content }
                }
                PackageEntry::PackageYank(PackageYank { version }) => {
                    let version = match Version::parse(&version) {
                        Ok(version) => version,
                        Err(_) => return Err(PackageEncodeErrno::PackageVersionParseError),
                    };
                    package::PackageEntry::Yank { version }
                } //_ => return Err(PackageEncodeErrno::UnknownPackageEntry),
            });
        }

        let prev: Option<WargRecordId> = match prev {
            Some(prev) => Some(prev.into()),
            None => None,
        };

        let package_record = package::PackageRecord {
            prev,
            version: rec.version,
            timestamp: SystemTime::UNIX_EPOCH
                + Duration::new(rec.timestamp.seconds as u64, rec.timestamp.nanos as u32),
            entries,
        };

        let content_bytes = Encode::encode(&package_record);
        let record_id = WargRecordId::package_record::<Sha256>(&content_bytes).to_string();

        Ok(EncodedPackageRecord {
            content_bytes,
            record_id,
        })
    }
    fn decode_package_record(bytes: Vec<u8>) -> Result<PackageRecord, PackageDecodeErrno> {
        let rec = match package::PackageRecord::decode(&bytes) {
            Ok(rec) => rec,
            Err(_) => return Err(PackageDecodeErrno::FailedToDecode),
        };

        let duration_since_epoch = match rec.timestamp.duration_since(UNIX_EPOCH) {
            Ok(duration_since_epoch) => duration_since_epoch,
            Err(_) => return Err(PackageDecodeErrno::FailedToDecode),
        };

        let mut entries: Vec<PackageEntry> = Vec::with_capacity(rec.entries.len());

        for entry in rec.entries {
            entries.push(match entry {
                package::PackageEntry::Init {
                    hash_algorithm,
                    key,
                } => PackageEntry::PackageInit(PackageInit {
                    hash_algorithm: hash_algorithm.to_string(),
                    key: key.to_string(),
                }),
                package::PackageEntry::GrantFlat { key, permission } => {
                    PackageEntry::PackageGrantFlat(PackageGrantFlat {
                        key: key.to_string(),
                        permission: match permission {
                            package::Permission::Release => PackagePermission::Release,
                            package::Permission::Yank => PackagePermission::Yank,
                            _ => return Err(PackageDecodeErrno::UnknownPackagePermission),
                        },
                    })
                }
                package::PackageEntry::RevokeFlat { key_id, permission } => {
                    PackageEntry::PackageRevokeFlat(PackageRevokeFlat {
                        key: key_id.to_string(),
                        permission: match permission {
                            package::Permission::Release => PackagePermission::Release,
                            package::Permission::Yank => PackagePermission::Yank,
                            _ => return Err(PackageDecodeErrno::UnknownPackagePermission),
                        },
                    })
                }
                package::PackageEntry::Release { version, content } => {
                    PackageEntry::PackageRelease(PackageRelease {
                        version: version.to_string(),
                        content_digest: content.to_string(),
                    })
                }
                package::PackageEntry::Yank { version } => PackageEntry::PackageYank(PackageYank {
                    version: version.to_string(),
                }),
                _ => return Err(PackageDecodeErrno::UnknownPackageEntry),
            });
        }

        Ok(PackageRecord {
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
