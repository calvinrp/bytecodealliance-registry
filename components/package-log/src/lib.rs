cargo_component_bindings::generate!();

use bindings::exports::warg::package_log::package_records::{
    EncodedPackageRecord, Envelope, LogIdErrno, PackageDecodeErrno, PackageEncodeErrno,
    PackageEntry, PackagePermission, PackageRecord, PackageRecords,
    PackageValidationError, RecordId,
    UnauthorizedPermissionError, UnexpectedHashAlgorithm,
    PackageInit, PackageGrantFlat, PackageRevokeFlat, PackageRelease, PackageYank,
};
use bindings::warg::package_log::types::{Hash, Timestamp};

use semver::Version;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::unreachable;
use sync_unsafe_cell::SyncUnsafeCell;
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
use warg_protocol::registry::{
    LogId as WargLogId, PackageId as WargPackageId, RecordId as WargRecordId,
};

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
    fn log_id(name: String) -> Result<Hash, LogIdErrno> {
        match WargPackageId::new(name) {
            Ok(package_id) => Ok(WargLogId::package_log::<Sha256>(&package_id).to_string()),
            Err(_) => Err(LogIdErrno::InvalidPackageName),
        }
    }

    fn signing_prefix() -> Vec<u8> {
        package::SIGNING_PREFIX.to_vec()
    }

    fn append(envelope: Envelope) -> Result<RecordId, PackageValidationError> {
        let signature = Signature::from_str(&envelope.signature)
            .or(Err(PackageValidationError::SignatureParseFailure))?;
        let contents = package::PackageRecord::decode(&envelope.content_bytes)
            .or(Err(PackageValidationError::FailedToDecodeOperatorRecord))?;

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

    fn encode(rec: PackageRecord) -> Result<EncodedPackageRecord, PackageEncodeErrno> {
        let prev = match rec.prev {
            Some(id) => match AnyHash::from_str(&id) {
                Ok(id) => Some(id),
                Err(_) => return Err(PackageEncodeErrno::PrevRecordIdInvalidFormat),
            },
            None => None,
        };

        let entries = rec.entries
            .into_iter()
            .map(|entry| match entry {
                PackageEntry::PackageInit(PackageInit{
                    hash_algorithm,
                    key,
                }) => {
                    let hash_algorithm = HashAlgorithm::from_str(&hash_algorithm)
                        .or(Err(PackageEncodeErrno::UnsupportedHashAlgorithm))?;

                    let key = PublicKey::from_str(&key)
                        .or(Err(PackageEncodeErrno::PublicKeyParseFailure))?;

                    Ok(package::PackageEntry::Init {
                        hash_algorithm,
                        key,
                    })
                }
                PackageEntry::PackageGrantFlat(PackageGrantFlat{ key, permissions }) => {
                    let key = PublicKey::from_str(&key)
                        .or(Err(PackageEncodeErrno::PublicKeyParseFailure))?;

                    Ok(package::PackageEntry::GrantFlat {
                        key,
                        permissions: permissions.iter().map(|permission| match permission {
                            PackagePermission::Release => Ok(package::Permission::Release),
                            PackagePermission::Yank => Ok(package::Permission::Yank),
                            //_ => return Err(PackageEncodeErrno::UnknownPackagePermission),
                        }).collect::<Result<Vec<_>, _>>()?,
                    })
                }
                PackageEntry::PackageRevokeFlat(PackageRevokeFlat{ key, permissions }) => {
                    Ok(package::PackageEntry::RevokeFlat {
                        key_id: key.into(),
                        permissions: permissions.iter().map(|permission| match permission {
                            PackagePermission::Release => Ok(package::Permission::Release),
                            PackagePermission::Yank => Ok(package::Permission::Yank),
                            //_ => return Err(PackageEncodeErrno::UnknownPackagePermission),
                        }).collect::<Result<Vec<_>, _>>()?,
                    })
                }
                PackageEntry::PackageRelease(PackageRelease{
                    version,
                    content_digest,
                }) => {
                    let version = Version::parse(&version)
                        .or(Err(PackageEncodeErrno::PackageVersionParseError))?;

                    let content = AnyHash::from_str(&content_digest)
                        .or(Err(PackageEncodeErrno::ContentDigestParseError))?;

                    Ok(package::PackageEntry::Release { version, content })
                }
                PackageEntry::PackageYank(PackageYank{ version }) => {
                    let version = Version::parse(&version)
                        .or(Err(PackageEncodeErrno::PackageVersionParseError))?;

                    Ok(package::PackageEntry::Yank { version })
                } //_ => return Err(PackageEncodeErrno::UnknownPackageEntry),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let prev: Option<WargRecordId> = prev.map(|prev| prev.into());

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
    fn decode(bytes: Vec<u8>) -> Result<PackageRecord, PackageDecodeErrno> {
        let rec = package::PackageRecord::decode(&bytes)
            .or(Err(PackageDecodeErrno::FailedToDecode))?;

        let duration_since_epoch = rec.timestamp.duration_since(UNIX_EPOCH)
            .or(Err(PackageDecodeErrno::FailedToDecode))?;

        let entries = rec.entries
            .iter()
            .map(|entry| match entry {
                package::PackageEntry::Init {
                    hash_algorithm,
                    key,
                } => Ok(PackageEntry::PackageInit(PackageInit{
                    hash_algorithm: hash_algorithm.to_string(),
                    key: key.to_string(),
                })),
                package::PackageEntry::GrantFlat { key, permissions } => {
                    Ok(PackageEntry::PackageGrantFlat(PackageGrantFlat{
                        key: key.to_string(),
                        permissions: permissions.iter().map(|permission| match permission {
                            package::Permission::Release => Ok(PackagePermission::Release),
                            package::Permission::Yank => Ok(PackagePermission::Yank),
                            _ => Err(PackageDecodeErrno::UnknownPackagePermission),
                        }).collect::<Result<Vec<_>, _>>()?,
                    }))
                }
                package::PackageEntry::RevokeFlat { key_id, permissions } => {
                    Ok(PackageEntry::PackageRevokeFlat(PackageRevokeFlat{
                        key: key_id.to_string(),
                        permissions: permissions.iter().map(|permission| match permission {
                            package::Permission::Release => Ok(PackagePermission::Release),
                            package::Permission::Yank => Ok(PackagePermission::Yank),
                            _ => Err(PackageDecodeErrno::UnknownPackagePermission),
                        }).collect::<Result<Vec<_>, _>>()?,
                    }))
                }
                package::PackageEntry::Release { version, content } => {
                    Ok(PackageEntry::PackageRelease(PackageRelease{
                        version: version.to_string(),
                        content_digest: content.to_string(),
                    }))
                }
                package::PackageEntry::Yank { version } => Ok(PackageEntry::PackageYank(PackageYank{
                    version: version.to_string(),
                })),
                _ => return Err(PackageDecodeErrno::UnknownPackageEntry),
            })
            .collect::<Result<Vec<_>, _>>()?;

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
