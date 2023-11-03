//! Types relating to the fetch names API.

use crate::Status;
use serde::{de::Unexpected, Deserialize, Serialize, Serializer};
use std::{borrow::Cow, collections::HashMap};
use thiserror::Error;
use warg_crypto::hash::AnyHash;
use warg_protocol::registry::{LogId, PackageId};

/// Represents a fetch names request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchNamesRequest<'a> {
    /// List of package log IDs to request the package name.
    pub packages: Cow<'a, Vec<LogId>>,
}

/// Represents a fetch names response. The
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchNamesResponse {
    /// The log ID hash mapping to a package ID. If `None`, the package name cannot be provided.
    pub packages: HashMap<LogId, Option<PackageId>>,
}

/// Represents a fetch names API error.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum FetchNamesError {
    /// The provided package log ID was not found.
    #[error("log `{0}` was not found")]
    LogNotFound(LogId),
    /// An error with a message occurred.
    #[error("{message}")]
    Message {
        /// The HTTP status code.
        status: u16,
        /// The error message
        message: String,
    },
}

impl FetchNamesError {
    /// Returns the HTTP status code of the error.
    pub fn status(&self) -> u16 {
        match self {
            Self::LogNotFound(_) => 404,
            Self::Message { status, .. } => *status,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum EntityType {
    Log,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
enum RawError<'a, T>
where
    T: Clone + ToOwned,
    <T as ToOwned>::Owned: Serialize + for<'b> Deserialize<'b>,
{
    NotFound {
        status: Status<404>,
        #[serde(rename = "type")]
        ty: EntityType,
        id: Cow<'a, T>,
    },
    Message {
        status: u16,
        message: Cow<'a, T>,
    },
}

impl Serialize for FetchNamesError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::LogNotFound(log_id) => RawError::NotFound {
                status: Status::<404>,
                ty: EntityType::Log,
                id: Cow::Borrowed(log_id),
            }
            .serialize(serializer),
            Self::Message { status, message } => RawError::Message {
                status: *status,
                message: Cow::Borrowed(message),
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for FetchNamesError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match RawError::<String>::deserialize(deserializer)? {
            RawError::NotFound { status: _, ty, id } => match ty {
                EntityType::Log => Ok(Self::LogNotFound(
                    id.parse::<AnyHash>()
                        .map_err(|_| {
                            serde::de::Error::invalid_value(Unexpected::Str(&id), &"a valid log id")
                        })?
                        .into(),
                )),
            },
            RawError::Message { status, message } => Ok(Self::Message {
                status,
                message: message.into_owned(),
            }),
        }
    }
}
