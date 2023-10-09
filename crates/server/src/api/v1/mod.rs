use crate::{
    policy::{content::ContentPolicy, record::RecordPolicy},
    services::CoreService,
};
use anyhow::Result;
use axum::{
    async_trait,
    extract::{
        rejection::{JsonRejection, PathRejection},
        FromRequest, FromRequestParts,
    },
    http::{request::Parts, uri, StatusCode},
    response::IntoResponse,
    Router,
};
use serde::{Serialize, Serializer};
use std::{path::PathBuf, str::FromStr, sync::Arc};
use url::Url;
use warg_api::v1::monitor::PROXY_REGISTRY_HEADER_NAME;

pub mod content;
pub mod fetch;
pub mod monitor;
pub mod package;
pub mod proof;

/// An extractor that wraps the JSON extractor of Axum.
///
/// This extractor returns an API error on rejection.
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(Error))]
pub struct Json<T>(pub T);

impl<T> IntoResponse for Json<T>
where
    T: Serialize,
{
    fn into_response(self) -> axum::response::Response {
        axum::Json(self.0).into_response()
    }
}

fn serialize_status<S>(status: &StatusCode, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u16(status.as_u16())
}

/// Represents a generic error from the API.
#[derive(Serialize, Debug)]
pub struct Error {
    #[serde(serialize_with = "serialize_status")]
    status: StatusCode,
    message: String,
}

impl From<JsonRejection> for Error {
    fn from(rejection: JsonRejection) -> Self {
        Self {
            status: rejection.status(),
            message: rejection.body_text(),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        (self.status, axum::Json(self)).into_response()
    }
}

/// An extractor that wraps the path extractor of Axum.
///
/// This extractor returns an API error on rejection.
#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Path), rejection(Error))]
pub struct Path<T>(T);

impl From<PathRejection> for Error {
    fn from(rejection: PathRejection) -> Self {
        Self {
            status: rejection.status(),
            message: rejection.body_text(),
        }
    }
}

pub async fn not_found() -> impl IntoResponse {
    Error {
        status: StatusCode::NOT_FOUND,
        message: "the requested resource was not found".to_string(),
    }
}

/// An extractor for the Proxy Registry header.
pub struct ProxyRegistry(Option<uri::Authority>);

#[async_trait]
impl<S> FromRequestParts<S> for ProxyRegistry
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(proxy_registry) = parts.headers.get(PROXY_REGISTRY_HEADER_NAME) {
            let parsed = uri::Authority::try_from(proxy_registry.as_bytes()).or(Err((
                StatusCode::BAD_REQUEST,
                "`X-Proxy-Registry` header is not a valid Authority URI",
            )))?;
            Ok(ProxyRegistry(Some(parsed)))
        } else {
            Ok(ProxyRegistry(None))
        }
    }
}

impl FromStr for ProxyRegistry {
    type Err = uri::InvalidUri;
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Ok(ProxyRegistry(Some(uri::Authority::try_from(src)?)))
    }
}

pub fn create_router(
    content_base_url: Url,
    core: CoreService,
    temp_dir: PathBuf,
    files_dir: PathBuf,
    content_policy: Option<Arc<dyn ContentPolicy>>,
    record_policy: Option<Arc<dyn RecordPolicy>>,
) -> Router {
    let proof_config = proof::Config::new(core.clone());
    let package_config = package::Config::new(
        core.clone(),
        files_dir.clone(),
        temp_dir,
        content_policy,
        record_policy,
    );
    let content_config = content::Config::new(content_base_url, files_dir);
    let fetch_config = fetch::Config::new(core.clone());
    let monitor_config = monitor::Config::new(core);

    Router::new()
        .nest("/package", package_config.into_router())
        .nest("/content", content_config.into_router())
        .nest("/fetch", fetch_config.into_router())
        .nest("/proof", proof_config.into_router())
        .nest("/verify", monitor_config.into_router())
        .fallback(not_found)
}
