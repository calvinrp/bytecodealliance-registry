use super::{Error, Json, RegistryHeader};
use crate::datastore::DataStoreError;
use crate::services::CoreService;
use axum::http::StatusCode;
use axum::{
    debug_handler, extract::State, response::IntoResponse, response::Response, routing::get, Router,
};
use warg_api::v1::ledger::{LedgerSource, LedgerSourceContentType, LedgerSourcesResponse};
use warg_crypto::hash::HashAlgorithm;

#[derive(Clone)]
pub struct Config {
    core_service: CoreService,
}

impl Config {
    pub fn new(core_service: CoreService) -> Self {
        Self { core_service }
    }

    pub fn into_router(self) -> Router {
        Router::new()
            .route("/", get(get_ledger_sources))
            .route("/records", get(get_ledger_records))
            .with_state(self)
    }
}

struct LedgerApiError(Error);

impl From<DataStoreError> for LedgerApiError {
    fn from(e: DataStoreError) -> Self {
        tracing::error!("unexpected data store error: {e}");

        Self(Error {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "an error occurred while processing the request".into(),
        })
    }
}

impl IntoResponse for LedgerApiError {
    fn into_response(self) -> axum::response::Response {
        self.0.into_response()
    }
}

#[debug_handler]
async fn get_ledger_sources(
    State(config): State<Config>,
    RegistryHeader(_registry_header): RegistryHeader,
) -> Result<Json<LedgerSourcesResponse>, LedgerApiError> {
    let log_length = config
        .core_service
        .store()
        .get_latest_checkpoint()
        .await?
        .into_contents()
        .checkpoint
        .log_length;

    Ok(Json(LedgerSourcesResponse {
        hash_algorithm: HashAlgorithm::Sha256,
        sources: vec![LedgerSource {
            first_registry_index: 0,
            last_registry_index: log_length - 1,
            url: "v1/ledger/records".to_string(),
            accept_ranges: false,
            content_type: LedgerSourceContentType::Packed,
        }],
    }))
}

#[debug_handler]
async fn get_ledger_records(
    State(config): State<Config>,
    RegistryHeader(_registry_header): RegistryHeader,
) -> Result<Response, LedgerApiError> {
    let log_leafs = config
        .core_service
        .store()
        .get_log_leafs_starting_with_registry_index(0, None)
        .await?;

    let mut body: Vec<u8> = Vec::with_capacity(log_leafs.len() * 64);

    for (_, leaf) in log_leafs.into_iter() {
        body.extend_from_slice(leaf.log_id.as_ref());
        body.extend_from_slice(leaf.record_id.as_ref());
    }

    Ok(Response::builder()
        .status(200)
        .header(
            axum::http::header::CONTENT_TYPE,
            LedgerSourceContentType::Packed.as_str(),
        )
        .body(axum::body::boxed(axum::body::Full::from(body)))
        .unwrap())
}
